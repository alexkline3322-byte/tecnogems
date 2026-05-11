"""V48: Background task functions usable by both threading fallback and RQ.

If REDIS_URL is configured we enqueue to RQ (durable, multi-worker).
Otherwise we fall back to the existing in-process Queue + Thread pool
(works in single-process gunicorn but loses jobs on restart).

This module is intentionally framework-light: import-safe even when redis
is unavailable, and contains NO Flask context dependencies so RQ workers
can import it and run process_order() / send_email_task() in isolation.
"""

from __future__ import annotations

import os
import re
import smtplib
import logging
from email.mime.text import MIMEText

log = logging.getLogger("tasks")


# V50.2 MEDIUM (M12): sanitise supplier response messages before they land in
# the DB. Suppliers occasionally echo our own API key back in errors, return
# internal stack traces, or include raw HTML that would break admin views.
_NOTE_MAX_LEN = 200
_SUPPLIER_KEY_RE = re.compile(r"(key|token|apikey|api_key|authorization)\s*[:=]\s*[A-Za-z0-9._\-]+", re.IGNORECASE)
_SUPPLIER_HTML_RE = re.compile(r"<[^>]{1,200}>")
_SUPPLIER_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _sanitise_supplier_note(text) -> str:
    """Strip credentials/HTML/control chars from supplier error text and
    truncate to a safe length so admin screens (and users, via the orders
    API) do not see raw response blobs."""
    if text is None:
        return ""
    s = str(text)
    s = _SUPPLIER_KEY_RE.sub(r"\1=[REDACTED]", s)
    s = _SUPPLIER_HTML_RE.sub(" ", s)
    s = _SUPPLIER_CTRL_RE.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > _NOTE_MAX_LEN:
        s = s[: _NOTE_MAX_LEN - 1] + "…"
    return s

# ---- Redis / RQ optional bootstrap --------------------------------------
_redis_url = os.getenv("REDIS_URL", "").strip()
USE_RQ = False
_queue = None

if _redis_url:
    try:
        from redis import Redis  # type: ignore
        from rq import Queue  # type: ignore

        _conn = Redis.from_url(_redis_url)
        _queue = Queue("tecnogems_orders", connection=_conn)
        USE_RQ = True
        log.info("RQ enabled (REDIS_URL set, queue=tecnogems_orders)")
    except Exception as exc:  # pragma: no cover
        log.warning("RQ disabled — failed to init redis/rq: %s", exc)
        USE_RQ = False
        _queue = None


# ---- Email task ---------------------------------------------------------
def send_email_task(
    to_email: str,
    subject: str,
    body: str,
    smtp_server: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_tls: bool,
    mail_from: str,
):
    """Pure function — safe to enqueue. No app context needed."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = to_email
    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
        if smtp_use_tls:
            server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)


# ---- Order processing task (RQ-callable) -------------------------------
def process_order(order_id: int):
    """Process a single order: read from DB, send to supplier, update status.

    This is the RQ-callable entry point. It re-fetches the order and product
    from the database (cannot trust serialized objects across workers) so the
    correct provider_product_id (from the products table) is used when
    talking to the supplier.

    Notes:
    - Uses get_product_by_id (NOT order["product_id"]) to obtain the
      supplier's external product id (provider_product_id).
    - Mirrors the auto-refund / manual_pending logic of the legacy
      in-process worker.
    """
    from database import get_order, get_product_by_id, update_order, get_setting
    from providers import create_provider_order

    try:
        order = get_order(order_id)
        if not order:
            log.error("process_order: order %s not found", order_id)
            return

        product = get_product_by_id(order["product_id"])
        if not product:
            log.error("process_order: product %s not found for order %s", order["product_id"], order_id)
            update_order(order_id, "manual_pending", None, "Product not found in DB")
            return

        # Manual mode short-circuit
        if get_setting("manual_orders", "0") == "1":
            update_order(order_id, "manual_pending", None, "Manual mode is enabled")
            return

        update_order(order_id, "processing", None, "Sending order to supplier")

        res = create_provider_order(
            product["provider"],
            product["provider_product_id"],   # ← critical: external supplier id
            order["player_id"],
        )

        auto_refund = get_setting("auto_refund_on_failure", "0") == "1"

        if not isinstance(res, dict):
            note = "Invalid response from supplier"
            status = "rejected" if auto_refund else "manual_pending"
            update_order(order_id, status, None, f"{note}{' (auto-refund)' if auto_refund else ''}")
            log.error("Order %s: invalid supplier response: %r", order_id, res)
            return

        provider_order_id = (
            res.get("order_id")
            or (res.get("order", {}) if isinstance(res.get("order"), dict) else {}).get("order_id")
            or res.get("order")
            or ""
        )

        if "error" in res or res.get("success") is False:
            reason = res.get("error") or res.get("message") or str(res)
            # V50.2 MEDIUM (M12): sanitise supplier error before storing in
            # the order `note` column (which is later shown to admins and, via
            # the orders API, reflected to users). Supplier responses can echo
            # back our API key, internal IDs, or raw HTML payloads — redact
            # anything that looks like a credential and truncate to 200 chars.
            reason = _sanitise_supplier_note(reason)
            status = "rejected" if auto_refund else "manual_pending"
            note = f"Supplier error{' (auto-refund)' if auto_refund else ''}: {reason}"
            update_order(order_id, status, str(provider_order_id), note)
            log.warning("Order %s rejected by supplier: %s", order_id, reason)
            return

        update_order(order_id, "completed", str(provider_order_id), "Accepted by supplier")
        log.info("Order %s completed (provider id=%s)", order_id, provider_order_id)

    except Exception as exc:
        log.exception("process_order error on order %s: %s", order_id, exc)
        try:
            from database import update_order as _update
            # V50.2 MEDIUM (M12): sanitise exception text — tracebacks can
            # leak filesystem paths or library internals to the admin UI.
            _update(order_id, "manual_pending", None,
                    f"Worker error: {_sanitise_supplier_note(exc)}")
        except Exception:
            pass


# ---- Public enqueue helpers --------------------------------------------
def enqueue_email(*args, **kwargs):
    if USE_RQ and _queue is not None:
        return _queue.enqueue(send_email_task, *args, **kwargs)
    return None  # caller falls back to thread queue


# Note: app.py uses enqueue_order_job() which dispatches between local
# Queue.put and rq.enqueue(process_order). We deliberately do NOT export
# a separate tasks.enqueue_order here to avoid two parallel queue paths.
