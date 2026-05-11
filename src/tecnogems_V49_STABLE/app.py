import os
import gzip
from io import BytesIO
from pathlib import Path
from queue import Queue  # PATCH-A1: must be imported BEFORE email_queue = Queue()

import re
from datetime import datetime, timezone, timedelta
import threading
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename

from functools import wraps
from dotenv import load_dotenv
from flask import Response, Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify, send_from_directory
from flask_wtf.csrf import CSRFProtect, CSRFError

from database import (
    InsufficientBalance,
    init_db, ensure_indexes, seed_admin, create_user, authenticate, get_user, get_user_by_email, verify_user_email, set_user_email_token, set_password_reset_token, get_user_by_reset_token, reset_user_password, list_games, list_products, list_public_games, list_all_game_groups, list_product_games_from_products, add_custom_game, set_game_active, accounting_summary, list_product_groups, get_product_group, create_product_group, update_product_group, delete_product_group, update_products_admin, update_game_pricing, update_manual_syp_prices, translate_product_name, list_public_product_groups_for_home,
    get_product, get_game, create_order, update_order, list_user_orders, list_orders,
    get_order, stats, list_users, search_users, get_user_by_id, user_financial_summary, list_user_deposits_admin, update_user_profile, set_pending_email_change, confirm_pending_email_change, set_user_balance, change_balance,
    list_payment_methods, get_payment_method, update_payment_method,
    create_deposit, list_deposits, list_deposits_for_user, update_deposit, get_setting as _db_get_setting, set_setting as _db_set_setting,
    list_orders_for_auto_refresh, get_order_public,
    list_all_games_for_admin, update_game_image, list_all_products_for_admin, update_product_sort_orders, update_profit_margin, seed_local_provider_catalog, attach_generated_posters
)

# --- V35: in-memory settings cache (TTL 30s) to cut SQLite hits per request ---
import time as _time
_SETTINGS_CACHE = {}
_SETTINGS_TTL = 30.0

def get_setting(key, default=None):
    now = _time.time()
    hit = _SETTINGS_CACHE.get(key)
    if hit and hit[1] > now:
        val = hit[0]
        return val if val is not None else default
    val = _db_get_setting(key, default)
    _SETTINGS_CACHE[key] = (val, now + _SETTINGS_TTL)
    return val if val is not None else default

def set_setting(key, value):
    _SETTINGS_CACHE.pop(key, None)
    return _db_set_setting(key, value)

from providers import create_provider_order, get_provider_balance, validate_player_provider

load_dotenv()

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("tecnogems")

app = Flask(__name__)

_secret = os.getenv("SECRET_KEY", "")
if not _secret or _secret == "dev-secret-change-me" or _secret == "change-this-secret-key":
    if os.getenv("FLASK_ENV") == "production":
        raise RuntimeError("SECRET_KEY is missing or default. Set a strong SECRET_KEY in .env before running in production.")
    log.warning("Using development SECRET_KEY. Set a strong SECRET_KEY in .env for production.")
    # In dev: persist a stable secret to avoid CSRF/session invalidation on restart.
    # Never write to disk in production (containers/Heroku have ephemeral filesystems).
    _secret_file = os.path.join(os.path.dirname(__file__), ".secret_key")
    if not _secret:
        try:
            if os.path.exists(_secret_file):
                with open(_secret_file, "r", encoding="utf-8") as fh:
                    _secret = fh.read().strip()
            if not _secret:
                _secret = secrets.token_urlsafe(48)
                try:
                    with open(_secret_file, "w", encoding="utf-8") as fh:
                        fh.write(_secret)
                except OSError:
                    # Read-only filesystem (containers) — use in-memory secret for this run
                    log.warning(".secret_key file not writable; secret is ephemeral this session.")
        except Exception:
            _secret = _secret or secrets.token_urlsafe(48)
app.secret_key = _secret

BASE_URL = os.getenv("BASE_URL", "https://tecnogems.com").rstrip("/")
_is_https = BASE_URL.startswith("https://")

# V50.2 LOW/MEDIUM: production should enforce CSRF SSL strict check (verifies
# Referer header matches host over HTTPS). Dev stays permissive so you can
# test from http://127.0.0.1 without tripping the check.
_IS_PROD = os.getenv("FLASK_ENV") == "production"
# V50.2 MEDIUM: shorten session lifetime from 14 days to 7 days. Long-lived
# sessions survive long after a device is stolen/lost. 7 days balances UX
# (weekly-or-more active users stay logged in) with risk.
_SESSION_DAYS = int(os.getenv("SESSION_LIFETIME_DAYS", "7") or 7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_is_https,
    PERMANENT_SESSION_LIFETIME=timedelta(days=_SESSION_DAYS),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5 MB upload cap
    # CSRF: no time limit (token tied to session lifetime). Avoids the
    # "page expired, please retry" error after the user idles on the login form.
    WTF_CSRF_TIME_LIMIT=None,
    # V50.2 MEDIUM: SSL-strict enforces Referer header check for POSTs over
    # HTTPS. Kept off in dev so local http:// testing still works.
    WTF_CSRF_SSL_STRICT=_IS_PROD,
)

# V50 SECURITY: input length caps to prevent storage-bomb / CPU-DoS attacks.
# Any field longer than these limits is rejected before touching the DB or
# password hashing. Values balance real-world use vs abuse.
MAX_PLAYER_ID_LEN = 64
MAX_PASSWORD_LEN = 128
MAX_EMAIL_LEN = 120
MAX_NAME_LEN = 80
MAX_PHONE_LEN = 32
MAX_PROOF_TEXT_LEN = 2000
# Deposit ceiling (in the method's native currency for SYP, USD otherwise).
# Defaults to 10,000 USD. Override via MAX_DEPOSIT_USD env var.
try:
    MAX_DEPOSIT_USD = float(os.getenv("MAX_DEPOSIT_USD", "10000"))
except Exception:
    MAX_DEPOSIT_USD = 10000.0
# Admin balance set ceiling (prevents a compromised admin wiping the company).
try:
    MAX_ADMIN_BALANCE = float(os.getenv("MAX_ADMIN_BALANCE", "1000000"))
except Exception:
    MAX_ADMIN_BALANCE = 1_000_000.0

# CSRF protection
try:
    from flask_wtf import CSRFProtect
    csrf = CSRFProtect(app)
except Exception:  # graceful if dependency missing in dev
    csrf = None
    log.warning("Flask-WTF not installed. CSRF protection disabled. Run: pip install Flask-WTF")

# V45: Flask-Babel (real i18n). Falls back gracefully if not installed.
try:
    from flask_babel import Babel, gettext as _babel_gettext
    app.config.setdefault("BABEL_DEFAULT_LOCALE", "ar")
    app.config.setdefault("BABEL_SUPPORTED_LOCALES", ["ar", "en"])

    def _select_locale():
        from flask import session, request
        return session.get("lang") or request.cookies.get("lang") or "ar"

    babel = Babel(app, locale_selector=_select_locale)
    app.jinja_env.globals["_"] = _babel_gettext
    app.jinja_env.globals["gettext"] = _babel_gettext
except Exception as _exc:
    log.warning("Flask-Babel not installed; templates fall back to legacy tr(). %s", _exc)

# V45: register blueprints (phase 1: lang_bp). app.py keeps remaining
# routes for now; future phases extract auth/admin/api/games/wallet.
try:
    from routes import register_blueprints
    register_blueprints(app)
except Exception as _exc:
    log.warning("Blueprint registration failed: %s", _exc)

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    # V50.2 MEDIUM: when REDIS_URL is set, use the Redis storage backend so
    # rate limits are shared across gunicorn workers and survive restarts.
    # Falls back to in-memory when Redis is unavailable (dev or single-process).
    _limiter_kwargs = {"app": app, "default_limits": []}
    _redis_url = os.getenv("REDIS_URL", "").strip()
    if _redis_url:
        _limiter_kwargs["storage_uri"] = _redis_url
        _limiter_kwargs["strategy"] = "fixed-window"
    limiter = Limiter(get_remote_address, **_limiter_kwargs)
    if _redis_url:
        log.info("Flask-Limiter using Redis storage backend.")
    else:
        log.warning("Flask-Limiter using in-memory storage — limits are per-worker and cleared on restart. Set REDIS_URL for shared limits.")
except Exception:
    limiter = None
    log.warning("Flask-Limiter not installed. Rate limiting disabled. Run: pip install Flask-Limiter")

# V43: Brotli + Gzip compression for HTML/CSS/JS responses
try:
    from flask_compress import Compress
    app.config["COMPRESS_ALGORITHM"] = ["br", "gzip"]
    app.config["COMPRESS_MIN_SIZE"] = 500
    app.config["COMPRESS_LEVEL"] = 6
    app.config["COMPRESS_BR_LEVEL"] = 5
    Compress(app)
    log.info("Flask-Compress enabled (br, gzip)")
except Exception as _e:
    log.warning("Flask-Compress not installed (%s). Run: pip install Flask-Compress", _e)

# V43: WebP image processing on upload (Pillow)
try:
    from PIL import Image, ImageOps
    # PATCH-M3: cap decompression to prevent "image bomb" DoS
    Image.MAX_IMAGE_PIXELS = 25_000_000  # ~25 MP, plenty for any UI image
    _PIL_OK = True
except Exception:
    _PIL_OK = False
    log.warning("Pillow not installed. Image auto-conversion disabled. Run: pip install Pillow")

# Magic-byte signatures (real type check, not just file extension)
_IMG_MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # WEBP starts with RIFF....WEBP
}

def _detect_image_kind(head_bytes):
    if not head_bytes:
        return None
    for sig, kind in _IMG_MAGIC.items():
        if head_bytes.startswith(sig):
            if kind == "webp" and b"WEBP" not in head_bytes[:16]:
                continue
            return kind
    return None

def process_upload_to_webp(file_storage, dest_dir, base_name, max_w=1200, quality=82):
    """
    Read uploaded image, verify magic bytes, strip EXIF, downscale to max_w,
    and save as WebP. Returns saved filename (e.g. "name.webp") or None on failure.
    Falls back to plain save if Pillow is unavailable.
    """
    try:
        head = file_storage.stream.read(32)
        file_storage.stream.seek(0)
        kind = _detect_image_kind(head)
        if not kind:
            return None
        os.makedirs(dest_dir, exist_ok=True)
        out_name = f"{base_name}.webp"
        out_path = os.path.join(dest_dir, out_name)
        if not _PIL_OK:
            # Fallback: just save original under .webp-suffixed name? No — keep original ext.
            ext = "webp" if kind == "webp" else kind
            out_name = f"{base_name}.{ext}"
            out_path = os.path.join(dest_dir, out_name)
            file_storage.save(out_path)
            return out_name
        # PATCH-H3: verify the file is a valid, non-malicious image BEFORE
        # decoding the full payload. Image.verify() consumes the file so we
        # must reopen for actual processing.
        try:
            _verify_img = Image.open(file_storage.stream)
            _verify_img.verify()
        except Exception as exc:
            log.warning("process_upload_to_webp verify failed: %s", exc)
            return None
        try:
            file_storage.stream.seek(0)
        except Exception:
            return None
        img = Image.open(file_storage.stream)
        img = ImageOps.exif_transpose(img)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        if img.width > max_w:
            ratio = max_w / float(img.width)
            new_h = max(1, int(img.height * ratio))
            # PATCH-L5: use new Resampling enum (Pillow ≥ 10) with fallback.
            _resample = getattr(Image, "Resampling", Image).LANCZOS
            img = img.resize((max_w, new_h), _resample)
        save_kwargs = {"quality": quality, "method": 6}
        if img.mode == "RGBA":
            save_kwargs["lossless"] = False
        img.save(out_path, "WEBP", **save_kwargs)
        return out_name
    except Exception as exc:
        log.warning("process_upload_to_webp failed: %s", exc)
        try:
            file_storage.stream.seek(0)
        except Exception:
            pass
        return None


# Uploads (V50 SECURITY H4): moved OUT of static/ into data/uploads/ so
# the public static handler cannot bypass login_required on /uploads/proof/.
# The old /static/uploads/ path is also explicitly blocked below.
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "data", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Migrate any legacy files that may already exist under static/uploads/ once.
_LEGACY_UPLOADS = os.path.join(os.path.dirname(__file__), "static", "uploads")
if os.path.isdir(_LEGACY_UPLOADS):
    try:
        for _name in os.listdir(_LEGACY_UPLOADS):
            _src = os.path.join(_LEGACY_UPLOADS, _name)
            _dst = os.path.join(UPLOAD_FOLDER, _name)
            if os.path.isfile(_src) and not os.path.exists(_dst):
                try:
                    os.rename(_src, _dst)
                except OSError:
                    pass
    except OSError:
        pass
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# V50.2 LOW: removed "pdf" from deposit-proof allowed extensions. PDFs
# can embed JavaScript and are a common malware vector; images are
# sufficient for a payment-proof screenshot and much safer to serve back.
ALLOWED_UPLOAD_EXTS = {"jpg", "jpeg", "png", "webp", "gif"}

def _ext_ok(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_UPLOAD_EXTS


# PATCH-H4: magic-byte verification for deposit proofs (prevents file-type
# spoofing such as evil.php renamed to evil.png).
# V50.2 LOW: PDF removed — images only.
_PROOF_MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
}

def _proof_magic_ok(file_stream):
    """Verify uploaded file's first bytes match an accepted media type.
    Resets stream position to 0 before returning so the caller can save it."""
    try:
        head = file_stream.read(16)
        file_stream.seek(0)
    except Exception:
        return False
    if not head:
        return False
    for sig, _kind in _PROOF_MAGIC.items():
        if head.startswith(sig):
            return True
    # WebP starts with RIFF....WEBP
    if head.startswith(b"RIFF") and b"WEBP" in head[:16]:
        return True
    return False


# PATCH-H1: SVG sanitiser — strips <script>, on* event handlers, and
# javascript:/data: URIs from admin-uploaded SVGs to prevent stored XSS.
import re as _re_svg

_SVG_SCRIPT_RE = _re_svg.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", _re_svg.IGNORECASE | _re_svg.DOTALL)
_SVG_EVENT_RE = _re_svg.compile(r"\son[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", _re_svg.IGNORECASE)
_SVG_JS_URI_RE = _re_svg.compile(r"(href|xlink:href|src)\s*=\s*(\"|')\s*(javascript|data):[^\"']*(\"|')", _re_svg.IGNORECASE)
_SVG_FOREIGN_RE = _re_svg.compile(r"<\s*(foreignObject|iframe|object|embed)\b[^>]*>.*?<\s*/\s*\1\s*>", _re_svg.IGNORECASE | _re_svg.DOTALL)

def _sanitise_svg(svg_text):
    """Best-effort SVG XSS sanitiser. Removes scripts, event handlers,
    foreignObject / iframe nodes, and javascript:/data: URLs."""
    if not svg_text:
        return ""
    s = _SVG_SCRIPT_RE.sub("", svg_text)
    s = _SVG_FOREIGN_RE.sub("", s)
    s = _SVG_EVENT_RE.sub("", s)
    s = _SVG_JS_URI_RE.sub(r"\1=\2#\4", s)
    return s


# Make csrf_token() always available in templates even if Flask-WTF missing
if csrf is None:
    @app.context_processor
    def _csrf_noop():
        return {"csrf_token": lambda: ""}


MAIL_SERVER = os.getenv("MAIL_SERVER", "")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "1") == "1"
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "").replace(" ", "").strip()
MAIL_FROM = os.getenv("MAIL_FROM", MAIL_USERNAME or "no-reply@tecnogems.com")


# --- Public language system (Arabic default / English optional) ---
PUBLIC_TRANSLATIONS = {
    "home": {"ar": "الرئيسية", "en": "Home"},
    "my_orders": {"ar": "طلباتي", "en": "My Orders"},
    "wallet_records": {"ar": "سجل طلبات الرصيد", "en": "Wallet Requests"},
    "topup_wallet": {"ar": "شحن المحفظة", "en": "Top Up Wallet"},
    "balance": {"ar": "الرصيد", "en": "Balance"},
    "login": {"ar": "دخول", "en": "Login"},
    "register": {"ar": "إنشاء حساب", "en": "Create Account"},
    "logout": {"ar": "خروج", "en": "Logout"},
    "menu": {"ar": "القائمة", "en": "Menu"},
    "hero_pill": {"ar": "✨ منصة شحن الألعاب الأسرع في الشرق الأوسط", "en": "✨ Fast game top-up for global players"},
    "hero_title_1": {"ar": "اشحن لعبتك المفضلة", "en": "Top up your favorite game"},
    "hero_title_2": {"ar": "بضغطة واحدة", "en": "in one simple step"},
    "hero_desc": {"ar": "جواهر، شدات، نقاط CP وأكثر —", "en": "Diamonds, UC, CP and more — fast and secure."},
    "browse_games": {"ar": "تصفح الألعاب", "en": "Browse Games"},
    "available_now": {"ar": "🔥 المتاح الآن", "en": "🔥 Available Now"},
    "games_sections": {"ar": "الألعاب والأقسام المتاحة", "en": "Available Games & Sections"},
    "choose_game": {"ar": "اختر اللعبة أو القسم المناسب مباشرة.", "en": "Choose a game or section directly."},
    "search_game": {"ar": "🔍 ابحث عن لعبة أو قسم...", "en": "🔍 Search for a game or section..."},
    "packages": {"ar": "باقة", "en": "packages"},
    "packages_plural": {"ar": "باقات", "en": "packages"},
    "from": {"ar": "من", "en": "From"},
    "back_games": {"ar": "← العودة للألعاب", "en": "← Back to games"},
    "choose_package": {"ar": "اختر الباقة المناسبة.", "en": "Choose your package."},
    "search_package": {"ar": "🔍 ابحث عن باقة...", "en": "🔍 Search packages..."},
    "buy": {"ar": "شراء", "en": "Buy"},
    "login_to_buy": {"ar": "سجل للشراء", "en": "Login to buy"},
    "no_packages": {"ar": "لا توجد باقات متاحة لهذه اللعبة حاليًا.", "en": "No packages are available for this game right now."},
    "checkout": {"ar": "تأكيد الشراء", "en": "Confirm Purchase"},
    "game": {"ar": "اللعبة", "en": "Game"},
    "package": {"ar": "الباقة", "en": "Package"},
    "price": {"ar": "السعر", "en": "Price"},
    "player_id": {"ar": "معرف اللاعب Player ID", "en": "Player ID"},
    "confirm_order": {"ar": "تأكيد الطلب", "en": "Confirm Order"},
    "example_id": {"ar": "مثال: 123456789", "en": "Example: 123456789"},
    "order": {"ar": "الطلب", "en": "Order"},
    "status": {"ar": "الحالة", "en": "Status"},
    "date": {"ar": "التاريخ / سوريا", "en": "Date / Syria"},
    "waiting": {"ar": "بانتظار التنفيذ", "en": "Waiting"},
    "manual_pending": {"ar": "بانتظار تنفيذ يدوي", "en": "Manual processing"},
    "processing": {"ar": "جاري التنفيذ", "en": "Processing"},
    "completed": {"ar": "مكتمل", "en": "Completed"},
    "rejected": {"ar": "مرفوض", "en": "Rejected"},
    "wallet": {"ar": "المحفظة", "en": "Wallet"},
    "available_balance": {"ar": "الرصيد المتاح", "en": "Available Balance"},
    "support": {"ar": "الدعم", "en": "Support"},
    "amount": {"ar": "المبلغ", "en": "Amount"},
    "payment_method": {"ar": "طريقة الدفع", "en": "Payment Method"},
    "deposit_note": {"ar": "أدخل المبلغ حسب عملة طريقة الدفع المختارة.", "en": "Enter the amount using the selected payment method currency."},
    "method_currency": {"ar": "عملة الطريقة", "en": "Method currency"},
    "address": {"ar": "العنوان / الرقم", "en": "Address / Number"},
    "proof": {"ar": "إثبات الدفع", "en": "Payment proof"},
    "submit_deposit": {"ar": "إرسال طلب الشحن", "en": "Submit Top-up Request"},
    "email": {"ar": "البريد الإلكتروني", "en": "Email"},
    "password": {"ar": "كلمة المرور", "en": "Password"},
    "forgot_password": {"ar": "نسيت كلمة المرور؟", "en": "Forgot password?"},
    "resend_verification": {"ar": "إعادة إرسال رابط التفعيل", "en": "Resend verification link"},
    "name": {"ar": "الاسم", "en": "Name"},
    "phone": {"ar": "رقم الهاتف", "en": "Phone"},
    "confirm_password": {"ar": "تأكيد كلمة المرور", "en": "Confirm Password"},
    "create_account": {"ar": "إنشاء الحساب", "en": "Create Account"},
}

def current_lang():
    # Arabic is the default. English only if explicitly selected in this session.
    return "en" if session.get("lang") == "en" and session.get("lang_user_selected") == "1" else "ar"


def tr(key):
    return PUBLIC_TRANSLATIONS.get(key, {}).get(current_lang(), PUBLIC_TRANSLATIONS.get(key, {}).get("ar", key))

def lang_url(target):
    nxt = request.path
    if nxt.startswith("/lang/"):
        nxt = url_for("home")
    if request.query_string and not nxt.startswith("/lang/"):
        nxt = request.full_path
    return url_for("set_language", lang=target, next=nxt)


def public_price_text(usd_amount):
    try:
        amount = float(usd_amount or 0)
    except Exception:
        amount = 0.0
    if current_lang() == "en":
        return f"${amount:.2f}"
    return wallet_money_text(amount)


def product_public_price(product, game=None):
    return product_display_price(product, game)


def package_public_name(name):
    name = str(name or "")
    # Remove supplier/category labels in both languages.
    remove_terms = ["MENA Direct Topup", "Mena Direct Topup", "Direct Topup", "direct topup", "شحن مباشر"]
    for old in remove_terms:
        name = name.replace(old, "")

    if current_lang() == "en":
        replacements = [
            ("جواهر", "Diamonds"), ("جوهرة", "Diamond"),
            ("شدات ببجي", "PUBG UC"), ("شدات", "UC"),
            ("بطاقات", "Cards"), ("بطاقة", "Card"),
            ("عملات", "Coins"), ("عملة", "Coin"),
            ("قسائم", "Vouchers"), ("قسيمة", "Voucher"),
            ("نقاط", "Points"), ("نقطة", "Point")
        ]
        for old, new in replacements:
            name = name.replace(old, new)
        return re.sub(r"\s+", " ", name).strip(" -–—|")

    # Arabic display: translate provider/product English words even if stored in DB in English.
    replacements = [
        (r"\bdiamonds\b", "جواهر"),
        (r"\bdiamond\b", "جوهرة"),
        (r"\bpubg\s*uc\b", "شدات ببجي"),
        (r"\buc\b", "شدات"),
        (r"\bcards\b", "بطاقات"),
        (r"\bcard\b", "بطاقة"),
        (r"\bcoins\b", "عملات"),
        (r"\bcoin\b", "عملة"),
        (r"\bvouchers\b", "قسائم"),
        (r"\bvoucher\b", "قسيمة"),
        (r"\bpoints\b", "نقاط"),
        (r"\bpoint\b", "نقطة"),
        (r"\bweekly\b", "أسبوعي"),
        (r"\bmonthly\b", "شهري"),
    ]
    for old, new in replacements:
        name = re.sub(old, new, name, flags=re.I)
    return translate_product_name(re.sub(r"\s+", " ", name).strip(" -–—|"))



@app.route("/reset-lang")
def reset_lang():
    session.pop("lang", None)
    session.pop("lang_user_selected", None)
    return redirect(url_for("home"))

@app.route("/lang/<lang>")
def set_language(lang):
    # V35: only switch language if request comes from same-origin click (Referer check).
    # This prevents browser preloads / prefetch / cached requests from accidentally toggling language.
    referer = request.headers.get("Referer", "")
    same_origin = referer and (referer.startswith(BASE_URL) or referer.startswith(request.host_url))
    if same_origin:
        if lang == "en":
            session["lang"] = "en"
            session["lang_user_selected"] = "1"
        else:
            session["lang"] = "ar"
            session.pop("lang_user_selected", None)
    nxt = request.args.get("next") or (referer if same_origin else None) or url_for("home")
    if not isinstance(nxt, str) or not nxt.startswith("/") or nxt.startswith("/lang/"):
        nxt = url_for("home")
    resp = redirect(nxt)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp



def get_pricing_mode():
    """base pricing mode: usd | auto_syp"""
    mode = get_setting("pricing_mode", "usd")
    return mode if mode in ("usd", "auto_syp") else "usd"


def get_display_currency():
    return "USD" if get_pricing_mode() == "usd" else "SYP"


def manual_price_edit_enabled():
    return get_setting("manual_price_edit_enabled", "0") == "1"


def get_usd_syp_rate():
    try:
        return float(get_setting("usd_syp_rate", "15000") or 15000)
    except Exception:
        return 15000.0


def display_price_value(usd_amount, currency=None):
    try:
        amount = float(usd_amount or 0)
    except Exception:
        amount = 0.0
    cur = currency or get_display_currency()
    if cur == "SYP":
        return round(amount * get_usd_syp_rate(), 0)
    return round(amount, 2)


def display_price_text(usd_amount, currency=None):
    cur = currency or get_display_currency()
    val = display_price_value(usd_amount, cur)
    if cur == "SYP":
        return f"{val:,.0f} ل.س"
    return f"{val:.2f}$"


def product_manual_syp(product):
    try:
        return float((product or {}).get("manual_price_syp") or 0)
    except Exception:
        return 0.0


def manual_syp_override_active(product):
    return manual_price_edit_enabled() and product_manual_syp(product) > 0


def product_sell_usd(product, game=None):
    product = product or {}
    rate = get_usd_syp_rate()
    try:
        sell_usd = float(product.get("sell_price") or 0)
    except Exception:
        sell_usd = 0.0

    # Manual SYP is an override only when enabled and a value exists.
    if manual_syp_override_active(product) and rate > 0:
        return product_manual_syp(product) / rate

    return sell_usd


def product_display_price(product, game=None):
    product = product or {}

    if current_lang() == "en":
        return f"${product_sell_usd(product, game):.2f}"

    # Manual SYP overrides the selected base pricing mode only if enabled.
    if manual_syp_override_active(product):
        return f"{product_manual_syp(product):,.0f} ل.س"

    if get_pricing_mode() == "auto_syp":
        return display_price_text(product.get("sell_price", 0), "SYP")

    return display_price_text(product.get("sell_price", 0), "USD")


def product_profit_percent(product, game=None):
    try:
        base = float((product or {}).get("base_price") or 0)
        sell = float(product_sell_usd(product, game))
        if base <= 0:
            return None
        return round(((sell / base) - 1) * 100, 2)
    except Exception:
        return None


def wallet_money_text(amount):
    try:
        amount = float(amount or 0)
    except Exception:
        amount = 0.0
    if current_lang() == "en":
        return f"${amount:.2f}"
    if get_display_currency() == "SYP":
        return f"{amount * get_usd_syp_rate():,.0f} ل.س"
    return f"{amount:.2f}$"







def email_verification_is_enabled():
    return get_setting("email_verification_enabled", "0") == "1"


def email_is_configured():
    return bool(MAIL_SERVER and MAIL_USERNAME and MAIL_PASSWORD and MAIL_FROM)


# V42 batch2: async email queue ----------------------------------------
email_queue = Queue()


def _send_email_sync(to_email, subject, body):
    if not email_is_configured():
        app.logger.warning("Email skipped (SMTP not configured): to=%s subject=%s", to_email, subject)
        return
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=30) as server:
            if MAIL_USE_TLS:
                server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
    except Exception as exc:
        app.logger.error("Email send failed to=%s: %s", to_email, exc)


def _email_worker():
    while True:
        item = email_queue.get()
        try:
            if item is None:
                continue
            _send_email_sync(*item)
        except Exception as exc:
            app.logger.error("email_worker error: %s", exc)
        finally:
            email_queue.task_done()


# spin up 2 worker threads (lightweight) for parallel SMTP sends
for _i in range(2):
    threading.Thread(target=_email_worker, daemon=True, name=f"email-worker-{_i}").start()


def send_email(to_email, subject, body):
    """Non-blocking: enqueue email and return immediately.

    V45: prefer durable RQ queue when REDIS_URL is configured; fall back to
    the in-process thread queue otherwise (backwards compatible).
    """
    if not email_is_configured():
        raise RuntimeError("SMTP email settings are missing. Check .env")
    try:
        from tasks import enqueue_email, USE_RQ
        if USE_RQ:
            enqueue_email(
                to_email, subject, body,
                MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD,
                MAIL_USE_TLS, MAIL_FROM,
            )
            return
    except Exception as exc:
        app.logger.warning("RQ enqueue failed, falling back to thread queue: %s", exc)
    email_queue.put((to_email, subject, body))


def send_verification_email(to_email, token):
    link = f"{BASE_URL}/verify-email/{token}"
    body = f"""مرحبًا بك في TecnoGems

لتفعيل حسابك اضغط على الرابط التالي:
{link}

إذا لم تطلب إنشاء حساب، تجاهل هذه الرسالة.
"""
    send_email(to_email, "تفعيل حسابك في TecnoGems", body)


def send_password_reset_email(to_email, token):
    link = f"{BASE_URL}/reset-password/{token}"
    body = f"""مرحبًا

لاستعادة كلمة المرور اضغط على الرابط التالي:
{link}

صلاحية الرابط ساعة واحدة فقط.
إذا لم تطلب استعادة كلمة المرور، تجاهل هذه الرسالة.
"""
    send_email(to_email, "استعادة كلمة المرور - TecnoGems", body)


def send_email_change_confirmation(to_email, token):
    link = f"{BASE_URL}/confirm-email-change/{token}"
    body = f"""مرحبًا

لتأكيد تغيير البريد الإلكتروني في TecnoGems اضغط الرابط التالي:
{link}

إذا لم تطلب تغيير البريد، تجاهل هذه الرسالة.
"""
    send_email(to_email, "تأكيد تغيير البريد - TecnoGems", body)


if os.getenv("REDIS_URL"):
    from rq import Queue as _RQQueue
    from redis import Redis
    redis_conn = Redis.from_url(os.getenv("REDIS_URL"))
    order_queue = _RQQueue("tecnogems_orders", connection=redis_conn)
    _ORDER_QUEUE_KIND = "rq"
    log.info("Using Redis Queue for orders.")
else:
    from queue import Queue as _LocalQueue
    order_queue = _LocalQueue()
    _ORDER_QUEUE_KIND = "local"
    log.warning("⚠️  REDIS_URL is not set. Orders are queued in-memory and will be LOST if the process restarts. Set REDIS_URL and run worker_rq.py for durable processing.")


def enqueue_order_job(order_id, product=None, player_id=None):
    """PATCH-C1/H4: unified enqueue. Both backends now process via
    tasks.process_order(order_id) which re-fetches the order from DB.
    The product and player_id parameters are ignored (kept for compatibility).
    """
    if _ORDER_QUEUE_KIND == "rq":
        from tasks import process_order
        order_queue.enqueue(process_order, order_id)
    else:
        order_queue.put({"order_id": order_id})



def smart_game_image_url(game):
    """Lightweight generated SVG thumbnails for games without uploaded images."""
    try:
        name = str((game or {}).get("name") or "")
        key = str((game or {}).get("game_key") or "")
    except Exception:
        name, key = str(game or ""), ""
    s = (name + " " + key).lower().replace("_", " ")
    mapping = {
        "8 ball": "8-ball-pool.svg", "afk": "afk-journey.svg", "acecraft": "acecraft.svg",
        "arena breakout": "arena-breakout.svg", "arena of valor": "arena-of-valor.svg",
        "asphalt": "asphalt-9-legends.svg", "black clover": "black-clover-m.svg",
        "blood strike": "blood-strike.svg", "call of duty": "call-of-duty-mobile.svg", "cod": "call-of-duty-mobile.svg",
        "crossfire": "crossfire-mobile.svg", "delta": "delta-force-mobile.svg", "dragon nest": "dragon-nest-m.svg",
        "fc": "ea-fc-mobile.svg", "fifa": "ea-fc-mobile.svg", "eve": "eve-echoes.svg",
        "eggy": "eggy-party.svg", "farlight": "farlight-84.svg", "genshin": "genshin-impact.svg",
        "honkai": "honkai-star-rail.svg", "honor": "honor-of-kings.svg", "mobile legends": "mobile-legends.svg",
        "pubg": "pubg-mobile.svg", "free fire": "free-fire.svg", "freefire": "free-fire.svg",
        "roblox": "roblox.svg", "minecraft": "minecraft.svg", "valorant": "valorant.svg",
        "clash royale": "clash-royale.svg", "clash": "clash-of-clans.svg", "stumble": "stumble-guys.svg",
        "wild rift": "wild-rift.svg", "zenless": "zenless-zone-zero.svg", "ragnarok": "ragnarok-x.svg",
        "solo leveling": "solo-leveling.svg", "magic chess": "magic-chess.svg", "crystal": "crystal-of-atlan.svg",
        "etheria": "etheria-restart.svg", "watcher": "watcher-of-realms.svg", "harry potter": "harry-potter-magic-awakened.svg",
        "blockman": "blockman-go.svg", "bleach": "bleach-soul-resonance.svg", "devil may cry": "devil-may-cry.svg",
        "echocalypse": "echocalypse.svg", "frag": "frag-pro-shooter.svg", "heartopia": "heartopia.svg",
    }
    for needle, filename in mapping.items():
        if needle in s:
            return url_for("static", filename=f"img/smart-games/{filename}")
    return url_for("static", filename="img/smart-games/game-default-smart.svg")



def game_image_url(game):
    """Priority: admin uploaded/custom image -> bundled old game art -> smart generated fallback."""
    try:
        name = str((game or {}).get("name") or (game or {}).get("game_name") or "")
        key = str((game or {}).get("game_key") or "")
        custom = str((game or {}).get("image_url") or (game or {}).get("game_image_url") or "")
    except Exception:
        name, key, custom = str(game or ""), "", ""

    if custom:
        return custom

    s = (name + " " + key).lower().replace("_", " ")
    bundled = {
        "pubg": "pubg.jpg",
        "free fire": "free-fire.jpg",
        "freefire": "free-fire.jpg",
        "fc": "fc-mobile.jpg",
        "fifa": "fifa.jpg",
        "call of duty": "cod-mobile.jpg",
        "cod": "cod-mobile.jpg",
        "genshin": "genshin.jpg",
        "valorant": "valorant.jpg",
        "roblox": "roblox.jpg",
        "minecraft": "minecraft.jpg",
        "mobile legends": "mobile-legends.jpg",
        "clash royale": "clash-royale.jpg",
        "clash": "clash.jpg",
        "8 ball": "8ball.jpg",
        "stumble": "stumble.jpg",
        "wild rift": "wild-rift.jpg",
        "honor": "honor-kings.jpg",
        "fortnite": "fortnite.jpg",
        "aov": "aov.jpg",
        "arena of valor": "aov.jpg",
        "brawl": "brawl.jpg",
        "apex": "apex.jpg",
    }
    for needle, filename in bundled.items():
        if needle in s:
            return url_for("static", filename=f"react-assets/games/{filename}")

    return smart_game_image_url(game)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    user = get_user(uid)
    if not user:
        session.clear()
        return None
    # V50 SECURITY (HH): deactivated users must not retain access on
    # long-lived sessions. authenticate() checks active=1 at login but the
    # per-request guard did not. Clear the session if the user was deactivated.
    try:
        if int(user.get("active", 1)) != 1:
            session.clear()
            return None
    except Exception:
        pass
    return user


@app.context_processor
def inject_user():
    # PATCH-M2/C4: per-request CSP nonce for all inline <script> tags.
    # Combined with the strict CSP header (no 'unsafe-inline'), this is
    # the canonical way to whitelist trusted inline JS.
    from flask import g as _g
    nonce = getattr(_g, "_csp_nonce", None)
    if not nonce:
        nonce = secrets.token_urlsafe(16)
        _g._csp_nonce = nonce
    return {
        "current_user": current_user(),
        "site_theme": get_setting("site_theme", "theme-aurora"),
        "nav_mode": get_setting("nav_mode", "menu"),
        "show_groups_direct": get_setting("show_groups_direct", "0"),
        "old_games_layout": get_setting("old_games_layout", "0"),
        "display_currency": get_display_currency(),
        "display_price": display_price_text,
        "pricing_mode": get_pricing_mode(),
        "manual_price_edit_enabled": manual_price_edit_enabled(),
        "wallet_money": wallet_money_text,
        "product_sell_usd": product_sell_usd,
        "whatsapp_number": get_setting("whatsapp_number", ""),
        "telegram_username": get_setting("telegram_username", ""),
        "lang": current_lang(),
        "is_en": current_lang() == "en",
        "t": tr,
        "lang_url": lang_url,
        "product_price": product_public_price,
        "csp_nonce": nonce,
        "product_profit_percent": product_profit_percent,
        "smart_game_image": smart_game_image_url,
        "game_image": game_image_url
    }



@app.template_filter("public_package_name")
def public_package_name_filter(value):
    return package_public_name(value)

@app.template_filter("syria_time")
def syria_time(value):
    """تحويل timestamp إلى توقيت سوريا UTC+3."""
    try:
        ts = int(value)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(timezone(timedelta(hours=3)))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


@app.template_filter("money")
def money(amount):
    return display_price_text(amount)

@app.template_filter("clean_package_name")
def clean_package_name(value):
    """تنظيف أسماء الباقات المعروضة للمستخدم من عبارات المزود الفنية."""
    text = str(value or "")
    patterns = [
        r"\bMENA\s+Direct\s+Topup\b\s*-?\s*",
        r"\bMena\s+Direct\s+Topup\b\s*-?\s*",
        r"\bmena\s+direct\s+topup\b\s*-?\s*",
    ]
    for pat in patterns:
        text = re.sub(pat, "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s{2,}", " ", text).strip(" -–—\t\n")
    return text or str(value or "")



def validate_password_strength(password):
    """PATCH-M4: enforce minimum complexity for production-grade safety.
    Requires 8+ chars and at least 2 of: lowercase, uppercase, digit, symbol.
    """
    password = password or ""
    if len(password) < 8:
        return False, "كلمة المرور يجب أن تكون 8 أحرف على الأقل"
    classes = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])
    if classes < 2:
        return False, "كلمة المرور ضعيفة. استخدم مزيجاً من الأحرف والأرقام (أو رموزاً)"
    return True, None


def safe_next_url(default_endpoint="home", **url_for_kwargs):
    """PATCH-B4: now accepts kwargs forwarded to url_for() so callers like
    safe_next_url("products", provider=p, game_key=k) no longer crash with
    TypeError. The ?next= parameter still wins when present and safe.

    V50 SECURITY (HF): hardened against open-redirect variants:
    - reject backslashes (\\evil.com), null bytes, control chars
    - reject any ':' (blocks javascript:, http://, etc)
    - reject /%2f%2f... (encoded protocol-relative)
    - cap length to avoid log/memory pollution
    """
    nxt = request.args.get("next") or request.form.get("next") or ""
    if not nxt or len(nxt) > 512:
        return url_for(default_endpoint, **url_for_kwargs)
    # Reject anything that is not a plain same-origin path.
    bad_chars = ("\\", "\x00", "\r", "\n", "\t", " ")
    if any(c in nxt for c in bad_chars) or ":" in nxt:
        return url_for(default_endpoint, **url_for_kwargs)
    # Lowercase for encoded-scheme check
    low = nxt.lower()
    if low.startswith("//") or low.startswith("/%2f") or low.startswith("/\\"):
        return url_for(default_endpoint, **url_for_kwargs)
    if nxt.startswith("/") and not nxt.startswith("/legacy"):
        return nxt
    return url_for(default_endpoint, **url_for_kwargs)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("يرجى تسجيل الدخول أولًا", "warning")
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def worker():
    """PATCH-H4: in-memory worker now delegates to tasks.process_order to keep
    a SINGLE source of truth for the order processing flow. The local queue
    only carries the order_id; product/player are re-resolved from the DB
    inside process_order() — exactly like the RQ path."""
    from tasks import process_order
    while True:
        job = order_queue.get()
        try:
            order_id = job["order_id"] if isinstance(job, dict) else int(job)
            process_order(order_id)
        except Exception as exc:
            log.exception("Worker error on order %s: %s", job, exc)
        finally:
            order_queue.task_done()



@app.template_filter("order_status_label")
def order_status_label(status):
    labels = {
        "waiting": "بانتظار التنفيذ",
        "processing": "جاري التنفيذ",
        "supplier_pending": "جاري التنفيذ",
        "manual_pending": "بانتظار تنفيذ يدوي",
        "completed": "مكتمل",
        "rejected": "مرفوض",
        "pending": "معلق",
    }
    return labels.get(status, status)


@app.template_filter("order_status_class")
def order_status_class(status):
    classes = {
        "waiting": "waiting",
        "processing": "processing",
        "supplier_pending": "processing",
        "manual_pending": "pending",
        "completed": "completed",
        "rejected": "rejected",
        "pending": "pending",
    }
    return classes.get(status, "pending")




def gzip_text_response(response):
    try:
        accept = request.headers.get("Accept-Encoding", "")
        ctype = response.headers.get("Content-Type", "")
        if (
            "gzip" in accept
            and response.status_code == 200
            and not response.direct_passthrough
            and "Content-Encoding" not in response.headers
            and any(t in ctype for t in ["text/html", "text/css", "application/javascript", "text/javascript", "application/json"])
        ):
            data = response.get_data()
            if len(data) > 1024:
                gz = gzip.compress(data, compresslevel=5)
                if len(gz) < len(data):
                    response.set_data(gz)
                    response.headers["Content-Encoding"] = "gzip"
                    response.headers["Content-Length"] = str(len(gz))
                    response.headers["Vary"] = "Accept-Encoding"
    except Exception:
        pass
    return response





@app.before_request
def lang_cookie_reset_v36():
    if session.get("lang") == "en" and session.get("lang_user_selected") != "1":
        session["lang"] = "ar"
        session.pop("lang_user_selected", None)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("انتهت صلاحية الصفحة، يرجى إعادة المحاولة.", "warning")
    return redirect(safe_next_url("home"))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", title="404 - الصفحة غير موجودة"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", title="500 - خطأ في الخادم"), 500

@app.after_request
def add_cache_headers(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.path.startswith("/admin") or request.path.startswith("/login") or request.path.startswith("/register") or request.path.startswith("/forgot") or request.path.startswith("/reset") or request.method == "POST":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    else:
        response.headers.setdefault("Cache-Control", "private, max-age=120")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # V50.2 LOW: block legacy cross-domain Flash/Silverlight policy files.
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    # V50.2 LOW: isolate browsing-context group (mitigates Spectre / cross-origin
    # window references). Safe here because we do not embed third-party windows.
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # V50.2 LOW: block other origins from embedding our resources as images
    # or scripts. "same-site" keeps our own subdomains working.
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    # PATCH-C4: nonce-based CSP — no more 'unsafe-inline' for scripts.
    # Inline <script> blocks must declare nonce="{{ csp_nonce }}" to execute.
    from flask import g as _g
    _nonce = getattr(_g, "_csp_nonce", "")
    # V50.2 MEDIUM: tighter CSP. Added object-src 'none' (blocks <object>/<embed>
    # and Flash/plugins), form-action 'self' (forms can only POST to our origin
    # — blocks form-hijack XSS payloads), frame-src 'none' (we don't use frames),
    # and upgrade-insecure-requests so any accidental http:// asset is auto-upgraded.
    # Note: style-src still includes 'unsafe-inline' because many templates use
    # inline style="..." attributes. Removing it is tracked as a follow-up refactor.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"script-src 'self' 'nonce-{_nonce}'; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "upgrade-insecure-requests;"
    )
    if request.is_secure:
        # V50.2 LOW: add 'preload' so the browser can submit the domain to
        # the HSTS preload list (requires 2-year max-age + includeSubDomains,
        # which we have). Site admins must still enrol at hstspreload.org.
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return gzip_text_response(response)


@app.route("/robots.txt")
def robots_txt():
    return app.send_static_file("robots.txt")

@app.route("/manifest.json")
def manifest_json():
    return app.send_static_file("manifest.json")


@app.route("/sitemap.xml")
def sitemap_xml():
    # V43: full sitemap with hreflang ar/en alternates + per-game URLs
    static_paths = ["/", "/login", "/register", "/games"]
    game_paths = []
    try:
        for g in list_public_games(True):
            p = g.get("provider"); k = g.get("game_key")
            if p and k:
                game_paths.append(f"/products/{p}/{k}")
    except Exception as exc:
        log.warning("sitemap games enumeration failed: %s", exc)

    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
             'xmlns:xhtml="http://www.w3.org/1999/xhtml">']

    def _entry(path, prio="0.8", freq="weekly"):
        loc_ar = f"{BASE_URL}{path}"
        loc_en = f"{BASE_URL}/lang/en?next={path}"
        lines.append(f"  <url><loc>{loc_ar}</loc>"
                     f"<changefreq>{freq}</changefreq><priority>{prio}</priority>"
                     f'<xhtml:link rel="alternate" hreflang="ar" href="{loc_ar}"/>'
                     f'<xhtml:link rel="alternate" hreflang="en" href="{loc_en}"/>'
                     f'<xhtml:link rel="alternate" hreflang="x-default" href="{loc_ar}"/>'
                     f"</url>")

    for p in static_paths:
        _entry(p, "1.0" if p == "/" else "0.7", "daily" if p == "/" else "weekly")
    for p in game_paths:
        _entry(p, "0.8", "weekly")
    lines.append("</urlset>")
    return Response("\n".join(lines), mimetype="application/xml")


# Back-compat: redirect any remaining /legacy/... links to clean URLs (single rule)
@app.route("/legacy/<path:rest>")
def legacy_redirect(rest):
    return redirect("/" + rest, code=301)


# Secure proof file delivery (login required, owner-or-admin)
@app.route("/uploads/proof/<path:filename>")
@login_required
def serve_proof(filename):
    user = current_user()
    if not user:
        abort(403)
    safe = secure_filename(filename)
    # File names start with the owner user id: "<uid>_<ts>_<name>"
    owner_ok = safe.startswith(f"{user['id']}_") or user.get("role") == "admin"
    if not owner_ok:
        abort(403)
    full = os.path.join(app.config["UPLOAD_FOLDER"], safe)
    if not os.path.exists(full):
        abort(404)
    resp = send_from_directory(app.config["UPLOAD_FOLDER"], safe)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# V50 SECURITY (H4): explicitly block the legacy public path.
# Flask's built-in static handler would otherwise happily serve anything
# left in static/uploads/ to the world without auth. This route takes
# precedence and forces a 403.
@app.route("/static/uploads/<path:_ignored>")
def _block_static_uploads(_ignored):
    abort(403)


@app.route("/")
@app.route("/legacy")
def home():
    games = list_public_games(True)
    groups = list_public_product_groups_for_home() if get_setting("show_groups_direct", "0") == "1" else []
    if groups:
        grouped_keys = {(g.get("provider"), g.get("game_key")) for g in groups}
        games = [g for g in games if (g.get("provider"), g.get("game_key")) not in grouped_keys]
    recent_orders = []
    user = current_user()
    if user:
        recent_orders = list_user_orders(user["id"])[:3]
    all_stats = stats()
    from featured_games import FEATURED_GAMES
    return render_template("home.html", games=games, home_groups=groups,
        featured_games=FEATURED_GAMES,
        recent_orders=recent_orders,
        games_count=len(games) + len(groups),
        completed_orders_count=all_stats.get("completed", 0) if all_stats else 0)


@app.route("/register", methods=["GET", "POST"])
@(limiter.limit("8 per minute") if limiter else (lambda f: f))
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        # V50 SECURITY (HD): enforce upper length bounds before hashing the
        # password. Without this a 10MB password would consume CPU in
        # pbkdf2 and be a cheap DoS vector.
        if (
            len(password) > MAX_PASSWORD_LEN
            or len(email) > MAX_EMAIL_LEN
            or len(request.form.get("name", "")) > MAX_NAME_LEN
            or len(request.form.get("phone", "")) > MAX_PHONE_LEN
        ):
            flash("أحد الحقول تجاوز الحد المسموح به", "danger")
            return render_template("register.html", hide_phone_on_register=get_setting("hide_phone_on_register", "0"))
        if password != password_confirm:
            flash("كلمة المرور وتأكيدها غير متطابقين", "danger")
            return render_template("register.html", hide_phone_on_register=get_setting("hide_phone_on_register", "0"))
        pw_ok, pw_err = validate_password_strength(password)
        if not pw_ok:
            flash(pw_err, "danger")
            return render_template("register.html", hide_phone_on_register=get_setting("hide_phone_on_register", "0"))
        verification_enabled = email_verification_is_enabled()
        token = secrets.token_urlsafe(32) if verification_enabled else None

        ok, err = create_user(
            request.form.get("name", "").strip(),
            email,
            request.form.get("phone", "").strip() if get_setting("hide_phone_on_register", "0") != "1" else "",
            password,
            email_verified=0 if verification_enabled else 1,
            email_token=token
        )
        if ok:
            if verification_enabled:
                try:
                    send_verification_email(email, token)
                    flash("تم إنشاء الحساب. أرسلنا رابط التفعيل إلى بريدك الإلكتروني.", "success")
                except Exception as exc:
                    log.warning("verification email failed for %s: %s", email, exc)
                    user = get_user_by_email(email)
                    if user:
                        set_user_email_token(user["id"], token)
                    flash("تم إنشاء الحساب، لكن لم يتم إرسال بريد التفعيل. افحص إعدادات Gmail App Password في ملف .env، ثم استخدم إعادة إرسال رابط التفعيل.", "warning")
                return redirect("/login")

            flash("تم إنشاء الحساب. يمكنك تسجيل الدخول الآن.", "success")
            return redirect("/login")
        flash(err or "فشل إنشاء الحساب", "danger")
    return render_template("register.html", hide_phone_on_register=get_setting("hide_phone_on_register", "0"))


@app.route("/verify-email/<token>")
@(limiter.limit("20 per hour") if limiter else (lambda f: f))  # V50.2 MEDIUM: was unlimited
def verify_email(token):
    ok, err = verify_user_email(token)
    if ok:
        flash("تم تفعيل البريد الإلكتروني بنجاح. يمكنك تسجيل الدخول الآن.", "success")
    else:
        flash(err or "تعذر تفعيل البريد الإلكتروني.", "danger")
    return redirect("/login")


@app.route("/resend-verification", methods=["GET", "POST"])
@(limiter.limit("3 per minute;20 per hour") if limiter else (lambda f: f))  # V50.2 MEDIUM: was unlimited
def resend_verification():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = get_user_by_email(email)
        if user and not user.get("email_verified"):
            token = secrets.token_urlsafe(32)
            set_user_email_token(user["id"], token)
            try:
                send_verification_email(email, token)
                flash("تم إرسال رابط تفعيل جديد إلى بريدك.", "success")
            except Exception as exc:
                flash(f"تعذر إرسال رابط التفعيل: {exc}", "danger")
        else:
            flash("إذا كان البريد مسجلًا وغير مفعل، سيتم إرسال رابط تفعيل.", "info")
        return redirect("/login")
    return render_template("resend_verification.html")


@app.route("/forgot-password", methods=["GET", "POST"])
@(limiter.limit("5 per minute") if limiter else (lambda f: f))
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = get_user_by_email(email)
        if user:
            token = secrets.token_urlsafe(32)
            set_password_reset_token(user["id"], token)
            try:
                send_password_reset_email(email, token)
            except Exception as exc:
                flash(f"تعذر إرسال رابط الاستعادة: {exc}", "danger")
                return redirect(url_for("forgot_password"))
        flash("إذا كان البريد مسجلًا، أرسلنا رابط استعادة كلمة المرور.", "info")
        return redirect("/login")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
@(limiter.limit("10 per hour") if limiter else (lambda f: f))  # V50.2 MEDIUM: was unlimited
def reset_password(token):
    user = get_user_by_reset_token(token)
    if not user:
        flash("رابط الاستعادة غير صحيح أو انتهت صلاحيته.", "danger")
        return redirect("/login")

    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if password != password_confirm:
            flash("كلمة المرور وتأكيدها غير متطابقين", "danger")
            return render_template("reset_password.html", token=token)
        ok, err = reset_user_password(token, password)
        if ok:
            flash("تم تغيير كلمة المرور. يمكنك تسجيل الدخول الآن.", "success")
            return redirect("/login")
        flash(err or "تعذر تغيير كلمة المرور", "danger")
    return render_template("reset_password.html", token=token)


@app.route("/login", methods=["GET", "POST"])
@(limiter.limit("10 per minute") if limiter else (lambda f: f))
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        # V50 SECURITY (HD): reject oversized inputs before password hashing
        # to prevent CPU-DoS via huge passwords.
        if len(password) > MAX_PASSWORD_LEN or len(email) > MAX_EMAIL_LEN:
            log.warning("Rejected oversized login inputs from %s", request.remote_addr)
            flash("بيانات الدخول غير صحيحة", "danger")
            return render_template("login.html", prefill_email="",
                seo_title="تسجيل الدخول - TecnoGems شحن ألعاب",
                seo_description="سجّل الدخول إلى حسابك في TecnoGems لمتابعة طلبات شحن الألعاب وإدارة محفظتك.")
        user = authenticate(email, password)
        if user:
            if email_verification_is_enabled() and user["role"] != "admin" and not user.get("email_verified"):
                flash("يجب تفعيل بريدك الإلكتروني قبل تسجيل الدخول. راجع بريدك.", "warning")
                return redirect("/login")
            # PATCH-H2: prevent session fixation by clearing any pre-existing
            # session data before assigning the authenticated user id.
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            flash("تم تسجيل الدخول بنجاح", "success")
            return redirect(safe_next_url("home"))
        # V50 SECURITY (M10): log failed auth attempts for monitoring / fail2ban.
        log.warning("Failed login attempt for email=%s from ip=%s",
                    email, request.remote_addr)
        flash("بيانات الدخول غير صحيحة", "danger")
        return render_template("login.html",
            prefill_email=email,
            seo_title="تسجيل الدخول - TecnoGems شحن ألعاب",
            seo_description="سجّل الدخول إلى حسابك في TecnoGems لمتابعة طلبات شحن الألعاب وإدارة محفظتك."
        )
    return render_template("login.html",
        seo_title="تسجيل الدخول - TecnoGems شحن ألعاب",
        seo_description="سجّل الدخول إلى حسابك في TecnoGems لمتابعة طلبات شحن الألعاب وإدارة محفظتك."
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    # V50.2 LOW: prefer POST (CSRF-protected form) for logout. GET is kept
    # for backwards compatibility with existing <a href="/logout"> links
    # and email deep-links, but new UI code should POST. When the request
    # is a GET we still log it so we can track how many clients are using
    # the deprecated path.
    if request.method == "GET":
        log.info("logout via GET from ip=%s user_id=%s — consider moving to POST form",
                 request.remote_addr, session.get("user_id"))
    session.clear()
    flash("تم تسجيل الخروج", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    orders = list_user_orders(user["id"])[:5]
    return render_template("dashboard.html", orders=orders)


@app.route("/servers")
@app.route("/legacy/servers")
def servers():
    return redirect(url_for("home"))


@app.route("/games/<provider>")
@app.route("/legacy/games/<provider>")
def games(provider):
    if provider not in ("server1", "server2"):
        abort(404)
    games = list_games(provider)
    return render_template("games.html", provider=provider, games=games)


@app.route("/products/<provider>/<game_key>")
@app.route("/legacy/products/<provider>/<game_key>")
def products(provider, game_key):
    game = get_game(provider, game_key)
    if not game:
        abort(404)
    groups = list_product_groups(provider, game_key, True)
    if groups:
        return render_template("product_groups.html", provider=provider, game=game, groups=groups)
    products = list_products(provider, game_key)
    return render_template("products.html", provider=provider, game=game, products=products, group=None)


@app.route("/products/<provider>/<game_key>/group/<int:group_id>")
def products_group(provider, game_key, group_id):
    game = get_game(provider, game_key)
    group = get_product_group(group_id)
    if not game or not group or group["provider"] != provider or group["game_key"] != game_key or not group.get("active", 1):
        abort(404)
    products = list_products(provider, game_key, group_id=group_id)
    return render_template("products.html", provider=provider, game=game, products=products, group=group)


@app.route("/checkout/<int:product_id>", methods=["GET", "POST"])
@app.route("/legacy/checkout/<int:product_id>", methods=["GET", "POST"])
@(limiter.limit("20 per minute") if limiter else (lambda f: f))
@login_required
def checkout(product_id):
    user = current_user()
    if not user:
        session.clear()
        flash("انتهت الجلسة أو لم يعد الحساب موجودًا. يرجى تسجيل الدخول مرة أخرى.", "warning")
        return redirect("/login")

    product = get_product(product_id)
    if not product:
        abort(404)
    game = get_game(product["provider"], product["game_key"])
    if not game:
        abort(404)
    if request.method == "POST":
        player_id = request.form.get("player_id", "").strip()
        # V50 SECURITY (C1): bound player_id length to prevent storage-bomb
        # attacks where MBs of garbage are shoved into orders.player_id.
        if len(player_id) < 3 or len(player_id) > MAX_PLAYER_ID_LEN:
            flash("معرف اللاعب غير صحيح", "danger")
            return redirect(request.url)

        try:
            order_id, code = create_order(user, product, game, player_id)
        except InsufficientBalance:
            flash("رصيدك غير كافٍ", "danger")
            return redirect(safe_next_url("home"))
        except Exception as _e:
            log.exception("create_order failed: %s", _e)
            flash("حدث خطأ أثناء إنشاء الطلب، يرجى المحاولة مجدداً", "danger")
            return redirect(request.url)

        enqueue_order_job(order_id, product, player_id)
        flash(f"تم استلام الطلب {code}. حالته الآن بانتظار بدء التنفيذ.", "success")
        return redirect(url_for("orders"))
    return render_template("checkout.html", product=product, game=game, show_server1=get_setting("show_server1", "1"),
        show_server2=get_setting("show_server2", "1"))



@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        new_email = request.form.get("new_email", "").strip().lower()

        if not name:
            flash("الاسم مطلوب", "danger")
            return redirect(url_for("profile"))

        update_user_profile(user["id"], name, phone)

        if new_email and new_email != user["email"]:
            if get_user_by_email(new_email):
                flash("هذا البريد مستخدم في حساب آخر", "danger")
            else:
                token = secrets.token_urlsafe(32)
                set_pending_email_change(user["id"], new_email, token)
                try:
                    send_email_change_confirmation(new_email, token)
                    flash("تم إرسال رابط تأكيد تغيير البريد إلى البريد الجديد", "success")
                except Exception:
                    flash("تم حفظ طلب تغيير البريد، لكن تعذر إرسال رسالة التأكيد الآن", "warning")
        else:
            flash("تم تحديث الملف الشخصي", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


@app.route("/confirm-email-change/<token>")
def confirm_email_change(token):
    ok, error = confirm_pending_email_change(token)
    if ok:
        flash("تم تغيير البريد الإلكتروني بنجاح", "success")
    else:
        flash(error or "تعذر تغيير البريد", "danger")
    return redirect(url_for("profile") if current_user() else url_for("login"))


@app.route("/orders")
@app.route("/legacy/orders")
@login_required
def orders():
    user = current_user()
    return render_template("orders.html", orders=list_user_orders(user["id"]))


@app.route("/wallet", methods=["GET", "POST"])
@app.route("/wallet/deposit", methods=["GET", "POST"])
@app.route("/legacy/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    user = current_user()
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", "0"))
        except Exception:
            amount = 0
        method_id = request.form.get("method_id", "")
        method = get_payment_method(method_id)
        proof_text = request.form.get("proof", "").strip()
        # V50 SECURITY (HE): cap proof-text length (2000 chars ~= 2KB).
        # Prevents a user from shoving MBs of garbage into deposits.proof.
        if len(proof_text) > MAX_PROOF_TEXT_LEN:
            flash("وصف الإثبات طويل جداً (الحد الأقصى 2000 حرف)", "danger")
            return redirect(url_for("wallet"))
        proof_file = request.files.get("proof_image")
        proof_parts = []

        if proof_text:
            proof_parts.append(proof_text)

        if proof_file and proof_file.filename:
            if not _ext_ok(proof_file.filename):
                flash("نوع الملف غير مدعوم. الأنواع المسموحة: jpg, png, webp, gif", "danger")
                return redirect(url_for("wallet"))
            # PATCH-H4: verify file content (magic bytes) — not just extension.
            if not _proof_magic_ok(proof_file.stream):
                flash("الملف لا يطابق نوعه المُعلَن. أرسل صورة (JPG/PNG/WebP/GIF) حقيقياً.", "danger")
                return redirect(url_for("wallet"))
            filename = secure_filename(proof_file.filename)
            filename = f"{user['id']}_{int(__import__('time').time())}_{filename}"
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            proof_file.save(save_path)
            # Use authenticated route instead of public /static/uploads/
            proof_parts.append(f"صورة: /uploads/proof/{filename}")


        proof = "\n".join(proof_parts)

        if amount <= 0:
            flash("أدخل مبلغًا صحيحًا", "danger")
            return redirect(url_for("wallet"))
        if not method:
            flash("طريقة الدفع غير صحيحة", "danger")
            return redirect(url_for("wallet"))
        if len(proof) < 3:
            flash("أرسل إثبات الدفع أو ارفع صورة الإيصال", "danger")
            return redirect(url_for("wallet"))

        rate = float(get_setting("usd_syp_rate", "15000") or 15000)
        if method.get("currency") == "SYP":
            amount_usd = round(amount / rate, 2)
        else:
            amount_usd = amount

        # V50 SECURITY (C3): cap the USD-equivalent deposit amount so abusive
        # users cannot submit fake deposits for billions that clutter the
        # admin queue or cause float overflow in financial aggregation.
        if amount_usd > MAX_DEPOSIT_USD:
            flash(f"المبلغ يتجاوز الحد الأقصى المسموح به ({MAX_DEPOSIT_USD:.0f}$)", "danger")
            return redirect(url_for("wallet"))

        dep = create_deposit(user["id"], amount, method_id, proof, amount_usd=amount_usd)
        if dep:
            flash(f"تم إرسال طلب الشحن {dep[1]}، بانتظار موافقة الإدارة", "success")
        else:
            flash("فشل إرسال طلب الشحن", "danger")
        return redirect(url_for("wallet"))

    return render_template("wallet.html", methods=list_payment_methods(only_active=True), support=get_setting("support_contact", "@support"), deposits=list_deposits_for_user(user["id"]), usd_syp_rate=get_usd_syp_rate())


@app.route("/wallet/transactions")
@login_required
def wallet_transactions():
    user = current_user()
    return render_template("wallet_transactions.html", deposits=list_deposits_for_user(user["id"]))




@app.route("/admin/game/<provider>/<game_key>/manual-prices", methods=["POST"])
@login_required
@admin_required
def admin_update_manual_syp_prices(provider, game_key):
    if not manual_price_edit_enabled():
        flash("تعديل الأسعار من الواجهة غير مفعّل من الإعدادات", "danger")
        return redirect(url_for("products", provider=provider, game_key=game_key))

    updates = []
    for key, value in request.form.items():
        if key.startswith("manual_syp_"):
            product_id = key.replace("manual_syp_", "")
            updates.append((product_id, value))
    update_manual_syp_prices(updates)
    flash("تم حفظ أسعار الليرة اليدوية", "success")
    return redirect(safe_next_url("products", provider=provider, game_key=game_key))

@app.route("/api/validate-player", methods=["POST"])
@login_required
@(limiter.limit("30 per minute") if limiter else (lambda f: f))
def api_validate_player():
    return {"enabled": False, "success": False}




# Admin
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    return render_template("admin/dashboard.html", stats=stats())


@app.route("/admin/orders")
@login_required
@admin_required
def admin_orders():
    status = request.args.get("status")
    return render_template("admin/orders.html", orders=list_orders(status), status=status)


@app.route("/admin/order/<int:order_id>/<action>", methods=["POST"])
@login_required
@admin_required
@(limiter.limit("60 per minute") if limiter else (lambda f: f))
def admin_order_action(order_id, action):
    order = get_order(order_id)
    if not order:
        abort(404)
    # V50.2 MEDIUM: audit trail for every admin order action so a compromised
    # admin account leaves a paper trail (who, from where, which order, what
    # change, from which status).
    admin = current_user()
    if action == "complete":
        update_order(order_id, "completed", order.get("provider_order_id"), "Manual complete")
        log.warning(
            "ADMIN_ORDER_COMPLETE admin_id=%s admin_email=%s order_id=%s "
            "old_status=%s user_id=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            order_id, order.get("status"), order.get("user_id"),
            request.remote_addr,
        )
        flash("تم تعليم الطلب كمكتمل", "success")
    elif action == "reject":
        update_order(order_id, "rejected", None, "Manual reject")
        log.warning(
            "ADMIN_ORDER_REJECT admin_id=%s admin_email=%s order_id=%s "
            "old_status=%s user_id=%s amount=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            order_id, order.get("status"), order.get("user_id"),
            order.get("price"), request.remote_addr,
        )
        flash("تم رفض الطلب وإرجاع الرصيد", "warning")
    else:
        abort(404)
    return redirect(url_for("admin_orders"))


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    q = request.args.get("q", "").strip()
    return render_template("admin/users.html", users=search_users(q), q=q)


@app.route("/admin/user/<int:user_id>")
@login_required
@admin_required
def admin_user_detail(user_id):
    user = get_user_by_id(user_id)
    if not user:
        abort(404)
    return render_template(
        "admin/user_detail.html",
        u=user,
        summary=user_financial_summary(user_id),
        orders=list_user_orders(user_id),
        deposits=list_user_deposits_admin(user_id)
    )


@app.route("/admin/user/<int:user_id>/balance", methods=["POST"])
@login_required
@admin_required
@(limiter.limit("30 per minute") if limiter else (lambda f: f))
def admin_user_balance(user_id):
    try:
        new_balance = float(request.form.get("amount", "0") or 0)
    except Exception:
        flash("أدخل رقمًا صحيحًا للرصيد", "danger")
        return redirect(safe_next_url("admin_users"))

    # V50 SECURITY (HG): bound admin balance edits to [0, MAX_ADMIN_BALANCE].
    # Prevents a compromised admin account from setting negative or
    # astronomical balances.
    if not (0 <= new_balance <= MAX_ADMIN_BALANCE):
        flash(f"القيمة يجب أن تكون بين 0 و {MAX_ADMIN_BALANCE:.0f}", "danger")
        return redirect(safe_next_url("admin_users"))

    admin = current_user()
    old = get_user_by_id(user_id)
    old_balance = float(old["balance"]) if old else None
    set_user_balance(user_id, new_balance)
    # V50 SECURITY (HG): audit log every admin balance change.
    log.warning(
        "ADMIN_BALANCE_CHANGE admin_id=%s admin_email=%s target_user_id=%s "
        "old=%s new=%s ip=%s",
        (admin or {}).get("id"), (admin or {}).get("email"),
        user_id, old_balance, new_balance, request.remote_addr
    )
    flash("تم تعيين الرصيد الجديد للمستخدم", "success")
    return redirect(safe_next_url("admin_users"))


@app.route("/admin/balances")
@login_required
@admin_required
def admin_balances():
    balances = {
        "server1": get_provider_balance("server1"),
        "server2": get_provider_balance("server2"),
    }
    return render_template("admin/balances.html", balances=balances)



def _public_user(user):
    if not user:
        return None
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "phone": user.get("phone") if hasattr(user, "get") else user["phone"],
        "role": user["role"],
        "balance": float(user["balance"] or 0),
        "email_verified": bool(user.get("email_verified", 0) if hasattr(user, "get") else user["email_verified"]) if "email_verified" in user.keys() else True,
    }


def _game_to_api(g):
    slug = f"{g['provider']}--{g['game_key']}"
    img = g.get("image_url", "") if hasattr(g, "get") else g["image_url"]
    if not img:
        img = "/static/img/game-default.svg"
    return {
        "id": slug,
        "slug": slug,
        "provider": g["provider"],
        "game_key": g["game_key"],
        "name": g["name"],
        "emoji": g.get("emoji", "🎮") if hasattr(g, "get") else g["emoji"],
        "cover": img,
        "image_url": img,
        "category": "ألعاب",
        "packagesCount": int(g.get("product_count", 0) or 0) if hasattr(g, "get") else int(g["product_count"] or 0),
        "startingPrice": float(g.get("min_price", 0) or 0) if hasattr(g, "get") else float(g["min_price"] or 0),
        "currency": "رصيد",
    }


@app.route("/api/me")
def api_me():
    user = current_user()
    return jsonify({
        "ok": True,
        "user": _public_user(user),
        "settings": {
            "theme": get_setting("site_theme", "theme-aurora"),
            "support": get_setting("support_contact", "@support"),
            "emailVerification": get_setting("email_verification_enabled", "0") == "1",
        }
    })


@app.route("/api/games")
def api_games():
    games = [_game_to_api(g) for g in list_public_games(True)]
    return jsonify({"ok": True, "games": games})


@app.route("/api/games/<slug>")
def api_game(slug):
    if "--" not in slug:
        return jsonify({"ok": False, "error": "اللعبة غير موجودة"}), 404
    provider, game_key = slug.split("--", 1)
    game = get_game(provider, game_key)
    if not game or not game["active"]:
        return jsonify({"ok": False, "error": "اللعبة غير موجودة"}), 404
    products = list_products(provider, game_key)
    return jsonify({
        "ok": True,
        "game": _game_to_api({
            **game,
            "product_count": len(products),
            "min_price": min([p["sell_price"] for p in products], default=0)
        }),
        "products": [{
            "id": p["id"],
            "name": p["name"],
            "priceUsd": float(p["sell_price"] or 0),
            "basePrice": float(p["base_price"] or 0),
            "popular": i == 1,
        } for i, p in enumerate(products)]
    })


@app.route("/api/login", methods=["POST"])
@(limiter.limit("10 per minute") if limiter else (lambda f: f))
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    # V50 SECURITY (HD): oversized inputs rejected pre-hash.
    if len(password) > MAX_PASSWORD_LEN or len(email) > MAX_EMAIL_LEN:
        log.warning("Rejected oversized api_login inputs from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "بيانات الدخول غير صحيحة"}), 401
    user = authenticate(email, password)
    if not user:
        # V50 SECURITY (M10): log failed API auth attempts.
        log.warning("Failed api_login for email=%s from ip=%s",
                    email, request.remote_addr)
        return jsonify({"ok": False, "error": "بيانات الدخول غير صحيحة"}), 401
    if email_verification_is_enabled() and user["role"] != "admin" and not user.get("email_verified"):
        return jsonify({"ok": False, "error": "يجب تفعيل بريدك الإلكتروني قبل تسجيل الدخول"}), 403
    # PATCH-H2: clear pre-existing session before authenticating
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    return jsonify({"ok": True, "user": _public_user(user)})


@app.route("/api/register", methods=["POST"])
@(limiter.limit("8 per minute") if limiter else (lambda f: f))
def api_register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""
    # V50 SECURITY (HD): cap input lengths before password hashing.
    if (
        len(password) > MAX_PASSWORD_LEN
        or len(email) > MAX_EMAIL_LEN
        or len(name) > MAX_NAME_LEN
        or len(phone) > MAX_PHONE_LEN
    ):
        return jsonify({"ok": False, "error": "أحد الحقول تجاوز الحد المسموح به"}), 400
    if not name or not email or not password:
        return jsonify({"ok": False, "error": "أكمل البيانات المطلوبة"}), 400
    if password != password_confirm:
        return jsonify({"ok": False, "error": "كلمة المرور وتأكيدها غير متطابقين"}), 400
    pw_ok, pw_err = validate_password_strength(password)
    if not pw_ok:
        return jsonify({"ok": False, "error": pw_err}), 400

    verification_enabled = email_verification_is_enabled()
    token = secrets.token_urlsafe(32) if verification_enabled else None
    ok, err = create_user(name, email, phone, password, email_verified=0 if verification_enabled else 1, email_token=token)
    if not ok:
        return jsonify({"ok": False, "error": err or "فشل إنشاء الحساب"}), 400

    if verification_enabled:
        try:
            send_verification_email(email, token)
            return jsonify({"ok": True, "message": "تم إنشاء الحساب. أرسلنا رابط التفعيل إلى بريدك."})
        except Exception as exc:
            log.warning("api_register verification email failed for %s: %s", email, exc)
            return jsonify({"ok": True, "message": "تم إنشاء الحساب، لكن لم يتم إرسال بريد التفعيل. افحص إعدادات Gmail App Password في ملف .env، ثم استخدم إعادة إرسال رابط التفعيل."})
    return jsonify({"ok": True, "message": "تم إنشاء الحساب. يمكنك تسجيل الدخول الآن."})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/orders", methods=["GET", "POST"])
@(limiter.limit("20 per minute") if limiter else (lambda f: f))
def api_orders():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "يجب تسجيل الدخول"}), 401

    if request.method == "GET":
        orders = list_user_orders(user["id"])
        return jsonify({"ok": True, "orders": [dict(o) for o in orders]})

    data = request.get_json(silent=True) or {}
    try:
        product_id = int(data.get("product_id"))
    except Exception:
        return jsonify({"ok": False, "error": "الباقة غير صحيحة"}), 400
    player_id = (data.get("player_id") or "").strip()
    # V50 SECURITY (C1): bound player_id length (see checkout).
    if len(player_id) < 3 or len(player_id) > MAX_PLAYER_ID_LEN:
        return jsonify({"ok": False, "error": "معرف اللاعب غير صحيح"}), 400

    product = get_product(product_id)
    if not product:
        return jsonify({"ok": False, "error": "الباقة غير موجودة"}), 404
    game = get_game(product["provider"], product["game_key"])
    if not game:
        return jsonify({"ok": False, "error": "اللعبة غير موجودة"}), 404

    # PATCH-B2/B7: rely on atomic balance deduction inside create_order
    # (BEGIN IMMEDIATE + UPDATE WHERE balance>=price) instead of the
    # race-prone Python pre-check, and properly catch InsufficientBalance
    # so the client gets a clean 400 instead of a 500.
    try:
        order_id, code = create_order(user, product, game, player_id)
    except InsufficientBalance:
        return jsonify({"ok": False, "error": "رصيدك غير كافٍ"}), 400
    except Exception as _e:
        log.exception("api_orders create_order failed: %s", _e)
        return jsonify({"ok": False, "error": "حدث خطأ أثناء إنشاء الطلب"}), 500

    enqueue_order_job(order_id, product, player_id)
    return jsonify({"ok": True, "order_id": order_id, "order_code": code})


@app.route("/api/payment-methods")
def api_payment_methods():
    return jsonify({"ok": True, "methods": list_payment_methods(True)})


@app.route("/api/wallet")
def api_wallet():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "يجب تسجيل الدخول"}), 401
    return jsonify({"ok": True, "balance": float(user["balance"] or 0), "methods": list_payment_methods(True)})


@app.route("/games")
def games_index():
    return redirect(url_for("home"))



_setup_lock = threading.Lock()

@app.before_request
def setup_once():
    if not getattr(app, "_setup_done", False):
        with _setup_lock:
            if not getattr(app, "_setup_done", False):
                # V47: warn / block weak admin password in production
                _admin_pw = os.getenv("ADMIN_PASSWORD", "admin123456")
                _weak_passwords = {"admin123456", "admin", "password", "123456", "change-this", "<CHANGE-THIS-STRONG-PASSWORD>", ""}
                if _admin_pw in _weak_passwords or len(_admin_pw) < 10:
                    if os.getenv("FLASK_ENV") == "production":
                        raise RuntimeError(
                            "ADMIN_PASSWORD is too weak or still the default value. "
                            "Set a strong ADMIN_PASSWORD in .env before running in production."
                        )
                    log.warning("ADMIN_PASSWORD is weak or default. Change it before going to production.")
                init_db()
                # PATCH-B8: ensure performance indexes also exist in production
                # (previously only ran via __main__).
                try:
                    ensure_indexes()
                except Exception as _exc:
                    log.warning("ensure_indexes failed: %s", _exc)
                seed_admin(os.getenv("ADMIN_EMAIL", "admin@example.com"), _admin_pw)
                seed_local_provider_catalog()
                try:
                    attach_generated_posters()
                except Exception:
                    pass
                app._setup_done = True



@app.route("/admin/games", methods=["GET", "POST"])
@login_required
@admin_required
def admin_games():
    if request.method == "POST":
        # حفظ الألعاب التي تظهر في واجهة المستخدم
        active_keys = set(request.form.getlist("active_game"))
        for game in list_all_game_groups():
            key = f"{game['provider']}::{game['game_key']}"
            set_game_active(game["provider"], game["game_key"], key in active_keys)
        flash("تم حفظ الألعاب المعروضة في الواجهة", "success")
        return redirect(url_for("admin_games"))

    return render_template(
        "admin/games.html",
        games=list_all_game_groups(),
        discovered=list_product_games_from_products()
    )


@app.route("/admin/games/add", methods=["POST"])
@login_required
@admin_required
@(limiter.limit("20 per minute") if limiter else (lambda f: f))
def admin_add_game():
    provider = request.form.get("provider", "").strip()
    game_key = request.form.get("game_key", "").strip().lower().replace(" ", "_")
    name = request.form.get("name", "").strip()
    emoji = request.form.get("emoji", "").strip() or "🎮"
    image_url = request.form.get("image_url", "").strip()

    if provider not in ("server1", "server2") or not game_key or not name:
        flash("تأكد من إدخال المزود ومعرّف اللعبة واسمها", "danger")
    else:
        add_custom_game(provider, game_key, name, emoji, image_url, 1)
        set_game_active(provider, game_key, True)
        # V50.2 MEDIUM: audit log for admin game catalogue changes.
        admin = current_user()
        log.warning(
            "ADMIN_GAME_ADD admin_id=%s admin_email=%s provider=%s game_key=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            provider, game_key, request.remote_addr,
        )
        flash(f"تمت إضافة/تفعيل اللعبة: {name}", "success")
    return redirect(url_for("admin_games"))


@app.route("/admin/game/<provider>/<game_key>/image", methods=["POST"])
@login_required
@admin_required
def admin_game_image(provider, game_key):
    game = get_game(provider, game_key)
    if not game:
        abort(404)

    file = request.files.get("image")
    image_url = request.form.get("image_url", "").strip()

    if file and file.filename:
        uploads_dir = Path("static/uploads/games")
        uploads_dir.mkdir(parents=True, exist_ok=True)
        ext = Path(file.filename).suffix.lower()
        if ext not in [".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg"]:
            flash("نوع الصورة غير مدعوم", "danger")
            return redirect(url_for("admin_games"))
        # V50.2 MEDIUM (M8): random suffix on uploaded game filenames so they
        # are not trivially enumerable. The previous "provider_gamekey.ext"
        # pattern let anyone guess URLs for every game in the catalogue
        # (and cache-bust attacks / asset scraping).
        _rand = secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10]
        if ext == ".svg":
            # PATCH-H1: sanitise SVG to prevent stored-XSS via <script> or
            # javascript: URIs that would execute when the image is shown.
            safe_name = secure_filename(f"{provider}_{game_key}_{_rand}.svg")
            target = uploads_dir / safe_name
            try:
                raw = file.stream.read().decode("utf-8", errors="replace")
            except Exception:
                flash("تعذّر قراءة ملف SVG", "danger")
                return redirect(url_for("admin_games"))
            cleaned = _sanitise_svg(raw)
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(cleaned)
            image_url = "/" + str(target).replace("\\", "/")
        else:
            base = secure_filename(f"{provider}_{game_key}_{_rand}")
            saved = process_upload_to_webp(file, str(uploads_dir), base, max_w=800, quality=82)
            if not saved:
                flash("تعذّر معالجة الصورة", "danger")
                return redirect(url_for("admin_games"))
            image_url = "/" + str(uploads_dir / saved).replace("\\", "/")


    if image_url:
        update_game_image(provider, game_key, image_url)
        # V50.2 MEDIUM: audit log for admin image changes.
        admin = current_user()
        log.warning(
            "ADMIN_GAME_IMAGE admin_id=%s admin_email=%s provider=%s game_key=%s url=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            provider, game_key, image_url, request.remote_addr,
        )
        flash("تم تحديث صورة اللعبة", "success")
    else:
        flash("اختر صورة أو ضع رابط صورة", "warning")

    return redirect(url_for("admin_games"))

@app.route("/admin/game/<provider>/<game_key>/products", methods=["GET", "POST"])
@login_required
@admin_required
def admin_game_products(provider, game_key):
    game = get_game(provider, game_key)
    if not game:
        abort(404)

    if request.method == "POST":
        action = request.form.get("action", "save_products")

        if action == "create_group":
            name = request.form.get("group_name", "").strip()
            image_url = request.form.get("group_image_url", "").strip() or game.get("image_url", "")
            sort_order = request.form.get("group_sort_order", "1")
            if name:
                create_product_group(provider, game_key, name, image_url, sort_order, 1 if request.form.get("group_active") else 0)
                flash("تم إنشاء واجهة العرض", "success")
            else:
                flash("اكتب اسم واجهة العرض", "danger")
            return redirect(url_for("admin_game_products", provider=provider, game_key=game_key))

        if action == "update_group":
            group_id = request.form.get("group_id")
            if group_id:
                update_product_group(
                    group_id,
                    request.form.get("group_name", "").strip(),
                    request.form.get("group_image_url", "").strip() or game.get("image_url", ""),
                    request.form.get("group_sort_order", "1"),
                    1 if request.form.get("group_active") else 0
                )
                flash("تم تحديث واجهة العرض", "success")
            return redirect(url_for("admin_game_products", provider=provider, game_key=game_key))

        if action == "delete_group":
            group_id = request.form.get("group_id")
            if group_id:
                delete_product_group(group_id)
                flash("تم حذف واجهة العرض وإرجاع باقاتها إلى عام", "warning")
            return redirect(url_for("admin_game_products", provider=provider, game_key=game_key))

        update_game_pricing(provider, game_key, request.form.get("pricing_currency", "GLOBAL"))
        updates = []
        for key, value in request.form.items():
            if key.startswith("sort_"):
                product_id = key.replace("sort_", "")
                updates.append({
                    "product_id": int(product_id),
                    "sort_order": int(value or 0),
                    "group_id": request.form.get(f"group_{product_id}") or None,
                    "fixed_syp_price": request.form.get(f"fixed_syp_{product_id}") or 0,
                    "pricing_mode": request.form.get(f"pricing_mode_{product_id}") or "usd"
                })
        update_products_admin(updates, get_usd_syp_rate())
        flash("تم حفظ ترتيب الباقات وتقسيمها والتسعير", "success")
        return redirect(url_for("admin_game_products", provider=provider, game_key=game_key))

    products = list_all_products_for_admin(provider, game_key)
    groups = list_product_groups(provider, game_key, False)
    return render_template("admin/game_products.html", game=game, products=products, groups=groups, usd_syp_rate=get_usd_syp_rate())


# Start in-memory worker only if REDIS_URL is not set
if not os.getenv("REDIS_URL"):
    threading.Thread(target=worker, daemon=True).start()
    log.info("Started in-memory worker thread.")
else:
    log.info("Using RQ worker (worker_rq.py) for order processing.")
# V47: warn operators that in-memory queue loses jobs on process restart



@app.route("/admin/accounting", methods=["GET", "POST"])
@login_required
@admin_required
def admin_accounting():
    if request.method == "POST":
        val = request.form.get("sales_override", "").strip()
        if val == "":
            set_setting("sales_override", "")
            flash("تم إلغاء تصحيح رقم المبيعات والعودة لحساب السجل", "success")
        else:
            try:
                float(val)
                set_setting("sales_override", val)
                flash("تم حفظ رقم المبيعات المعروض", "success")
            except Exception:
                flash("رقم المبيعات غير صحيح", "danger")
        return redirect(url_for("admin_accounting"))
    return render_template("admin/accounting.html", data=accounting_summary())


@app.route("/admin/deposits")
@login_required
@admin_required
def admin_deposits():
    status = request.args.get("status")
    q = request.args.get("q", "").strip()
    deposits = list_deposits(status)
    if q:
        ql = q.lower()
        deposits = [d for d in deposits if ql in str(d.get("deposit_code","")).lower()
                    or ql in str(d.get("user_name","")).lower()
                    or ql in str(d.get("user_email","")).lower()
                    or ql in str(d.get("proof","")).lower()]
    return render_template("admin/deposits.html", deposits=deposits, status=status, q=q)


@app.route("/admin/deposit/<int:deposit_id>/<action>", methods=["POST"])
@login_required
@admin_required
@(limiter.limit("60 per minute") if limiter else (lambda f: f))
def admin_deposit_action(deposit_id, action):
    # V50.2 MEDIUM: audit trail for deposit approve/reject. Deposits are
    # direct balance writes, so every admin decision is logged.
    admin = current_user()
    if action == "approve":
        ok = update_deposit(deposit_id, "approved")
        log.warning(
            "ADMIN_DEPOSIT_APPROVE admin_id=%s admin_email=%s deposit_id=%s ok=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            deposit_id, ok, request.remote_addr,
        )
        flash("تمت الموافقة وإضافة الرصيد" if ok else "لا يمكن تعديل هذا الطلب", "success" if ok else "warning")
    elif action == "reject":
        ok = update_deposit(deposit_id, "rejected")
        log.warning(
            "ADMIN_DEPOSIT_REJECT admin_id=%s admin_email=%s deposit_id=%s ok=%s ip=%s",
            (admin or {}).get("id"), (admin or {}).get("email"),
            deposit_id, ok, request.remote_addr,
        )
        flash("تم رفض طلب الشحن" if ok else "لا يمكن تعديل هذا الطلب", "warning")
    else:
        abort(404)
    return redirect(url_for("admin_deposits"))


@app.route("/admin/payment-methods")
@login_required
@admin_required
def admin_payment_methods():
    return render_template("admin/payment_methods.html", methods=list_payment_methods())


@app.route("/admin/payment-method/<method_id>", methods=["GET", "POST"])
@login_required
@admin_required
def admin_payment_method_edit(method_id):
    method = get_payment_method(method_id)
    if not method:
        abort(404)
    if request.method == "POST":
        update_payment_method(
            method_id,
            name=request.form.get("name", "").strip(),
            emoji=request.form.get("emoji", "").strip() or "💳",
            address=request.form.get("address", "").strip(),
            instructions=request.form.get("instructions", "").strip(),
            active=bool(request.form.get("active")),
            currency=request.form.get("currency", "USD")
        )
        flash("تم تحديث طريقة الدفع", "success")
        return redirect(url_for("admin_payment_methods"))
    return render_template("admin/payment_method_edit.html", method=method)


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
@admin_required
def admin_settings():
    if request.method == "POST":
        set_setting("support_contact", request.form.get("support_contact", "").strip())
        set_setting("whatsapp_number", request.form.get("whatsapp_number", "").strip().replace("+", ""))
        set_setting("telegram_username", request.form.get("telegram_username", "").strip().lstrip("@"))
        set_setting("usd_syp_rate", request.form.get("usd_syp_rate", "15000").strip())
        set_setting("pricing_mode", request.form.get("pricing_mode", "usd"))
        set_setting("manual_orders", "1" if request.form.get("manual_orders") else "0")
        set_setting("show_server1", "1" if request.form.get("show_server1") else "0")
        set_setting("show_server2", "1" if request.form.get("show_server2") else "0")
        set_setting("email_verification_enabled", "1" if request.form.get("email_verification_enabled") else "0")
        set_setting("hide_phone_on_register", "1" if request.form.get("hide_phone_on_register") else "0")
        set_setting("site_theme", request.form.get("site_theme", "theme-aurora"))
        set_setting("nav_mode", request.form.get("nav_mode", "menu"))
        set_setting("show_groups_direct", "1" if request.form.get("show_groups_direct") else "0")
        # old_games_layout setting removed in V44.2 (single neon layout only)
        set_setting("manual_price_edit_enabled", "1" if request.form.get("manual_price_edit_enabled") else "0")
        set_setting("auto_refund_on_failure", "1" if request.form.get("auto_refund_on_failure") else "0")
        try:
            new_margin = float(request.form.get("profit_margin", "1.20"))
            try:
                old_margin = float(get_setting("profit_margin", "1.20") or "1.20")
            except Exception:
                old_margin = None
            if old_margin is None or abs(new_margin - old_margin) > 1e-6:
                update_profit_margin(new_margin)
        except Exception:
            flash("نسبة الربح غير صحيحة", "danger")
        flash("تم حفظ الإعدادات", "success")
        return redirect(url_for("admin_settings"))
    return render_template(
        "admin/settings.html",
        support=get_setting("support_contact", "@support"),
        usd_syp_rate=get_setting("usd_syp_rate", "15000"),
        selected_display_currency=get_display_currency(),
        selected_pricing_mode=get_pricing_mode(),
        manual_price_edit_enabled_setting=get_setting("manual_price_edit_enabled", "0"),
        whatsapp_number_setting=get_setting("whatsapp_number", ""),
        telegram_username_setting=get_setting("telegram_username", ""),
        manual_orders=get_setting("manual_orders", "0"),
        show_server1=get_setting("show_server1", "1"),
        show_server2=get_setting("show_server2", "1"),
        email_verification_enabled=get_setting("email_verification_enabled", "0"),
        hide_phone_on_register=get_setting("hide_phone_on_register", "0"),
        email_is_configured=email_is_configured(),
        profit_margin=get_setting("profit_margin", "1.20"),
        selected_theme=get_setting("site_theme", "theme-aurora"),
        selected_nav_mode=get_setting("nav_mode", "menu"),
        show_groups_direct_setting=get_setting("show_groups_direct", "0"),
        old_games_layout_setting=get_setting("old_games_layout", "0"),
        auto_refund_on_failure_setting=get_setting("auto_refund_on_failure", "0"),
    )


# ============================================================================
# V43: Wishlist + Search Autocomplete REMOVED per user request.
# Google OAuth + Service Worker remain (below).
# ============================================================================
from database import (
    get_user_by_google_sub as _db_get_user_by_google_sub,
    create_user_oauth as _db_create_user_oauth,
    link_user_google_sub as _db_link_user_google_sub,
)


# ---------------- Service Worker (root scope) ----------------
@app.route("/sw.js")
def service_worker():
    resp = send_from_directory("static", "sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


# ---------------- Google OAuth ----------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "").strip() or f"{BASE_URL}/auth/google/callback"

_oauth = None
try:
    if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
        from authlib.integrations.flask_client import OAuth as _AuthlibOAuth
        _oauth = _AuthlibOAuth(app)
        _oauth.register(
            name="google",
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
except Exception as exc:
    app.logger.warning("Google OAuth disabled: %s", exc)
    _oauth = None


@app.context_processor
def _inject_oauth_flags():
    return {"google_oauth_enabled": bool(_oauth)}


@app.route("/auth/google")
def auth_google_login():
    if not _oauth:
        flash("تسجيل الدخول بـ Google غير مفعّل حالياً", "warning")
        return redirect(url_for("login"))
    return _oauth.google.authorize_redirect(GOOGLE_REDIRECT_URI)


@app.route("/auth/google/callback")
def auth_google_callback():
    if not _oauth:
        return redirect(url_for("login"))
    try:
        token = _oauth.google.authorize_access_token()
        userinfo = token.get("userinfo") or _oauth.google.parse_id_token(token, None)
    except Exception as exc:
        app.logger.error("Google OAuth callback failed: %s", exc)
        flash("تعذر إكمال تسجيل الدخول بـ Google", "danger")
        return redirect(url_for("login"))

    sub = (userinfo or {}).get("sub")
    email = ((userinfo or {}).get("email") or "").strip().lower()
    name = (userinfo or {}).get("name") or ""
    if not sub or not email:
        flash("لم يتم استلام بيانات كافية من Google", "danger")
        return redirect(url_for("login"))

    user = _db_get_user_by_google_sub(sub)
    if not user:
        existing = get_user_by_email(email)
        if existing:
            _db_link_user_google_sub(existing["id"], sub)
            user = existing
        else:
            uid = _db_create_user_oauth(name, email, sub)
            if not uid:
                flash("فشل إنشاء حساب جديد من Google", "danger")
                return redirect(url_for("login"))
            user = get_user_by_id(uid)

    # PATCH-H2: clear session before assigning user id (Google OAuth too)
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    flash("تم تسجيل الدخول عبر Google", "success")
    return redirect(safe_next_url("home"))


# PATCH-H1: exempt all /api/* JSON endpoints from CSRF.
# JSON requests cannot be forged via a hidden form, and the session cookie
# uses SameSite=Lax which already blocks cross-site form-style POSTs. Apps
# that need to call these from another origin must add their own auth.
#
# V50.2 MEDIUM: however, attackers CAN reach these endpoints from any
# origin if the browser decides to send cookies. We now add a defence-in-depth
# Origin/Referer check via before_request: for non-GET /api/* requests the
# Origin (or Referer) header must match our host or be absent (curl / native
# app clients). Mismatched origins are rejected with 403.
if csrf is not None:
    for _fn in (
        api_login, api_register, api_logout, api_orders,
        api_validate_player, api_me, api_games, api_game,
        api_payment_methods, api_wallet,
    ):
        try:
            csrf.exempt(_fn)
        except Exception:
            pass


@app.before_request
def _api_origin_guard():
    """V50.2 MEDIUM: reject state-changing /api/* requests whose Origin or
    Referer header points at a different host than this server. Protects
    CSRF-exempt endpoints from being called by malicious sites that
    managed to piggy-back on SameSite=Lax exceptions (e.g. top-level
    navigation POST fallbacks).
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if not request.path.startswith("/api/"):
        return None
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    # Absent Origin+Referer is allowed: real mobile / native / curl clients
    # often omit them. Browsers will send at least one.
    if not origin and not referer:
        return None
    try:
        from urllib.parse import urlparse
        host = request.host  # includes port if non-standard
        for candidate in (origin, referer):
            if not candidate:
                continue
            p = urlparse(candidate)
            if not p.netloc:
                continue
            if p.netloc != host:
                log.warning(
                    "API_ORIGIN_BLOCK path=%s origin=%s referer=%s host=%s ip=%s",
                    request.path, origin, referer, host, request.remote_addr,
                )
                return jsonify({"error": "cross-origin request rejected"}), 403
    except Exception as exc:
        log.warning("_api_origin_guard parse error: %s", exc)
    return None


if __name__ == "__main__":
    init_db()
    ensure_indexes()
    _admin_pw_dev = os.getenv("ADMIN_PASSWORD", "").strip()
    if not _admin_pw_dev or len(_admin_pw_dev) < 10 or _admin_pw_dev in {"admin", "admin123456", "password", "<CHANGE-THIS-STRONG-PASSWORD>"}:
        log.warning("ADMIN_PASSWORD missing/weak — using temporary dev password 'changeme123!'. Override via .env.")
        _admin_pw_dev = "changeme123!"
    seed_admin(os.getenv("ADMIN_EMAIL", "admin@example.com"), _admin_pw_dev)
    # V50 SECURITY (CB): never turn on the Werkzeug debugger outside explicit
    # development. The debugger console is a remote code execution surface
    # if any attacker can reach it.
    _debug = os.getenv("FLASK_ENV", "development").lower() == "development"
    if os.getenv("FLASK_ENV") == "production":
        _debug = False
    app.run(host="0.0.0.0", port=5000, debug=_debug)
