"""V53: CI guard — prevent inline <script> without nonce in any template."""
import re
from pathlib import Path

SCRIPT_RE = re.compile(
    r'<script(?![^>]*(?:type=["\']application/ld\+json["\']|nonce=["\']))[^>]*>',
    re.IGNORECASE,
)


def test_no_inline_script_without_nonce():
    """Every <script> tag must have nonce= or be type=application/ld+json."""
    offenders = []
    templates_dir = Path(__file__).resolve().parent.parent / "templates"
    for html in templates_dir.rglob("*.html"):
        content = html.read_text(encoding="utf-8")
        # Remove Jinja comments {# ... #} before scanning
        cleaned = re.sub(r"\{#.*?#\}", "", content, flags=re.DOTALL)
        for match in SCRIPT_RE.finditer(cleaned):
            offenders.append(f"{html.relative_to(templates_dir)}:{match.start()}: {match.group()[:80]}")
    assert not offenders, (
        "Inline <script> without nonce found. Add nonce=\"{{ csp_nonce }}\" or "
        "move JS to static/js/pages/:\n" + "\n".join(offenders)
    )
