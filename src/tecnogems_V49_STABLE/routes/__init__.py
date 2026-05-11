"""V48.1: Blueprint package.

The lang_bp blueprint was an experimental phase-1 extraction that conflicted
with the legacy /lang/<lang> and /reset-lang routes still defined in app.py.
We keep this package as a placeholder for the future split into auth/admin/api
blueprints but do NOT import or register lang_bp anymore — that prevents the
circular import on `from app import safe_next_url` and removes dead code.
"""


def register_blueprints(app, deps=None):
    """No-op for now; reserved for future blueprints."""
    return None
