#!/bin/bash
# V49 Currency Hotfix — one-shot installer.
#
# Usage (run on the server):
#   curl -fsSL https://raw.githubusercontent.com/alexkline3322-byte/tecnogems/hotfix/v49-currency-deposit-500/install_hotfix.sh | bash
#
# What it does:
#   1. Downloads the 4 modified files from the hotfix branch on GitHub
#   2. Builds a zip in /root/
#   3. Backs up the current /root/project files
#   4. Applies the hotfix
#   5. Smoke-tests + restarts + health-checks
#   6. Rolls back automatically if anything fails

set -u
PROJECT="/root/project"
BRANCH="hotfix/v49-currency-deposit-500"
BASE="https://raw.githubusercontent.com/alexkline3322-byte/tecnogems/${BRANCH}"
TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/hotfix_backup_$TS"
SRC="/tmp/v49_hotfix_src_$TS"
ZIP="/root/tecnogems_V49_HOTFIX_currency_$TS.zip"

echo "=== V49 Currency Hotfix installer ($TS) ==="

# Sanity: /root/project must exist
if [ ! -d "$PROJECT" ]; then
    echo "!!! $PROJECT does not exist. Are you sure this is the right server?"
    exit 1
fi
if [ ! -x "$PROJECT/.venv/bin/python" ]; then
    echo "!!! $PROJECT/.venv/bin/python not found. The project may not have a virtualenv."
    exit 1
fi

# [1] Download the 4 modified files
echo "[1/7] Downloading modified files from branch $BRANCH ..."
rm -rf "$SRC"
mkdir -p "$SRC/tecnogems/templates/admin"

download() {
    local url="$1" out="$2"
    if ! curl -fsSL -o "$out" "$url"; then
        echo "    !!! Failed to download: $url"
        exit 1
    fi
    # A GitHub 404 is HTML, not what we want. Sanity-check size.
    local size=$(stat -c%s "$out" 2>/dev/null || wc -c < "$out")
    if [ -z "$size" ] || [ "$size" -lt 200 ]; then
        echo "    !!! File suspiciously small ($size bytes): $out"
        echo "    Content:"
        head -5 "$out"
        exit 1
    fi
    echo "    ok: $(basename $out) ($size bytes)"
}

download "$BASE/database.py"                           "$SRC/tecnogems/database.py"
download "$BASE/templates/admin/user_detail.html"      "$SRC/tecnogems/templates/admin/user_detail.html"
download "$BASE/templates/admin/deposits.html"         "$SRC/tecnogems/templates/admin/deposits.html"
download "$BASE/templates/wallet_transactions.html"    "$SRC/tecnogems/templates/wallet_transactions.html"

# Verify database.py looks like Python
if ! head -3 "$SRC/tecnogems/database.py" | grep -q '^import '; then
    echo "!!! database.py does not look like Python. Aborting."
    head -5 "$SRC/tecnogems/database.py"
    exit 1
fi

# [2] Backup current files
echo "[2/7] Backing up current files to $BACKUP_DIR ..."
mkdir -p "$BACKUP_DIR/templates/admin"
cp "$PROJECT/database.py"                        "$BACKUP_DIR/database.py"
cp "$PROJECT/templates/admin/user_detail.html"   "$BACKUP_DIR/templates/admin/user_detail.html"
cp "$PROJECT/templates/admin/deposits.html"      "$BACKUP_DIR/templates/admin/deposits.html"
cp "$PROJECT/templates/wallet_transactions.html" "$BACKUP_DIR/templates/wallet_transactions.html"
echo "    ok"

# [3] Build a zip (so admins can replay later if needed). Non-fatal.
echo "[3/7] Packaging $ZIP ..."
if command -v zip >/dev/null 2>&1; then
    (cd "$SRC" && zip -rq "$ZIP" tecnogems/) && echo "    $(ls -lh $ZIP | awk '{print $5, $9}')"
elif command -v python3 >/dev/null 2>&1; then
    python3 - <<PY_ZIP
import os, zipfile
src = "$SRC"
out = "$ZIP"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for f in files:
            full = os.path.join(root, f)
            z.write(full, os.path.relpath(full, src))
print("    packaged via python zipfile:", out)
PY_ZIP
else
    echo "    (skipped: no zip and no python3; backup dir alone is enough for rollback)"
fi

# [4] Copy hotfix over project
echo "[4/7] Applying hotfix files over $PROJECT ..."
cp "$SRC/tecnogems/database.py"                        "$PROJECT/database.py"
cp "$SRC/tecnogems/templates/admin/user_detail.html"   "$PROJECT/templates/admin/user_detail.html"
cp "$SRC/tecnogems/templates/admin/deposits.html"      "$PROJECT/templates/admin/deposits.html"
cp "$SRC/tecnogems/templates/wallet_transactions.html" "$PROJECT/templates/wallet_transactions.html"
rm -rf "$SRC"
echo "    ok"

# [5] Smoke test BEFORE restarting. We MUST cd into $PROJECT because
# wsgi.py is in that directory — Python's sys.path starts with CWD, so
# running the check from /root (where `curl | bash` leaves us) would
# fail with ModuleNotFoundError even if the code is fine.
echo "[5/7] Smoke-testing the updated app (import check) ..."
SMOKE=$(cd "$PROJECT" && "$PROJECT/.venv/bin/python" -c "from wsgi import app; print('SMOKE_OK')" 2>&1 || true)
if ! echo "$SMOKE" | grep -q "SMOKE_OK"; then
    echo "!!! Smoke test FAILED. Rolling back WITHOUT restart (zero downtime)."
    echo "---- smoke output ----"
    echo "$SMOKE"
    echo "----------------------"
    cp "$BACKUP_DIR/database.py"                        "$PROJECT/database.py"
    cp "$BACKUP_DIR/templates/admin/user_detail.html"   "$PROJECT/templates/admin/user_detail.html"
    cp "$BACKUP_DIR/templates/admin/deposits.html"      "$PROJECT/templates/admin/deposits.html"
    cp "$BACKUP_DIR/templates/wallet_transactions.html" "$PROJECT/templates/wallet_transactions.html"
    echo ">>> ROLLED BACK (backup kept at $BACKUP_DIR)"
    exit 1
fi
echo "    ok"

# [6] Restart + health check
echo "[6/7] Restarting game-topup ..."
systemctl restart game-topup
sleep 4
if curl -fsSI http://127.0.0.1:5000/ >/dev/null 2>&1; then
    echo "    health check OK"
else
    echo "!!! Health check FAILED. Rolling back."
    journalctl -u game-topup --no-pager -n 25
    cp "$BACKUP_DIR/database.py"                        "$PROJECT/database.py"
    cp "$BACKUP_DIR/templates/admin/user_detail.html"   "$PROJECT/templates/admin/user_detail.html"
    cp "$BACKUP_DIR/templates/admin/deposits.html"      "$PROJECT/templates/admin/deposits.html"
    cp "$BACKUP_DIR/templates/wallet_transactions.html" "$PROJECT/templates/wallet_transactions.html"
    systemctl restart game-topup
    sleep 3
    echo ">>> ROLLED BACK"
    systemctl status game-topup --no-pager | head -8
    exit 1
fi

# [7] Done
echo "[7/7] >>> HOTFIX APPLIED SUCCESSFULLY <<<"
echo ""
echo "Summary:"
echo "  - Backup of old files : $BACKUP_DIR"
echo "  - Hotfix zip kept at  : $ZIP"
echo ""
echo "To roll back manually later:"
echo "  cp $BACKUP_DIR/database.py                        $PROJECT/"
echo "  cp $BACKUP_DIR/templates/admin/user_detail.html   $PROJECT/templates/admin/"
echo "  cp $BACKUP_DIR/templates/admin/deposits.html      $PROJECT/templates/admin/"
echo "  cp $BACKUP_DIR/templates/wallet_transactions.html $PROJECT/templates/"
echo "  systemctl restart game-topup"
echo ""
systemctl status game-topup --no-pager | head -10
