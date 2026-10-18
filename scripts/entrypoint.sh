#!/bin/sh
# =============================================================================
# SNode.C IdP — Docker entrypoint / first-run bootstrap
# =============================================================================
set -e

DATA_DIR="${DATA_DIR:-/app/data}"
KEYS_DIR="${KEYS_DIR:-/app/keys}"
DB_PATH="${DB_PATH:-$DATA_DIR/auth.db}"
PRIVATE_KEY="${IDP_PRIVATE_KEY_PATH:-$KEYS_DIR/private_key.pem}"
PUBLIC_KEY="${IDP_PUBLIC_KEY_PATH:-$KEYS_DIR/public_key.pem}"

echo "[entrypoint] SNode.C Identity Provider starting..."

# Never replace an existing private key merely because its public export is missing.
umask 077
if [ ! -f "$PRIVATE_KEY" ]; then
    if [ -e "$DB_PATH" ]; then
        echo "[entrypoint] Existing database requires its original signing key" >&2
        exit 1
    fi
    mkdir -p "$KEYS_DIR"
    openssl genrsa -out "$PRIVATE_KEY" 2048 2>/dev/null
fi
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null
TOTP_KEY_PATH="${TOTP_KEY_PATH:-$KEYS_DIR/totp.key}"
if [ ! -f "$TOTP_KEY_PATH" ]; then
    if [ -e "$DB_PATH" ]; then
        echo "[entrypoint] Existing database requires its TOTP encryption key; provision it explicitly" >&2
        exit 1
    fi
    openssl rand -out "$TOTP_KEY_PATH" 32
fi
export TOTP_KEY_PATH

# ── Ensure data directory exists ──────────────────────────────────────────────
mkdir -p "$DATA_DIR"

# ── Export environment so the binary can read it ──────────────────────────────
export DB_PATH="$DB_PATH"
export IDP_PRIVATE_KEY_PATH="$PRIVATE_KEY"
export IDP_PUBLIC_KEY_PATH="$PUBLIC_KEY"

echo "[entrypoint] Configuration:"
echo "  IDP_BASE_URL  = ${IDP_BASE_URL:-http://localhost:8080}"
echo "  IDP_PORT      = ${IDP_PORT:-8080}"
echo "  DB_PATH       = $DB_PATH"
echo "  PRIVATE_KEY   = $PRIVATE_KEY"

exec "$@"
