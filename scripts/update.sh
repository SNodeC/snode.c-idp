#!/bin/bash
# =============================================================================
# SNode.C IdP — Auto-Update Script
# Called by cron: pulls latest from GitHub, rebuilds if changed, restarts.
# Log: /var/log/auth-idp/update.log
# =============================================================================
set -euo pipefail

APP_DIR="/opt/apps/auth"
LOG_DIR="/var/log/auth-idp"
LOG_FILE="$LOG_DIR/update.log"
BACKUP_DIR="/opt/apps/backups/auth-idp"
COMPOSE="docker compose"
SERVICE="auth-idp"
MAX_LOG_LINES=2000

mkdir -p "$LOG_DIR" "$BACKUP_DIR"

# ── Rotate log if too large ───────────────────────────────────────────────────
if [ -f "$LOG_FILE" ] && [ "$(wc -l < "$LOG_FILE")" -gt "$MAX_LOG_LINES" ]; then
    tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "=== Auth IdP Update Check ==="
cd "$APP_DIR"

# ── Check for upstream changes ────────────────────────────────────────────────
git fetch origin main 2>&1 | tee -a "$LOG_FILE" || { log "ERROR: git fetch failed"; exit 1; }

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    log "No changes detected (commit: ${LOCAL:0:8}) — skipping rebuild."
    exit 0
fi

log "New commits available: ${LOCAL:0:8} → ${REMOTE:0:8}"
log "Changes:"
git log --oneline "${LOCAL}..${REMOTE}" | tee -a "$LOG_FILE"

# ── Backup current DB before update ──────────────────────────────────────────
log "Creating backup before update..."
BACKUP_TS=$(date '+%Y%m%d_%H%M%S')
BACKUP_PATH="$BACKUP_DIR/auth_db_pre_update_${BACKUP_TS}"
mkdir -p "$BACKUP_PATH"

# Copy DB from Docker volume
if docker volume ls -q | grep -q "auth_auth_data"; then
    docker run --rm \
        -v auth_auth_data:/data \
        -v "$BACKUP_PATH":/backup \
        debian:bookworm-slim \
        sh -c "cp -r /data/* /backup/ 2>/dev/null || true" \
        2>>"$LOG_FILE" && log "Database backed up to $BACKUP_PATH"
else
    log "WARNING: No data volume found, skipping DB backup."
fi

# ── Pull + Rebuild ────────────────────────────────────────────────────────────
log "Pulling latest source..."
git pull origin main 2>&1 | tee -a "$LOG_FILE"

log "Building new Docker image..."
if $COMPOSE build 2>&1 | tee -a "$LOG_FILE"; then
    log "Build successful. Restarting service..."
    $COMPOSE up -d --force-recreate 2>&1 | tee -a "$LOG_FILE"
    log "Service restarted. Checking health..."
    sleep 15
    if $COMPOSE exec -T "$SERVICE" /bin/sh /app/healthcheck.sh > /dev/null 2>&1; then
        log "✓ Health check passed. Update complete: ${REMOTE:0:8}"
    else
        log "✗ Health check FAILED after update! Check: docker compose logs $SERVICE"
    fi
else
    log "ERROR: Docker build failed! Rolling back..."
    $COMPOSE up -d 2>&1 | tee -a "$LOG_FILE"
    log "Previous version restored."
    exit 1
fi

log "=== Update done ==="
