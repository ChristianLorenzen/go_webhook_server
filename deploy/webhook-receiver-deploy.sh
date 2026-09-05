#!/usr/bin/env bash
set -euo pipefail

# Privileged half of the CI deploy — install once on the webhook VM as
#   /usr/local/sbin/webhook-receiver-deploy   (root-owned, chmod 0755)
#
# CI scp's the freshly built binary to $STAGED, then runs exactly:
#   sudo /usr/local/sbin/webhook-receiver-deploy
#
# Keeping the root logic here (rather than as inline ssh commands) means the deploy
# user needs ONE NOPASSWD sudo entry for this single script, instead of blanket rights
# to systemctl/install — CI cannot run arbitrary root commands on the VM.
#
# Rolls back to the previous binary automatically if the health check fails.

SERVICE="webhook-receiver"
STAGED="/tmp/webhook-receiver-new"
DEST="/usr/local/bin/webhook-receiver"
PREV="/usr/local/bin/webhook-receiver.prev"
HEALTH_URL="http://localhost:8080/health"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-45}"   # seconds to wait for /health after start

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
fail() { echo "[$(date '+%H:%M:%S')] ✗ $*" >&2; exit 1; }

[[ -f "$STAGED" ]] || fail "no staged binary at $STAGED"
[[ -s "$STAGED" ]] || fail "staged binary is empty"
# Sanity-check ELF magic so a truncated/garbage upload never replaces a working service.
[[ "$(head -c4 "$STAGED" | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]] \
    || fail "staged file is not an ELF binary"

if [[ -f "$DEST" ]]; then
    log "Backing up current binary → $PREV"
    cp -a "$DEST" "$PREV"
fi

log "Stopping $SERVICE..."
systemctl stop "$SERVICE" || true

log "Installing new binary..."
install -m 0755 -o root -g root "$STAGED" "$DEST"
rm -f "$STAGED"

log "Starting $SERVICE..."
systemctl start "$SERVICE"

# Poll rather than sleep-once: startup dials RabbitMQ and fetches the Cloudflare IP
# list (blocking, up to 15s) BEFORE the HTTP listener binds, so /health can legitimately
# take several seconds. Bail out early if the process dies instead of waiting it out.
log "Waiting for $SERVICE to become healthy (up to ${HEALTH_TIMEOUT}s)..."
healthy=false
for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
    if curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
        healthy=true
        break
    fi
    if ! systemctl is-active --quiet "$SERVICE"; then
        log "$SERVICE exited during startup"
        break
    fi
    sleep 1
done

if [[ "$healthy" != "true" ]]; then
    log "Health check FAILED — rolling back"
    systemctl stop "$SERVICE" || true
    if [[ -f "$PREV" ]]; then
        install -m 0755 -o root -g root "$PREV" "$DEST"
        systemctl start "$SERVICE" || true
        log "Restored previous binary"
    fi
    journalctl -u "$SERVICE" -n 50 --no-pager || true
    fail "deploy failed health check; previous version restored"
fi

log "✓ Deploy complete — $SERVICE healthy"
systemctl status "$SERVICE" --no-pager | head -5
