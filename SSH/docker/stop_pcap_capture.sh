#!/usr/bin/env bash
###############################################################################
# Stop PCAP Capture
# Stops tcpdump running in the ssh_client container.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()   { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
error() { printf "%b✗%b %s\n" "${RED}"   "${NC}" "$*" >&2; }
info()  { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' found."
  exit 1
fi

echo "══════════════════════════════════════════════════════════════"
info "Stopping PCAP capture"
echo "══════════════════════════════════════════════════════════════"
echo ""

# Stop tcpdump
if "${COMPOSE[@]}" exec -T ssh_client pgrep tcpdump >/dev/null 2>&1; then
  "${COMPOSE[@]}" exec -T ssh_client pkill tcpdump || true
  sleep 1
  log "Capture stopped"
else
  info "No tcpdump process found (already stopped)"
fi

echo ""
info "Captured files:"
"${COMPOSE[@]}" exec -T ssh_client ls -lh /data/captures/ 2>/dev/null | tail -n +2 || info "No captures found"
echo ""
echo "Copy to host with:"
echo "  docker cp \$(${COMPOSE[*]} ps -q ssh_client):/data/captures/FILENAME.pcap ./analysis/"
echo ""
