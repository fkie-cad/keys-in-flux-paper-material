#!/usr/bin/env bash
###############################################################################
# Start PCAP Capture for SSH Traffic
# Starts tcpdump in the ssh_client container to capture network traffic.
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

# ── Config ───────────────────────────────────────────────────────────────────
SERVER="${1:-dropbear}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="${SERVER}_${TIMESTAMP}.pcap"

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' found."
  exit 1
fi

# Determine port based on server
case "${SERVER}" in
  dropbear)
    PORT=2223
    ;;
  wolfssh)
    PORT=2224
    ;;
  openssh)
    PORT=2222
    ;;
  *)
    error "Unknown server: ${SERVER}"
    echo "Usage: $0 {dropbear|wolfssh|openssh}"
    exit 1
    ;;
esac

echo "══════════════════════════════════════════════════════════════"
info "Starting PCAP capture for ${SERVER} on port ${PORT}"
echo "══════════════════════════════════════════════════════════════"
echo ""
info "Output file: /data/captures/${PCAP_FILE}"
echo ""

# Start tcpdump in background (-d flag)
"${COMPOSE[@]}" exec -d ssh_client \
  tcpdump -i any -w "/data/captures/${PCAP_FILE}" \
  "host ${SERVER}_server and port ${PORT}" 2>/dev/null

sleep 2

# Verify it's running
if "${COMPOSE[@]}" exec -T ssh_client pgrep tcpdump >/dev/null 2>&1; then
  log "Capture started successfully"
  echo ""
  info "Stop with: ${COMPOSE[*]} exec ssh_client pkill tcpdump"
  info "Or use: ./stop_pcap_capture.sh"
  echo ""
  info "File will be saved to: data/captures/${PCAP_FILE}"
  echo ""
else
  error "Failed to start capture"
  exit 1
fi
