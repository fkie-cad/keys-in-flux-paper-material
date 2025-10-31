#!/usr/bin/env bash
###############################################################################
# Start Servers in Simple Mode (No LLDB Monitoring)
# Uses docker-compose.manual.yml to start servers without LLDB auto-attach.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()  { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
info() { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

echo "══════════════════════════════════════════════════════════════"
echo "  Starting Servers (Simple Mode - No LLDB)"
echo "══════════════════════════════════════════════════════════════"
echo ""

info "Stopping any running containers..."
"${COMPOSE[@]}" down 2>/dev/null || true

echo ""
info "Starting servers in simple mode..."
"${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.manual.yml \
  up -d dropbear_server dropbear_server_dbg ssh_client openssh_groundtruth

echo ""
info "Waiting for services to initialize..."
sleep 5

echo ""
log "All servers started (no LLDB):"
echo "  - OpenSSH:       localhost:2222"
echo "  - Dropbear:      localhost:2223"
echo "  - wolfSSH:       localhost:2224"
echo "  - Paramiko:      localhost:2225"
echo "  - Groundtruth:   localhost:2226"
echo "  - Dropbear-Dbg:  localhost:2228"
echo ""
info "Next steps:"
echo "  1. Test connectivity: ./test_basic_connectivity.sh"
echo "  2. Start PCAP: ./start_pcap_capture.sh dropbear"
echo "  3. Attach LLDB: ./attach_lldb_manual.sh dropbear"
echo "  4. Connect: ./connect_with_groundtruth.sh dropbear init"
echo ""
