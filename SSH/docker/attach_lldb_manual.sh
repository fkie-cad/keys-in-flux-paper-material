#!/usr/bin/env bash
###############################################################################
# Manually Attach LLDB to Running SSH Server
# Interactive LLDB attachment for debugging SSH key lifecycle.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()   { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
error() { printf "%b✗%b %s\n" "${RED}"   "${NC}" "$*" >&2; }
warn()  { printf "%b!%b %s\n" "${YELLOW}" "${NC}" "$*"; }
info()  { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# ── Config ───────────────────────────────────────────────────────────────────
SERVER="${1:-dropbear}"

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
echo "  Manual LLDB Attach for ${SERVER}"
echo "══════════════════════════════════════════════════════════════"
echo ""

# Verify server is running
if ! "${COMPOSE[@]}" ps | grep -q "${SERVER}_server.*Up"; then
  error "${SERVER}_server is not running"
  echo "Start it with: ./start_servers_no_lldb.sh"
  exit 1
fi

log "Server ${SERVER}_server is running"
echo ""

# Get PID
info "Finding ${SERVER} process..."
PID=$("${COMPOSE[@]}" exec -T "${SERVER}_server" pgrep -f "dropbear|wolfssh|sshd" | head -1 || true)

if [[ -z "${PID}" ]]; then
  error "Could not find ${SERVER} process"
  exit 1
fi

log "Found ${SERVER} process with PID: ${PID}"
echo ""

# Show LLDB instructions
echo "LLDB will now attach. In the LLDB prompt, run:"
echo ""
printf "  ${BLUE}(lldb)${NC} process attach --pid ${PID}\n"
printf "  ${BLUE}(lldb)${NC} settings set target.process.follow-fork-mode parent\n"
printf "  ${BLUE}(lldb)${NC} command script import /opt/lldb/ssh_monitor.py\n"
printf "  ${BLUE}(lldb)${NC} command script import /opt/lldb/${SERVER}_callbacks.py\n"
printf "  ${BLUE}(lldb)${NC} continue\n"
echo ""
info "Then make SSH connections to trigger breakpoints."
warn "To detach: Ctrl+C, then type 'detach' and 'quit'"
echo ""
read -p "Press Enter to start LLDB..." -r

# Launch LLDB interactively
"${COMPOSE[@]}" exec -it "${SERVER}_server" bash -c "
export LLDB_KEYLOG=/data/keylogs/ssh_keylog_${SERVER}.log
export LLDB_TIMING_CSV=/data/lldb_results/timing_${SERVER}.csv
export LLDB_EVENTS_LOG=/data/lldb_results/events_${SERVER}.log
export SSH_SERVER_TYPE=${SERVER}
export LLDB_RESULTS_DIR=/data/lldb_results
export LLDB_DUMPS_DIR=/data/dumps

lldb
"

echo ""
log "LLDB session ended."
echo ""
info "Check results:"
echo "  - Keys:   ${COMPOSE[*]} exec ${SERVER}_server cat /data/keylogs/ssh_keylog_${SERVER}.log"
echo "  - Timing: ${COMPOSE[*]} exec ${SERVER}_server cat /data/lldb_results/timing_${SERVER}.csv"
echo "  - Events: ${COMPOSE[*]} exec ${SERVER}_server cat /data/lldb_results/events_${SERVER}.log"
echo ""
