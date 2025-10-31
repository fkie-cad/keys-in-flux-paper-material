#!/usr/bin/env bash
###############################################################################
# Wait for Dropbear Fork and Attach LLDB to Child
#
# This script solves the LLDB follow-fork-mode issue on ARM64 by:
# 1. Waiting for you to connect SSH (which triggers fork)
# 2. Detecting the child process immediately
# 3. Attaching LLDB to the child FAST (before KEX completes)
#
# Usage:
#   Terminal 1: ./wait_and_attach_child.sh [no-wp]
#   Terminal 2: Use interactive menu to press [C] connect
#
###############################################################################

set -Eeuo pipefail

# Colors
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()   { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
error() { printf "%b✗%b %s\n" "${RED}"   "${NC}" "$*" >&2; }
warn()  { printf "%b!%b %s\n" "${YELLOW}" "${NC}" "$*"; }
info()  { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

NO_WATCHPOINTS="${1:-}"

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
else
  COMPOSE=(docker-compose)
fi

echo "════════════════════════════════════════════════════════════════════════"
echo "  Waiting for Dropbear Child Process..."
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Watchpoint mode
enable_wp="true"
if [[ "$NO_WATCHPOINTS" == "no-wp" ]]; then
  enable_wp="false"
  info "Watchpoints DISABLED"
fi

# Get parent Dropbear PID
PARENT_PID=$("${COMPOSE[@]}" exec -T dropbear_server pgrep -x dropbear | head -1)
log "Parent Dropbear PID: $PARENT_PID"

echo ""
warn "NOW CONNECT SSH FROM ANOTHER TERMINAL!"
echo ""
echo "In the interactive menu, press [C] to connect"
echo "This script will detect the fork and attach LLDB immediately..."
echo ""

# Wait for child process to appear
while true; do
  # Find Dropbear children (not the parent)
  CHILD_PID=$("${COMPOSE[@]}" exec -T dropbear_server bash -c "pgrep dropbear | grep -v ^${PARENT_PID}$ | head -1" 2>/dev/null || echo "")

  if [[ -n "$CHILD_PID" ]]; then
    echo ""
    log "CHILD DETECTED! PID: $CHILD_PID"
    break
  fi

  printf "\r  Waiting for fork... (parent: $PARENT_PID)  "
  sleep 0.2
done

# Attach LLDB immediately
echo ""
info "Attaching LLDB to child PID $CHILD_PID..."
echo ""

# Create inline LLDB commands
"${COMPOSE[@]}" exec dropbear_server bash << ATTACH_EOF
export LLDB_KEYLOG=/data/keylogs/ssh_keylog_dropbear.log
export LLDB_TIMING_CSV=/data/lldb_results/timing_dropbear.csv
export LLDB_EVENTS_LOG=/data/lldb_results/events_dropbear.log
export LLDB_EVENTS_JSONL=/data/lldb_results/events_dropbear.jsonl
export SSH_SERVER_TYPE=dropbear
export LLDB_RESULTS_DIR=/data/lldb_results
export LLDB_DUMPS_DIR=/data/dumps
export LLDB_ENABLE_WATCHPOINTS=$enable_wp

echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB Attaching to Child Process $CHILD_PID"
echo "════════════════════════════════════════════════════════════════════════"

lldb -o "process attach --pid $CHILD_PID" \\
     -o "command script import /opt/lldb/ssh_monitor.py" \\
     -o "command script import /opt/lldb/dropbear_callbacks.py" \\
     -o "script print('\\n[CHILD_ATTACH] Attached to child PID $CHILD_PID')" \\
     -o "script print('[CHILD_ATTACH] KEX should happen shortly...')" \\
     -o "script print('[CHILD_ATTACH] Breakpoints are active\\n')" \\
     -o "continue"

echo ""
echo "LLDB session ended"
ATTACH_EOF

log "Done!"
