#!/usr/bin/env bash
###############################################################################
# Attach LLDB to Child Dropbear Process (Workaround for ARM64 fork-following)
#
# This script works around LLDB's broken follow-fork-mode on ARM64 Linux by:
# 1. Establishing SSH connection first (triggers Dropbear fork)
# 2. Finding the child process PID
# 3. Attaching LLDB to the child (not parent)
# 4. Setting all breakpoints in the child
# 5. Continuing execution (breakpoints will fire!)
#
# Usage:
#   ./attach_lldb_to_child.sh                    # Auto-detect (with watchpoints)
#   ./attach_lldb_to_child.sh no-wp              # Without watchpoints
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

# ── Configuration ─────────────────────────────────────────────────────────────
SERVER="dropbear"
NO_WATCHPOINTS="${1:-}"

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' found."
  exit 1
fi

# ── Main ──────────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB Child Process Attacher - Dropbear"
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Determine watchpoint mode
enable_wp="true"
if [[ "$NO_WATCHPOINTS" == "no-wp" ]] || [[ "$NO_WATCHPOINTS" == "nowp" ]]; then
  enable_wp="false"
  warn "Watchpoints DISABLED - memory dumps only"
fi

# Step 1: Verify Dropbear server is running
if ! "${COMPOSE[@]}" ps 2>/dev/null | grep -q "dropbear_server.*Up"; then
  error "Dropbear server is not running"
  echo ""
  echo "Start it with: ./start_servers_no_lldb.sh"
  exit 1
fi

log "Dropbear server is running"

# Step 2: Check if there's already an SSH connection (child process)
info "Checking for existing child processes..."
existing_children=$("${COMPOSE[@]}" exec -T dropbear_server pgrep -P 1 dropbear 2>/dev/null || echo "")

if [[ -n "$existing_children" ]]; then
  warn "Found existing Dropbear child processes: $existing_children"
  echo ""
  read -p "Kill existing children and start fresh? [Y/n]: " response
  response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

  if [[ -z "$response" ]] || [[ "$response" == "y" ]]; then
    info "Killing existing child processes..."
    "${COMPOSE[@]}" exec -T dropbear_server pkill -P 1 dropbear || true
    sleep 1
    log "Cleaned up existing processes"
  fi
fi

# Step 3: Establish SSH connection in background
echo ""
info "Establishing SSH connection to trigger fork..."
echo ""

# Start SSH connection in background with persistent session
"${COMPOSE[@]}" exec -T dropbear_server bash -c '
  # Start SSH session in background that stays alive
  sshpass -p password ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=5 \
    -p 22 testuser@localhost \
    "sleep 3600" > /dev/null 2>&1 &

  # Give it a moment to fork
  sleep 2

  # Find the child Dropbear process (not parent PID 1)
  pgrep -P 1 dropbear | head -1
' > /tmp/dropbear_child_pid.txt 2>&1 &

SSH_BG_PID=$!

# Wait for child to spawn
sleep 3

# Read the child PID
if [[ ! -f /tmp/dropbear_child_pid.txt ]]; then
  error "Failed to capture child PID"
  exit 1
fi

CHILD_PID=$(cat /tmp/dropbear_child_pid.txt | grep -oE '[0-9]+' | head -1)

if [[ -z "$CHILD_PID" ]]; then
  error "No child Dropbear process found"
  echo ""
  echo "Check if SSH connection succeeded:"
  "${COMPOSE[@]}" exec dropbear_server ps aux | grep dropbear
  exit 1
fi

log "Found child Dropbear process: PID $CHILD_PID"

# Step 4: Create LLDB script to attach to child
echo ""
info "Creating LLDB attachment script for child process..."

LLDB_SCRIPT="/tmp/lldb_attach_child_${CHILD_PID}.sh"

cat > "$LLDB_SCRIPT" << 'LLDB_EOF'
#!/bin/bash
# Auto-generated LLDB script for child Dropbear process

CHILD_PID="__CHILD_PID__"
ENABLE_WP="__ENABLE_WP__"

export LLDB_KEYLOG=/data/keylogs/ssh_keylog_dropbear.log
export LLDB_TIMING_CSV=/data/lldb_results/timing_dropbear.csv
export LLDB_EVENTS_LOG=/data/lldb_results/events_dropbear.log
export LLDB_EVENTS_JSONL=/data/lldb_results/events_dropbear.jsonl
export SSH_SERVER_TYPE=dropbear
export LLDB_RESULTS_DIR=/data/lldb_results
export LLDB_DUMPS_DIR=/data/dumps
export LLDB_ENABLE_WATCHPOINTS=$ENABLE_WP

echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB Monitor - Child Dropbear Process (PID: $CHILD_PID)"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Watchpoints: $ENABLE_WP"
echo "Attaching LLDB to CHILD process (not parent)..."
echo "This works around LLDB's broken follow-fork-mode on ARM64"
echo ""

lldb -o "process attach --pid $CHILD_PID" \
     -o "settings show target.process.follow-fork-mode" \
     -o "command script import /opt/lldb/ssh_monitor.py" \
     -o "command script import /opt/lldb/dropbear_callbacks.py" \
     -o "script print('========== Attached to Child Process ==========')" \
     -o "script print('Child PID: $CHILD_PID')" \
     -o "script print('KEX will happen in THIS process')" \
     -o "script print('Breakpoints should fire shortly...')" \
     -o "script print('===============================================')" \
     -o "continue"

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB session ended"
echo "════════════════════════════════════════════════════════════════════════"

# Keep terminal open
read -p "Press Enter to close..." -r
LLDB_EOF

# Substitute variables
sed -i.bak "s/__CHILD_PID__/$CHILD_PID/g" "$LLDB_SCRIPT"
sed -i.bak "s/__ENABLE_WP__/$enable_wp/g" "$LLDB_SCRIPT"
chmod +x "$LLDB_SCRIPT"

log "Script created: $LLDB_SCRIPT"

# Step 5: Copy script into container and launch LLDB
echo ""
info "Launching LLDB in container..."
echo ""

# Copy script to container
cat "$LLDB_SCRIPT" | "${COMPOSE[@]}" exec -T dropbear_server bash -c "cat > /tmp/lldb_child.sh && chmod +x /tmp/lldb_child.sh"

# Launch in terminal
if [[ -n "${TMUX:-}" ]]; then
  info "Launching in tmux pane..."
  tmux split-window -h "${COMPOSE[*]} exec dropbear_server bash /tmp/lldb_child.sh"
elif [[ -n "${KITTY_WINDOW_ID:-}" ]] && command -v kitty >/dev/null 2>&1; then
  info "Launching in Kitty window..."
  kitty @ launch --type=window bash -c "cd $(pwd) && ${COMPOSE[*]} exec dropbear_server bash /tmp/lldb_child.sh" &
elif [[ "$OSTYPE" == "darwin"* ]]; then
  info "Launching in macOS Terminal..."
  osascript -e "tell application \"Terminal\" to do script \"cd $(pwd) && ${COMPOSE[*]} exec dropbear_server bash /tmp/lldb_child.sh\""
else
  warn "No terminal multiplexer detected"
  echo ""
  echo "Run this command in a separate terminal:"
  echo ""
  echo "  ${COMPOSE[*]} exec dropbear_server bash /tmp/lldb_child.sh"
  echo ""
fi

echo ""
log "LLDB should now be attached to child PID $CHILD_PID"
log "Breakpoints will fire when KEX happens"
echo ""
echo "The SSH connection is already established - KEX may have already happened!"
echo "If so, disconnect and run this script BEFORE connecting SSH next time."
echo ""
