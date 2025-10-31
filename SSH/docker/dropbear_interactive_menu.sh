#!/usr/bin/env bash
###############################################################################
# Dropbear SSH Key Lifecycle - Interactive Manual Debug Mode
#
# Interactive menu-driven workflow for manual debugging of SSH key lifecycle.
# Provides controls for connection, traffic, rekey, and termination while
# monitoring LLDB events and memory dumps in real-time.
#
# Usage:
#   ./dropbear_interactive_menu.sh
#
# Features:
#   - Auto-detects running server
#   - Launches LLDB in separate terminal (via attach_lldb_terminal.sh)
#   - Manages SSH connections in background
#   - Real-time status monitoring
#   - Menu-driven actions for testing key lifecycle
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

log()   { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
error() { printf "%b✗%b %s\n" "${RED}"   "${NC}" "$*" >&2; }
warn()  { printf "%b!%b %s\n" "${YELLOW}" "${NC}" "$*"; }
info()  { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# ── Configuration ─────────────────────────────────────────────────────────────
STATE_FILE=".ssh_session_state"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' found."
  exit 1
fi

# ── State Management ──────────────────────────────────────────────────────────

init_state() {
  cat > "$STATE_FILE" << EOF
SSH_PID=
SSH_CONTAINER_SESSION_PID=
SERVER=
CONNECTED=false
LLDB_LAUNCHED=false
EOF
}

load_state() {
  if [[ -f "$STATE_FILE" ]]; then
    source "$STATE_FILE"
  else
    init_state
    source "$STATE_FILE"
  fi

  # Ensure variables have defaults
  SSH_PID=${SSH_PID:-}
  SSH_CONTAINER_SESSION_PID=${SSH_CONTAINER_SESSION_PID:-}
  SERVER=${SERVER:-}
  CONNECTED=${CONNECTED:-false}
  LLDB_LAUNCHED=${LLDB_LAUNCHED:-false}
}

save_state() {
  cat > "$STATE_FILE" << EOF
SSH_PID=${SSH_PID:-}
SSH_CONTAINER_SESSION_PID=${SSH_CONTAINER_SESSION_PID:-}
SERVER=${SERVER:-}
CONNECTED=${CONNECTED:-false}
LLDB_LAUNCHED=${LLDB_LAUNCHED:-false}
EOF
}

# ── Server Detection ──────────────────────────────────────────────────────────

detect_running_server() {
  local servers=("dropbear" "openssh" "wolfssh" "paramiko")

  for srv in "${servers[@]}"; do
    if "${COMPOSE[@]}" ps 2>/dev/null | grep -q "${srv}_server.*Up"; then
      echo "$srv"
      return 0
    fi
  done

  return 1
}

# ── Status Queries ────────────────────────────────────────────────────────────

count_keylogs() {
  local server="$1"
  local count=0

  if [[ -f "data/keylogs/ssh_keylog_${server}.log" ]]; then
    count=$(wc -l < "data/keylogs/ssh_keylog_${server}.log" 2>/dev/null || echo "0")
    count=$(echo "$count" | xargs) # trim whitespace
  fi

  echo "${count:-0}"
}

count_dumps() {
  local count=0

  if ls data/dumps/*.dump >/dev/null 2>&1; then
    count=$(ls data/dumps/*.dump 2>/dev/null | wc -l | xargs)
  elif ls data/dumps/*.bin >/dev/null 2>&1; then
    count=$(ls data/dumps/*.bin 2>/dev/null | wc -l | xargs)
  fi

  echo "${count:-0}"
}

count_events() {
  local server="$1"
  local count=0

  if [[ -f "data/lldb_results/events_${server}.jsonl" ]]; then
    count=$(wc -l < "data/lldb_results/events_${server}.jsonl" 2>/dev/null || echo "0")
    count=$(echo "$count" | xargs)
  fi

  echo "${count:-0}"
}

check_lldb_running() {
  local server="$1"
  local lldb_count

  # More robust: use grep without -c, then count with wc -l
  lldb_count=$("${COMPOSE[@]}" exec -T "${server}_server" \
    ps aux 2>/dev/null | grep "[l]ldb" 2>/dev/null | wc -l || echo "0")

  # Trim all whitespace and newlines, take only first line
  lldb_count=$(echo "$lldb_count" | head -1 | tr -d '[:space:]')

  # Ensure it's a valid number, default to 0
  if [[ ! "$lldb_count" =~ ^[0-9]+$ ]]; then
    lldb_count=0
  fi

  if [[ "$lldb_count" -gt 0 ]]; then
    echo "true"
  else
    echo "false"
  fi
}

check_ssh_connection_active() {
  if [[ -n "${SSH_PID:-}" ]] && kill -0 "$SSH_PID" 2>/dev/null; then
    echo "true"
  else
    echo "false"
  fi
}

# ── Display ───────────────────────────────────────────────────────────────────

display_header() {
  clear
  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo "${BOLD}  Dropbear SSH Key Lifecycle - Manual Debug Mode${NC}"
  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo ""
}

display_status() {
  load_state

  # This menu is specifically for Dropbear
  local server="dropbear"
  local lldb_status="✗ Not attached"
  local ssh_status="● Idle"
  local keylog_count=0
  local dump_count=0
  local event_count=0

  # Check LLDB status
  local lldb_running
  lldb_running=$(check_lldb_running "$server")
  if [[ "$lldb_running" == "true" ]]; then
    lldb_status="${GREEN}✓ Attached${NC}"
  else
    lldb_status="${RED}✗ Not attached${NC}"
  fi

  keylog_count=$(count_keylogs "$server")
  event_count=$(count_events "$server")
  dump_count=$(count_dumps)

  # Check SSH connection status
  if [[ "$(check_ssh_connection_active)" == "true" ]]; then
    ssh_status="${GREEN}● Active${NC}"
  else
    ssh_status="${YELLOW}● Idle${NC}"
    CONNECTED=false
    save_state
  fi

  echo "${BOLD}Status:${NC}"
  echo "  Server:         ${server}_server"
  echo "  LLDB:           $lldb_status"
  echo "  SSH Connection: $ssh_status"
  echo "  Keylog entries: $keylog_count"
  echo "  Memory dumps:   $dump_count"
  echo "  LLDB events:    $event_count"
  echo ""
}

display_menu() {
  echo "${BOLD}Actions:${NC}"
  echo "  ${BLUE}[C]${NC} Connect    - Establish SSH connection to Dropbear"
  echo "  ${BLUE}[T]${NC} Traffic    - Send command via SSH (ls, pwd, etc.)"
  echo "  ${BLUE}[R]${NC} Rekey      - Trigger key renegotiation"
  echo "  ${BLUE}[X]${NC} Terminate  - Close SSH connection"
  echo "  ${BLUE}[S]${NC} Status     - Show detailed status"
  echo ""
  echo "${BOLD}Diagnostics:${NC}"
  echo "  ${YELLOW}[D]${NC} Diagnostics - Show processes, connections, debug info"
  echo "  ${YELLOW}[I]${NC} Internal SSH - Connect from inside container"
  echo "  ${YELLOW}[H]${NC} Host SSH    - Connect from M1 host to container"
  echo "  ${YELLOW}[M]${NC} Monitor PIDs - Attach LLDB for fork/thread monitoring"
  echo ""
  echo "${BOLD}LLDB Monitoring:${NC}"
  echo "  ${GREEN}[L]${NC} LLDB       - Launch full LLDB monitoring (with watchpoints)"
  echo "  ${GREEN}[V]${NC} LLDB       - Launch full LLDB investigator"
  echo "  ${GREEN}[N]${NC} LLDB No-WP - Launch LLDB without watchpoints (dumps only)"
  echo ""
  echo "${BOLD}Phase 6C Testing (Persistent State Watchpoints):${NC}"
  echo "  ${CYAN}[P]${NC} Phase 6C-I - Watch state->chacha + IMMEDIATE enable"
  echo "  ${CYAN}[K]${NC} Phase 6C-D - Watch state->chacha + DELAYED enable (1.5s)"
  echo ""
  echo "${BOLD}Container Management:${NC}"
  echo "  ${CYAN}[B]${NC} Rebuild    - Clean rebuild of Dropbear container"
  echo ""
  echo "  ${RED}[Q]${NC} Quit       - Cleanup and exit"
  echo ""
  printf "${BOLD}Choice:${NC} "
}

# ── Actions ───────────────────────────────────────────────────────────────────

action_connect() {
  load_state

  if [[ "$CONNECTED" == "true" ]]; then
    warn "SSH connection already active (PID: $SSH_PID)"
    echo ""
    read -p "Press Enter to continue..." -r
    return
  fi

  # This menu is specifically for Dropbear DBG container
  local server="dropbear"

  info "Establishing SSH connection to ${server}_server_dbg (port 2228)..."
  echo ""

  # Create expect script for background SSH connection
  local expect_script="/tmp/ssh_connect_${server}.exp"
  cat > "$expect_script" << 'EXPECTEOF'
#!/usr/bin/expect -f
set timeout 30
set host [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set pass [lindex $argv 3]

spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port $user@$host
expect {
    "password:" {
        send "$pass\r"
        expect "$ "
        send "echo SSH_SESSION_READY\r"
        interact
    }
    timeout {
        puts "Connection timeout"
        exit 1
    }
}
EXPECTEOF

  chmod +x "$expect_script"

  # Launch SSH in background - connect from HOST to dropbear_server_dbg on port 2228
  # Use sshpass if available, otherwise use expect (macOS compatible)
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p password ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -p 2228 testuser@localhost \
      "echo 'SSH Connected to dropbear_server_dbg'; while true; do sleep 1; done" &
    SSH_PID=$!
  else
    # Fall back to expect for macOS
    warn "sshpass not found, using expect (install: brew install hudochenkov/sshpass/sshpass)"
    expect -c "
      spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2228 testuser@localhost \"echo 'SSH Connected'; while true; do sleep 1; done\"
      expect \"password:\"
      send \"password\r\"
      expect eof
    " &
    SSH_PID=$!
  fi

  CONNECTED=true
  save_state

  sleep 2

  log "SSH connection established (PID: $SSH_PID)"
  echo ""
  info "Connected to: localhost:2228 (dropbear_server_dbg)"
  info "Connection will stay open until terminated with [X]"
  echo ""
  read -p "Press Enter to continue..." -r
}

action_send_traffic() {
  load_state

  if [[ "$CONNECTED" != "true" ]]; then
    warn "No active SSH connection. Use [C] to connect first."
    echo ""
    read -p "Press Enter to continue..." -r
    return
  fi

  # This menu is specifically for Dropbear
  local server="dropbear"

  echo ""
  echo "${BOLD}Send Traffic:${NC}"
  echo "  1) ls -la"
  echo "  2) pwd"
  echo "  3) hostname"
  echo "  4) uname -a"
  echo "  5) Custom command"
  echo ""
  printf "Choice (1-5): "
  read -r choice

  local cmd=""
  case "$choice" in
    1) cmd="ls -la" ;;
    2) cmd="pwd" ;;
    3) cmd="hostname" ;;
    4) cmd="uname -a" ;;
    5)
      echo ""
      printf "Enter command: "
      read -r cmd
      ;;
    *)
      warn "Invalid choice"
      read -p "Press Enter to continue..." -r
      return
      ;;
  esac

  echo ""
  info "Sending command: $cmd"
  echo ""

  # Execute command via new SSH connection (non-interactive) to dropbear_server_dbg
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p password ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -p 2228 testuser@localhost \
      "$cmd" 2>&1
  else
    # Fall back to expect for macOS
    expect -c "
      spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2228 testuser@localhost \"$cmd\"
      expect \"password:\"
      send \"password\r\"
      expect eof
    " 2>&1
  fi

  echo ""
  log "Command executed"
  echo ""
  read -p "Press Enter to continue..." -r
}

action_rekey() {
  load_state

  if [[ "$CONNECTED" != "true" ]]; then
    warn "No active SSH connection. Use [C] to connect first."
    echo ""
    read -p "Press Enter to continue..." -r
    return
  fi

  # This menu is specifically for Dropbear
  local server="dropbear"

  echo ""
  info "Triggering SSH rekey..."
  echo ""
  warn "Note: Automated rekey via escape sequence (~R) requires interactive terminal."
  warn "Alternative: Close and reconnect to trigger new key exchange."
  echo ""

  echo "Options:"
  echo "  1) Reconnect (new connection = new key exchange)"
  echo "  2) Manual (instructions for interactive rekey)"
  echo ""
  printf "Choice (1-2): "
  read -r choice

  case "$choice" in
    1)
      info "Closing current connection and reconnecting..."
      kill "$SSH_PID" 2>/dev/null || true
      CONNECTED=false
      save_state
      sleep 1
      action_connect
      ;;
    2)
      echo ""
      echo "${YELLOW}Manual Rekey Instructions:${NC}"
      echo "  1. Switch to your interactive SSH terminal"
      echo "  2. Press Enter to get a new line"
      echo "  3. Type ~ (tilde)"
      echo "  4. Type R (capital R)"
      echo "  5. You should see: [rekey request sent]"
      echo ""
      read -p "Press Enter to continue..." -r
      ;;
    *)
      warn "Invalid choice"
      read -p "Press Enter to continue..." -r
      ;;
  esac
}

action_terminate() {
  load_state

  if [[ "$CONNECTED" != "true" ]]; then
    warn "No active SSH connection to terminate."
    echo ""
    read -p "Press Enter to continue..." -r
    return
  fi

  echo ""
  info "Terminating SSH connection (PID: $SSH_PID)..."

  if kill "$SSH_PID" 2>/dev/null; then
    log "Connection terminated"
  else
    warn "Process already terminated"
  fi

  CONNECTED=false
  SSH_PID=
  save_state

  echo ""
  read -p "Press Enter to continue..." -r
}

action_detailed_status() {
  load_state

  # This menu is specifically for Dropbear
  local server="dropbear"

  clear
  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo "${BOLD}  Detailed Status${NC}"
  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  echo "${BOLD}Server Information:${NC}"
  echo "  Server: ${server}_server"
  echo ""

  echo "${BOLD}LLDB Status:${NC}"
  local lldb_running
  lldb_running=$(check_lldb_running "$server")
  if [[ "$lldb_running" == "true" ]]; then
    echo "  Status: ${GREEN}Running${NC}"

    # Show LLDB process info
    echo "  Processes:"
    "${COMPOSE[@]}" exec -T "${server}_server" ps aux 2>/dev/null | grep "[l]ldb" | \
      awk '{printf "    PID %-6s  CPU: %s%%  MEM: %s%%\n", $2, $3, $4}' || true
  else
    echo "  Status: ${RED}Not running${NC}"
    echo "  Tip: Press [L] to launch LLDB in separate terminal"
  fi
  echo ""

  echo "${BOLD}File Statistics:${NC}"

  # Keylog
  local keylog_path="data/keylogs/ssh_keylog_${server}.log"
  if [[ -f "$keylog_path" ]]; then
    local keylog_lines
    keylog_lines=$(wc -l < "$keylog_path" | xargs)
    local keylog_size
    keylog_size=$(du -h "$keylog_path" | awk '{print $1}')
    echo "  Keylog:  $keylog_lines entries  ($keylog_size)"
    echo "    Path: $keylog_path"
  else
    echo "  Keylog:  ${YELLOW}Not created yet${NC}"
  fi

  # Events
  local events_path="data/lldb_results/events_${server}.jsonl"
  if [[ -f "$events_path" ]]; then
    local event_lines
    event_lines=$(wc -l < "$events_path" | xargs)
    local event_size
    event_size=$(du -h "$events_path" | awk '{print $1}')
    echo "  Events:  $event_lines entries  ($event_size)"
    echo "    Path: $events_path"

    # Event breakdown
    echo ""
    echo "  Event types:"
    local monitor_start
    monitor_start=$(grep -c '"MONITOR_START"' "$events_path" 2>/dev/null || echo "0")
    local kex_exit
    kex_exit=$(grep -c '"KEX_EXIT"' "$events_path" 2>/dev/null || echo "0")
    local key_extract
    key_extract=$(grep -c '"KEY_EXTRACT"' "$events_path" 2>/dev/null || echo "0")
    local watchpoint
    watchpoint=$(grep -c '"WATCHPOINT"' "$events_path" 2>/dev/null || echo "0")

    printf "    MONITOR_START: %3d\n" "${monitor_start:-0}"
    printf "    KEX_EXIT:      %3d\n" "${kex_exit:-0}"
    printf "    KEY_EXTRACT:   %3d\n" "${key_extract:-0}"
    printf "    WATCHPOINT:    %3d\n" "${watchpoint:-0}"
  else
    echo "  Events:  ${YELLOW}Not created yet${NC}"
  fi

  # Dumps
  echo ""
  local dump_count
  dump_count=$(count_dumps)
  if [[ "${dump_count:-0}" -gt 0 ]]; then
    echo "  Dumps:   $dump_count files"
    echo "    Path: data/dumps/"

    # Show recent dumps
    echo ""
    echo "  Recent dumps:"
    ls -lht data/dumps/*.{dump,bin} 2>/dev/null | head -5 | \
      awk '{printf "    %s %s  %-8s  %s\n", $6, $7, $5, $9}' || true
  else
    echo "  Dumps:   ${YELLOW}None created yet${NC}"
  fi

  echo ""
  echo "${CYAN}────────────────────────────────────────────────────────────────────────${NC}"
  echo ""
  read -p "Press Enter to return to menu..." -r
}

action_launch_lldb() {
  load_state

  echo ""
  info "Launching LLDB in separate terminal (with watchpoints)..."
  echo ""

  # Call the standalone script
  if [[ -f "$SCRIPT_DIR/attach_lldb_terminal.sh" ]]; then
    bash "$SCRIPT_DIR/attach_lldb_terminal.sh" "dropbear"

    LLDB_LAUNCHED=true
    save_state

    echo ""
    log "LLDB launcher executed"
  else
    error "Script not found: attach_lldb_terminal.sh"
    echo ""
    echo "Expected location: $SCRIPT_DIR/attach_lldb_terminal.sh"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}

action_launch_lldb_investigator() {
  load_state

  echo ""
  info "Launching LLDB in separate terminal for investigations..."
  echo ""

  # Call the standalone script
  if [[ -f "$SCRIPT_DIR/attach_lldb_terminal.sh" ]]; then
    bash "$SCRIPT_DIR/attach_lldb_terminal.sh" "dropbear" "investigator"

    LLDB_LAUNCHED=true
    save_state

    echo ""
    log "LLDB launcher executed"
  else
    error "Script not found: attach_lldb_terminal.sh"
    echo ""
    echo "Expected location: $SCRIPT_DIR/attach_lldb_terminal.sh"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}


action_launch_lldb_nowp() {
  load_state

  echo ""
  info "Launching LLDB in separate terminal (without watchpoints)..."
  echo ""
  warn "Watchpoints disabled - memory dumps and key extraction only"
  echo ""

  # Call the standalone script with no-wp parameter
  if [[ -f "$SCRIPT_DIR/attach_lldb_terminal.sh" ]]; then
    bash "$SCRIPT_DIR/attach_lldb_terminal.sh" "dropbear" "no-wp"

    LLDB_LAUNCHED=true
    save_state

    echo ""
    log "LLDB launcher executed (no watchpoints)"
  else
    error "Script not found: attach_lldb_terminal.sh"
    echo ""
    echo "Expected location: $SCRIPT_DIR/attach_lldb_terminal.sh"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}

action_diagnostics() {
  echo ""
  echo "${BOLD}════════════════════════════════════════════════════════════════════════${NC}"
  echo "${BOLD}  System Diagnostics${NC}"
  echo "${BOLD}════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  info "Dropbear Processes:"
  echo ""
  "${COMPOSE[@]}" exec -T dropbear_server_dbg ps aux | grep "[d]ropbear" || echo "  (no processes found)"
  echo ""

  info "Process Tree from PID 1:"
  echo ""
  "${COMPOSE[@]}" exec -T dropbear_server_dbg pstree -p 1 2>/dev/null || \
    "${COMPOSE[@]}" exec -T dropbear_server_dbg ps -ef | grep -E "PID|dropbear"
  echo ""

  info "Network Connections on Port 22:"
  echo ""
  "${COMPOSE[@]}" exec -T dropbear_server_dbg netstat -anp 2>/dev/null | grep ":22 " || \
    "${COMPOSE[@]}" exec -T dropbear_server_dbg ss -anp 2>/dev/null | grep ":22 " || \
    echo "  (netstat/ss not available)"
  echo ""

  info "Data Directory Contents:"
  echo ""
  echo "  Keylogs: $(ls data/keylogs/ 2>/dev/null | wc -l) files"
  echo "  Dumps:   $(ls data/dumps/ 2>/dev/null | wc -l) files"
  echo "  Results: $(ls data/lldb_results/ 2>/dev/null | wc -l) files"
  echo ""

  if [[ -f "data/lldb_results/events_dropbear.jsonl" ]]; then
    local event_count=$(wc -l < data/lldb_results/events_dropbear.jsonl 2>/dev/null || echo "0")
    echo "  LLDB Events: $event_count lines"
  fi
  echo ""

  info "LLDB Process (if running):"
  echo ""
  "${COMPOSE[@]}" exec -T dropbear_server_dbg ps aux | grep "[l]ldb" || echo "  (LLDB not running)"
  echo ""

  echo "${BOLD}════════════════════════════════════════════════════════════════════════${NC}"
  echo ""
  read -p "Press Enter to return to menu..." -r
}

action_internal_ssh() {
  echo ""
  info "Testing SSH connection from INSIDE container (localhost:22)..."
  echo ""

  # Check if sshpass is available in container
  if ! "${COMPOSE[@]}" exec -T dropbear_server_dbg bash -c 'command -v sshpass >/dev/null 2>&1'; then
    warn "sshpass not installed in container"
    echo ""
    echo "Installing sshpass..."
    "${COMPOSE[@]}" exec -T dropbear_server_dbg bash -c 'apt-get update -qq && apt-get install -y -qq sshpass' 2>&1 | grep -v "debconf"
    echo ""
  fi

  echo "${BLUE}Command:${NC}"
  echo "  sshpass -p password ssh -v -o StrictHostKeyChecking=no testuser@localhost 'hostname; pwd; whoami'"
  echo ""

  info "Connecting..."
  echo ""

  "${COMPOSE[@]}" exec -T dropbear_server_dbg bash -c '
    sshpass -p password ssh \
      -v \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=5 \
      testuser@localhost "hostname; pwd; whoami" 2>&1
  '

  local exit_code=$?
  echo ""

  if [[ $exit_code -eq 0 ]]; then
    log "Internal SSH connection successful"
  else
    error "Internal SSH connection failed (exit code: $exit_code)"
  fi

  echo ""
  info "Check diagnostics [D] to see if Dropbear forked"
  echo ""
  read -p "Press Enter to return to menu..." -r
}

action_host_ssh() {
  echo ""
  info "Testing SSH connection from HOST (M1) to container (port 2228)..."
  echo ""

  # Check if sshpass is available on host
  if ! command -v sshpass >/dev/null 2>&1; then
    warn "sshpass not installed on host"
    echo ""
    echo "Install with: brew install hudochenkov/sshpass/sshpass"
    echo ""
    echo "Trying without sshpass (you'll need to enter password)..."
    echo ""

    echo "${BLUE}Command:${NC}"
    echo "  ssh -v -p 2228 -o StrictHostKeyChecking=no testuser@localhost 'hostname; pwd; whoami'"
    echo ""

    ssh -v \
      -p 2228 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      testuser@localhost "hostname; pwd; whoami" 2>&1

  else
    echo "${BLUE}Command:${NC}"
    echo "  sshpass -p password ssh -v -p 2228 testuser@localhost 'hostname; pwd; whoami'"
    echo ""

    sshpass -p password ssh \
      -v \
      -p 2228 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      testuser@localhost "hostname; pwd; whoami" 2>&1
  fi

  local exit_code=$?
  echo ""

  if [[ $exit_code -eq 0 ]]; then
    log "Host SSH connection successful"
  else
    error "Host SSH connection failed (exit code: $exit_code)"
  fi

  echo ""
  info "Check diagnostics [D] to see if Dropbear forked"
  echo ""
  read -p "Press Enter to return to menu..." -r
}

action_monitor_pids() {
  echo ""
  info "Launching simple PID/fork monitor with LLDB..."
  echo ""

  warn "This attaches a basic LLDB session that only monitors process events"
  echo "No breakpoints, just prints when processes fork or threads spawn"
  echo ""

  # Create simple monitoring script
  local monitor_script="/tmp/lldb_monitor_pids.py"

  cat > "$monitor_script" << 'MONITOR_EOF'
import lldb
import time

def monitor_process_events(debugger, command, result, internal_dict):
    """Simple process event monitor"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    if not process or not process.IsValid():
        print("[MONITOR] No valid process attached")
        return

    print("=" * 72)
    print("  PID/Fork Monitor Active")
    print("=" * 72)
    print(f"Attached to PID: {process.GetProcessID()}")
    print("Monitoring for:")
    print("  - Fork events")
    print("  - Thread creation")
    print("  - Process state changes")
    print("=" * 72)
    print()
    print("Press Ctrl+C to stop monitoring")
    print()

    listener = lldb.SBListener("ProcessMonitor")
    process.GetBroadcaster().AddListener(listener,
        lldb.SBProcess.eBroadcastBitStateChanged)

    try:
        while True:
            event = lldb.SBEvent()
            if listener.WaitForEvent(1, event):
                if lldb.SBProcess.EventIsProcessEvent(event):
                    state = lldb.SBProcess.GetStateFromEvent(event)
                    proc = lldb.SBProcess.GetProcessFromEvent(event)

                    print(f"[{time.strftime('%H:%M:%S')}] Process event: ", end="")

                    if state == lldb.eStateRunning:
                        print(f"RUNNING (PID: {proc.GetProcessID()})")
                    elif state == lldb.eStateStopped:
                        print(f"STOPPED (PID: {proc.GetProcessID()})")
                        thread = proc.GetSelectedThread()
                        if thread:
                            stop_reason = thread.GetStopReason()
                            if stop_reason == lldb.eStopReasonFork:
                                print(f"  → FORK DETECTED! New child process created")
                            else:
                                print(f"  → Stop reason: {stop_reason}")

                        # Show thread count
                        num_threads = proc.GetNumThreads()
                        print(f"  → Threads: {num_threads}")

                        # Auto-continue
                        proc.Continue()
                    elif state == lldb.eStateExited:
                        print(f"EXITED")
                        break
    except KeyboardInterrupt:
        print("\n[MONITOR] Stopping...")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_monitor_pids.monitor_process_events monitor_pids')
MONITOR_EOF

  # Copy to container
  cat "$monitor_script" | "${COMPOSE[@]}" exec -T dropbear_server_dbg bash -c "cat > /tmp/lldb_monitor_pids.py"

  # Get Dropbear parent PID
  local parent_pid=$("${COMPOSE[@]}" exec -T dropbear_server_dbg pgrep -x dropbear | head -1)

  echo "Parent Dropbear PID: $parent_pid"
  echo ""
  info "Attaching LLDB with PID monitor..."
  echo ""

  # Launch LLDB with monitor
  "${COMPOSE[@]}" exec dropbear_server_dbg bash << MONITOR_LLDB
lldb -p $parent_pid \
     -o "settings set target.process.follow-fork-mode child" \
     -o "command script import /tmp/lldb_monitor_pids.py" \
     -o "monitor_pids" \
     -o "continue"
MONITOR_LLDB

  echo ""
  log "PID monitor session ended"
  echo ""
  read -p "Press Enter to return to menu..." -r
}

action_phase6c_immediate() {
  load_state

  echo ""
  info "Launching Phase 6C-Immediate: Persistent State + Immediate Enable"
  echo ""
  warn "This is a research test for ARM64 watchpoint trace mode investigation"
  echo ""
  echo "What this does:"
  echo "  ✓ Watches x5 (state->chacha) - PERSISTENT heap storage"
  echo "  ✓ Register-based extraction (x2, x5 read at entry)"
  echo "  ✓ IMMEDIATE watchpoint enable after key copied to state"
  echo ""
  echo "Expected Result:"
  echo "  ❌ Trace mode (11+ trace hits)"
  echo "  → Proves immediate enable causes issue even with correct location"
  echo ""
  echo "Comparison to Phase 6A:"
  echo "  6A: Watched stack (x2) = temporary → trace mode"
  echo "  6C-I: Watches heap (state->chacha) = persistent → still trace mode!"
  echo ""
  read -p "Press Enter to launch Phase 6C-Immediate..." -r

  # Call the standalone script with phase6c-immediate flag
  if [[ -f "$SCRIPT_DIR/attach_lldb_terminal.sh" ]]; then
    bash "$SCRIPT_DIR/attach_lldb_terminal.sh" "dropbear" "phase6c-immediate"

    LLDB_LAUNCHED=true
    save_state

    echo ""
    log "Phase 6C-Immediate LLDB launched"
    echo ""
    info "After connecting SSH [C], check terminal for trace mode messages"
    echo ""
    info "Results will be in:"
    echo "  - data/lldb_results/lldb_test_state_immediate_output.log"
  else
    error "Script not found: attach_lldb_terminal.sh"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}

action_phase6c_delayed() {
  load_state

  echo ""
  info "Launching Phase 6C-Delayed: Persistent State + 1.5s Delayed Enable"
  echo ""
  warn "This is a research test for ARM64 watchpoint trace mode investigation"
  echo ""
  echo "What this does:"
  echo "  ✓ Watches x5 (state->chacha) - PERSISTENT heap storage"
  echo "  ✓ Register-based extraction (x2, x5 read at entry)"
  echo "  ✓ Creates watchpoint DISABLED"
  echo "  ✓ Waits 1.5 seconds for memory stabilization"
  echo "  ✓ ENABLES watchpoint after delay"
  echo ""
  echo "Expected Result:"
  echo "  ✅ 0 trace hits (timing delay prevents trace mode)"
  echo "  → Proves delay is critical for ARM64 watchpoint stability"
  echo ""
  echo "⚠️  IMPORTANT: Keep SSH connection alive >2 seconds!"
  echo "    Use [C] to connect, then wait before sending commands"
  echo ""
  read -p "Press Enter to launch Phase 6C-Delayed..." -r

  # Call the standalone script with phase6c-delayed flag
  if [[ -f "$SCRIPT_DIR/attach_lldb_terminal.sh" ]]; then
    bash "$SCRIPT_DIR/attach_lldb_terminal.sh" "dropbear" "phase6c-delayed"

    LLDB_LAUNCHED=true
    save_state

    echo ""
    log "Phase 6C-Delayed LLDB launched"
    echo ""
    warn "Remember: Keep SSH connection open >2 seconds for delay to complete!"
    echo ""
    info "Results will be in:"
    echo "  - data/lldb_results/lldb_test_state_delayed_output.log"
  else
    error "Script not found: attach_lldb_terminal.sh"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}

action_rebuild() {
  load_state

  echo ""
  warn "This will completely rebuild the Dropbear container from scratch"
  echo ""
  echo "Steps:"
  echo "  1. Remove existing Dropbear container"
  echo "  2. Rebuild container image with latest changes"
  echo "  3. Start fresh container with manual configuration"
  echo ""
  printf "Continue with rebuild? [y/N]: "
  read -r confirm

  confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')

  if [[ "$confirm" != "y" ]] && [[ "$confirm" != "yes" ]]; then
    warn "Rebuild cancelled"
    echo ""
    read -p "Press Enter to continue..." -r
    return
  fi

  # Terminate SSH connection if active
  if [[ "$CONNECTED" == "true" ]] && [[ -n "${SSH_PID:-}" ]]; then
    info "Terminating SSH connection..."
    kill "$SSH_PID" 2>/dev/null || true
    CONNECTED=false
    SSH_PID=
    save_state
  fi

  echo ""
  info "Step 1: Removing existing container..."
  "${COMPOSE[@]}" rm -sf dropbear_server_dbg 2>&1 | grep -v "^$" || true

  echo ""
  info "Step 2: Building fresh container image..."
  echo ""
  "${COMPOSE[@]}" build dropbear_server_dbg

  echo ""
  info "Step 3: Starting container with manual configuration..."
  echo ""
  "${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.manual.yml up -d dropbear_server_dbg --force-recreate

  echo ""
  info "Waiting for container to be ready..."
  sleep 3

  # Verify it's running
  if check_dropbear_running; then
    echo ""
    log "✓ Dropbear container rebuilt and running successfully"
    echo ""
    info "Container is ready for LLDB attachment and testing"
  else
    echo ""
    error "✗ Container rebuild completed but Dropbear not running"
    echo ""
    echo "Check logs with: docker compose logs dropbear_server_dbg"
  fi

  echo ""
  read -p "Press Enter to continue..." -r
}

action_quit() {
  load_state

  echo ""
  info "Cleaning up..."

  # Terminate SSH connection if active
  if [[ "$CONNECTED" == "true" ]] && [[ -n "${SSH_PID:-}" ]]; then
    info "Terminating SSH connection..."
    kill "$SSH_PID" 2>/dev/null || true
  fi

  # Remove state file
  rm -f "$STATE_FILE"

  echo ""
  log "Cleanup complete"
  echo ""

  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo "${BOLD}  Session Summary${NC}"
  echo "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
  echo ""

  # This menu is specifically for Dropbear
  local server="dropbear"

  echo "Results available in:"
  echo "  - Keys:   data/keylogs/ssh_keylog_${server}.log"
  echo "  - Events: data/lldb_results/events_${server}.jsonl"
  echo "  - Dumps:  data/dumps/"
  echo ""
  echo "To analyze results:"
  echo "  ./analyze_dropbear_experiment.sh data/"

  echo ""
  info "To stop containers:"
  echo "  docker compose down"
  echo ""
}

# ── Main Loop ─────────────────────────────────────────────────────────────────

start_dropbear_server_dbg() {
  echo ""
  info "Starting Dropbear server (without LLDB)..."
  echo ""

  # Stop any existing containers first
  "${COMPOSE[@]}" down 2>/dev/null || true

  # Start dropbear_server_dbg with manual override (no auto-LLDB)
  "${COMPOSE[@]}" -f docker-compose.yml -f docker-compose.manual.yml \
    up -d dropbear_server_dbg openssh_groundtruth 2>&1

  # Wait for startup
  sleep 3

  # Verify it's running
  if "${COMPOSE[@]}" ps 2>/dev/null | grep -q "dropbear_server_dbg.*Up"; then
    log "Dropbear server started successfully"
    echo ""
    return 0
  else
    error "Failed to start Dropbear server"
    echo ""
    echo "Check logs with: docker compose logs dropbear_server_dbg"
    return 1
  fi
}

check_dropbear_running() {
  # Check both container status AND dropbear process inside container

  # First check if container is up
  # Note: Capture output first to avoid issues with IFS and piping
  local ps_output=$("${COMPOSE[@]}" ps 2>&1)
  if ! echo "$ps_output" | grep -q "dropbear_server_dbg.*Up"; then
    return 1
  fi

  # Then check if dropbear process is actually running inside the container
  if ! "${COMPOSE[@]}" exec -T dropbear_server_dbg pgrep -x dropbear >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

main() {
  # Change to script directory (where docker-compose.yml is located)
  cd "$SCRIPT_DIR" || {
    error "Failed to change to script directory: $SCRIPT_DIR"
    exit 1
  }

  # Initialize state if needed
  if [[ ! -f "$STATE_FILE" ]]; then
    init_state
  fi

  # Load existing state
  load_state

  # This script is specifically for Dropbear
  SERVER="dropbear"

  # Check if Dropbear server is running
  if ! check_dropbear_running; then
    echo ""
    warn "Dropbear server is not running"
    echo ""
    echo "This interactive menu requires dropbear_server_dbg to be running."
    echo ""
    printf "Would you like to start it now? [Y/n]: "
    read -r response

    # Convert to lowercase
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    if [[ -z "$response" ]] || [[ "$response" == "y" ]] || [[ "$response" == "yes" ]]; then
      if ! start_dropbear_server_dbg; then
        exit 1
      fi
    else
      echo ""
      info "To start manually:"
      echo "  ./start_servers_no_lldb.sh"
      echo ""
      exit 0
    fi
  fi

  # Verify Dropbear is actually running
  if ! check_dropbear_running; then
    error "Dropbear server is not running"
    echo ""
    echo "Start it with: ./start_servers_no_lldb.sh"
    exit 1
  fi

  # Update server in state
  save_state

  # Main loop
  while true; do
    display_header
    display_status
    display_menu

    read -r choice

    # Convert to lowercase (portable for bash 3.x and 4.x)
    choice=$(echo "$choice" | tr '[:upper:]' '[:lower:]')

    case "$choice" in
      c) action_connect ;;
      t) action_send_traffic ;;
      r) action_rekey ;;
      x) action_terminate ;;
      s) action_detailed_status ;;
      d) action_diagnostics ;;
      i) action_internal_ssh ;;
      h) action_host_ssh ;;
      m) action_monitor_pids ;;
      l) action_launch_lldb ;;
      v) action_launch_lldb_investigator ;;
      n) action_launch_lldb_nowp ;;
      p) action_phase6c_immediate ;;
      k) action_phase6c_delayed ;;
      b) action_rebuild ;;
      q) action_quit; break ;;
      *)
        warn "Invalid choice: $choice"
        sleep 1
        ;;
    esac
  done
}

# ── Entry Point ───────────────────────────────────────────────────────────────

# Trap Ctrl+C to cleanup
trap 'action_quit; exit 130' INT

main "$@"
