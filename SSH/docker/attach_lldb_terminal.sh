#!/usr/bin/env bash
###############################################################################
# Attach LLDB to SSH Server in New Terminal (Auto-Detection)
#
# This script automatically detects which SSH server is running and launches
# LLDB in a new terminal window/pane with all monitoring hooks loaded.
#
# Usage:
#   ./attach_lldb_terminal.sh                           # Auto-detect server (with watchpoints)
#   ./attach_lldb_terminal.sh dropbear                  # Force specific server (with watchpoints)
#   ./attach_lldb_terminal.sh dropbear no-wp            # Disable watchpoints (memory dumps only)
#   ./attach_lldb_terminal.sh dropbear investigator     # Disable watchpoints and only activate certain investigator hooks
#
# Watchpoint modes:
#   - Default: Hardware watchpoints enabled (may pause execution)
#   - no-wp: Watchpoints disabled, memory dumps and key extraction only
#
# Can be used standalone or called from interactive menu.
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
FORCE_SERVER="${1:-}"
NO_WATCHPOINTS="${2:-}"
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

# ── Functions ─────────────────────────────────────────────────────────────────

detect_running_server() {
  # Auto-detect which SSH server is currently running
  local servers=("dropbear" "openssh" "wolfssh" "paramiko")

  for srv in "${servers[@]}"; do
    if "${COMPOSE[@]}" ps 2>/dev/null | grep -q "${srv}_server.*Up"; then
      echo "$srv"
      return 0
    fi
  done

  return 1
}

get_server_process_pattern() {
  local server="$1"
  case "$server" in
    dropbear) echo "dropbear" ;;
    openssh)  echo "sshd" ;;
    wolfssh)  echo "wolfsshd" ;;
    paramiko) echo "python3.*server_keylogger" ;;
    *) echo "" ;;
  esac
}

find_server_pid() {
  local server="$1"
  local pattern
  pattern=$(get_server_process_pattern "$server")

  if [[ -z "$pattern" ]]; then
    return 1
  fi

  # Get PID from container (may return parent listener or child connection handler)
  local pid
  pid=$("${COMPOSE[@]}" exec -T "${server}_server_dbg" \
    pgrep -f "$pattern" | head -1 || true)

  if [[ -n "$pid" ]]; then
    echo "$pid"
    return 0
  fi

  return 1
}

detect_terminal_environment() {
  # Detect terminal multiplexer or graphical terminal
  # Priority: tmux → kitty → gnome-terminal → xterm → macos → fallback

  # Check tmux (highest priority)
  if [[ -n "${TMUX:-}" ]]; then
    echo "tmux"
    return
  fi

  # Check Kitty (only if command exists AND environment detected)
  if [[ -n "${KITTY_WINDOW_ID:-}" ]] || [[ "$TERM" == "xterm-kitty" ]]; then
    if command -v kitty >/dev/null 2>&1; then
      echo "kitty"
      return
    fi
  fi

  # Check gnome-terminal
  if command -v gnome-terminal >/dev/null 2>&1; then
    echo "gnome-terminal"
    return
  fi

  # Check xterm
  if command -v xterm >/dev/null 2>&1; then
    echo "xterm"
    return
  fi

  # Check macOS
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macos"
    return
  fi

  # No suitable terminal found
  echo "none"
}

#dropbear_callbacks_chat.py
#      -o "command script import /opt/lldb/ssh_monitor.py" \\
#      -o "command script import /opt/lldb/${server}_callbacks.py" \\
# -o "command script import /opt/lldb/${server}_callbacks.py"

create_lldb_script() {
  local server="$1"
  local pid="$2"
  local no_watchpoints="$3"

  cat << EOF
#!/bin/bash
# Auto-generated LLDB attachment script for ${server}_server (PID: ${pid})

export LLDB_KEYLOG=/data/keylogs/ssh_keylog_${server}.log
export LLDB_TIMING_CSV=/data/lldb_results/timing_${server}.csv
export LLDB_EVENTS_LOG=/data/lldb_results/events_${server}.log
export LLDB_EVENTS_JSONL=/data/lldb_results/events_${server}.jsonl
export SSH_SERVER_TYPE=${server}
export LLDB_RESULTS_DIR=/data/lldb_results
export LLDB_DUMPS_DIR=/data/dumps
# Map watchpoint mode to true/false for backward compatibility (special modes pass through)
if [[ "${no_watchpoints}" == "no-wp" ]] || [[ "${no_watchpoints}" == "nowp" ]]; then
  export LLDB_ENABLE_WATCHPOINTS=false
elif [[ "${no_watchpoints}" == "phase6c-immediate" ]] || [[ "${no_watchpoints}" == "phase6c-delayed" ]]; then
  export LLDB_ENABLE_WATCHPOINTS=${no_watchpoints}  # Pass through for special modes
else
  export LLDB_ENABLE_WATCHPOINTS=true  # Default: watchpoints enabled
fi

echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB Monitor - ${server}_server (PID: ${pid})"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Watchpoint mode: \$LLDB_ENABLE_WATCHPOINTS"
echo "Attaching LLDB with monitoring hooks..."
echo ""

if [[ "${no_watchpoints}" == "phase6c-immediate" ]]; then
  # Phase 6C-Immediate: Watch persistent state->chacha with immediate enable
  lldb -o "process attach --pid ${pid}" \\
       -o "settings set target.process.follow-fork-mode child" \\
       -o "settings set target.process.stop-on-exec false" \\
       -o "settings set target.detach-on-error false" \\
       -o "command script import /opt/lldb/dropbear_callbacks_state_immediate.py" \\
       -o "dropbear_setup_monitoring" \\
       -o "dropbear_auto_continue" \\
       -o "script print('═' * 70)" \\
       -o "script print('PHASE 6C-IMMEDIATE: Persistent State + Immediate Enable')" \\
       -o "script print('Parent PID: ${pid}')" \\
       -o "script print('')" \\
       -o "script print('Expected: Trace mode (even with correct location)')" \\
       -o "script print('This tests if immediate watchpoint enable causes issues')" \\
       -o "script print('')" \\
       -o "script print('Connect via menu [C] to trigger KEX and watchpoint')" \\
       -o "script print('═' * 70)" \\
       -o "script print('')"
elif [[ "${no_watchpoints}" == "phase6c-delayed" ]]; then
  # Phase 6C-Delayed: Watch persistent state->chacha with 1.5s delay
  lldb -o "process attach --pid ${pid}" \\
       -o "settings set target.process.follow-fork-mode child" \\
       -o "settings set target.process.stop-on-exec false" \\
       -o "settings set target.detach-on-error false" \\
       -o "command script import /opt/lldb/dropbear_callbacks_state_delayed.py" \\
       -o "dropbear_setup_monitoring" \\
       -o "dropbear_auto_continue" \\
       -o "script print('═' * 70)" \\
       -o "script print('PHASE 6C-DELAYED: Persistent State + 1.5s Delay')" \\
       -o "script print('Parent PID: ${pid}')" \\
       -o "script print('')" \\
       -o "script print('Expected: 0 trace hits (delay prevents trace mode)')" \\
       -o "script print('This tests if timing delay resolves the issue')" \\
       -o "script print('')" \\
       -o "script print('Keep SSH connection open >2s after connect!')" \\
       -o "script print('═' * 70)" \\
       -o "script print('')"
else
  # Default: Minimal callbacks
  lldb -o "process attach --pid ${pid}" \\
       -o "settings set target.process.follow-fork-mode child" \\
       -o "settings set target.process.stop-on-exec false" \\
       -o "settings set target.detach-on-error false" \\
       -o "settings show target.process.follow-fork-mode" \\
       -o "command script import /opt/lldb/dropbear_callbacks_minimal.py" \\
       -o "dropbear_setup_monitoring" \\
       -o "dropbear_auto_continue" \\
       -o "script print('Parent PID: ${pid}')" \\
       -o "script print('All breakpoints are set and ready')" \\
       -o "script print('')" \\
       -o "script print('TYPE: continue (or c) to start monitoring')" \\
       -o "script print('THEN: Use interactive menu to press [C] to connect SSH')" \\
       -o "script print('Breakpoints will fire when Dropbear forks and handles connection')" \\
       -o "script print('=' * 72)" \\
       -o "script print('')"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB session ended"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Results available at:"
echo "  - Keys:   /data/keylogs/ssh_keylog_${server}.log"
echo "  - Timing: /data/lldb_results/timing_${server}.csv"
echo "  - Events: /data/lldb_results/events_${server}.jsonl"
echo "  - Dumps:  /data/dumps/"
echo ""

# Keep terminal open
read -p "Press Enter to close this terminal..." -r
EOF
}


create_lldb_investigator_script() {
  local server="$1"
  local pid="$2"
  local no_watchpoints="$3"

  cat << EOF
#!/bin/bash
# Auto-generated LLDB attachment script for ${server}_server (PID: ${pid})

export LLDB_KEYLOG=/data/keylogs/ssh_keylog_${server}.log
export LLDB_TIMING_CSV=/data/lldb_results/timing_${server}.csv
export LLDB_EVENTS_LOG=/data/lldb_results/events_${server}.log
export LLDB_EVENTS_JSONL=/data/lldb_results/events_${server}.jsonl
export SSH_SERVER_TYPE=${server}
export LLDB_RESULTS_DIR=/data/lldb_results
export LLDB_DUMPS_DIR=/data/dumps
export LLDB_ENABLE_WATCHPOINTS=${no_watchpoints}

echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB Monitor - ${server}_server (PID: ${pid})"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Watchpoint mode: LLDB_ENABLE_WATCHPOINTS=${no_watchpoints}"
echo "Attaching LLDB with investigator hooks..."
echo ""

lldb -o "process attach --pid ${pid}" \\
     -o "settings set target.detach-on-error false" \\
     -o "command script import /opt/lldb/dropbear_dbg.py" \
     -o "followfork child" \
     -o "br-fork" \
     -o "waitattach dropbear"

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "  LLDB session ended"
echo "════════════════════════════════════════════════════════════════════════"
echo ""
echo "Results available at:"
echo "  - Keys:   /data/keylogs/ssh_keylog_${server}.log"
echo "  - Timing: /data/lldb_results/timing_${server}.csv"
echo "  - Events: /data/lldb_results/events_${server}.jsonl"
echo "  - Dumps:  /data/dumps/"
echo ""

# Keep terminal open
read -p "Press Enter to close this terminal..." -r
EOF
}

launch_in_terminal() {
  local terminal_type="$1"
  local server="$2"
  local script_path="$3"

  case "$terminal_type" in
    tmux)
      info "Launching LLDB in new tmux pane..."
      tmux split-window -h \
        "${COMPOSE[@]}" exec "${server}_server_dbg" bash "$script_path"
      ;;

    kitty)
      info "Launching LLDB in new Kitty window..."

      # Create wrapper script to execute in Kitty (avoids bash -c escaping issues)
      local kitty_wrapper="/tmp/lldb_kitty_wrapper_${server}.sh"
      cat > "$kitty_wrapper" << WRAPPER_EOF
#!/bin/bash
cd "$(pwd)"
docker compose exec ${server}_server_dbg bash $script_path
WRAPPER_EOF
      chmod +x "$kitty_wrapper"

      # Launch Kitty with wrapper
      if kitty @ ls >/dev/null 2>&1; then
        # Use remote control (new tab in same instance)
        kitty @ launch --type=window --cwd=current bash "$kitty_wrapper" >/dev/null 2>&1 &
      else
        # New Kitty instance (no remote control needed)
        kitty --detach bash "$kitty_wrapper" >/dev/null 2>&1 &
      fi
      ;;

    gnome-terminal)
      info "Launching LLDB in new gnome-terminal window..."
      gnome-terminal -- bash -c \
        "${COMPOSE[*]} exec ${server}_server_dbg bash $script_path" &
      ;;

    xterm)
      info "Launching LLDB in new xterm window..."
      xterm -e \
        "${COMPOSE[*]} exec ${server}_server_dbg bash $script_path" &
      ;;

    macos)
      info "Launching LLDB in new macOS Terminal window..."
      osascript -e "tell application \"Terminal\" to do script \"cd $(pwd) && ${COMPOSE[*]} exec ${server}_server_dbg bash $script_path\""
      ;;

    none)
      warn "No suitable terminal emulator found."
      echo ""
      echo "To attach LLDB manually, open a new terminal and run:"
      echo ""
      echo "  cd $(pwd)"
      echo "  docker compose exec ${server}_server_dbg bash $script_path"
      echo ""
      echo "Or install one of these terminal emulators:"
      echo "  • Kitty:          https://sw.kovidgoyal.net/kitty/"
      echo "  • gnome-terminal: sudo apt install gnome-terminal"
      echo "  • xterm:          sudo apt install xterm"
      echo ""
      return 1
      ;;

    *)
      error "Unknown terminal type: $terminal_type"
      return 1
      ;;
  esac
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  # Change to script directory (where docker-compose.yml is located)
  cd "$SCRIPT_DIR" || {
    error "Failed to change to script directory: $SCRIPT_DIR"
    exit 1
  }

  echo "════════════════════════════════════════════════════════════════════════"
  echo "  LLDB Terminal Launcher - Auto-Detection Mode"
  echo "════════════════════════════════════════════════════════════════════════"
  echo ""

  # Step 1: Determine target server
  local server=""

  if [[ -n "$FORCE_SERVER" ]]; then
    info "Using forced server: $FORCE_SERVER"
    server="$FORCE_SERVER"
  else
    info "Auto-detecting running SSH server..."
    server=$(detect_running_server) || {
      error "No SSH server containers running"
      echo ""
      echo "Start servers with: ./start_servers_no_lldb.sh"
      exit 1
    }
    log "Detected server: ${server}_server"
  fi

  # Verify container is running (more robust check)
  local ps_output
  ps_output=$("${COMPOSE[@]}" ps "${server}_server" 2>/dev/null || echo "")

  if [[ -z "$ps_output" ]] || ! echo "$ps_output" | grep -q "Up"; then
    error "${server}_server is not running"
    echo ""
    echo "Docker Compose status:"
    "${COMPOSE[@]}" ps "${server}_server" 2>&1 || echo "  (container not found)"
    echo ""
    echo "Start it with: ./start_servers_no_lldb.sh"
    exit 1
  fi

  echo ""

  # Step 2: Find server PID
  info "Finding ${server} process..."
  local pid
  pid=$(find_server_pid "$server") || {
    error "Could not find ${server} process in container"
    exit 1
  }
  log "Found PID: $pid"
  echo ""

  # Step 3: Detect terminal environment
  local terminal_env
  terminal_env=$(detect_terminal_environment)
  info "Terminal environment: $terminal_env"
  echo ""

  # Step 4: Create LLDB attach script inside container
  info "Creating LLDB attachment script..."
  local script_path="/tmp/lldb_attach_${server}.sh"
  local script_content

  # Determine watchpoint mode - pass the actual mode string, not just true/false
  if [[ "$NO_WATCHPOINTS" == "no-wp" ]] || [[ "$NO_WATCHPOINTS" == "nowp" ]]; then
    info "Watchpoints DISABLED - memory dumps only"
  fi

  if [[ "$NO_WATCHPOINTS" == "investigator" ]] || [[ "$NO_WATCHPOINTS" == "invest" ]]; then
    info "Watchpoints DISABLED - only investigator hooks active"
  fi

  if [[ "$NO_WATCHPOINTS" == "phase6c-immediate" ]]; then
    info "Phase 6C-Immediate: Persistent state + immediate enable"
  fi

  if [[ "$NO_WATCHPOINTS" == "phase6c-delayed" ]]; then
    info "Phase 6C-Delayed: Persistent state + delayed enable"
  fi

  if [[ "$NO_WATCHPOINTS" == "investigator" ]] || [[ "$NO_WATCHPOINTS" == "invest" ]]; then
    script_content=$(create_lldb_investigator_script "$server" "$pid" "$NO_WATCHPOINTS")
  else
    script_content=$(create_lldb_script "$server" "$pid" "$NO_WATCHPOINTS")
  fi

  # Write script to container
  echo "$script_content" | \
    "${COMPOSE[@]}" exec -T "${server}_server_dbg" \
    bash -c "cat > $script_path && chmod +x $script_path"

  log "Script created: $script_path (inside container)"
  echo ""

  # Step 5: Launch in appropriate terminal
  info "Launching LLDB in new terminal..."
  echo ""

  # Redirect stderr to avoid showing remote control errors
  if launch_in_terminal "$terminal_env" "$server" "$script_path" 2>/tmp/lldb_launch_error.log; then
    echo ""
    log "LLDB launched successfully!"
  else
    # Terminal launch failed (fallback case already showed manual instructions)
    echo ""
    warn "Could not automatically launch terminal."
    echo ""
    info "The LLDB script is ready inside the container at:"
    echo "  $script_path"
    echo ""
    info "Manual attachment instructions displayed above."
    echo ""
    read -p "Press Enter to return to menu..." -r
    exit 0
  fi
  echo ""
  info "Monitoring files:"
  echo "  - Keylog:  data/keylogs/ssh_keylog_${server}.log"
  echo "  - Events:  data/lldb_results/events_${server}.jsonl"
  echo "  - Dumps:   data/dumps/"
  echo ""
  info "To view logs:"
  echo "  tail -f data/lldb_results/events_${server}.log"
  echo ""
  info "To check LLDB status:"
  echo "  docker compose exec ${server}_server_dbg ps aux | grep lldb"
  echo ""
}

# ── Entry Point ───────────────────────────────────────────────────────────────

main "$@"
