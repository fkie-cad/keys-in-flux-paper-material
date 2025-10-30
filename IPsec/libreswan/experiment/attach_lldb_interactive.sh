#!/usr/bin/env bash
#
# attach_lldb_interactive.sh
#
# Interactive LLDB attachment to pluto process for manual investigation
# Similar to strongswan experiment framework but for libreswan/pluto
#
# Usage:
#   ./attach_lldb_interactive.sh [namespace] [output_dir]
#
# Example:
#   ./attach_lldb_interactive.sh left ./results/manual_test
#   ./attach_lldb_interactive.sh right /tmp/debug_right
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${1:-left}"
OUTPUT_DIR="${2:-${SCRIPT_DIR}/results/manual_lldb_$(date +%Y%m%d_%H%M%S)}"
MONITORING_SCRIPT="${SCRIPT_DIR}/monitoring_ipsec.py"

echo "========================================"
echo "  Interactive LLDB Attachment"
echo "  Libreswan/Pluto Process"
echo "========================================"
echo ""
echo "Namespace: $NS"
echo "Output directory: $OUTPUT_DIR"
echo "Monitoring script: $MONITORING_SCRIPT"
echo ""

# Check if monitoring script exists
if [[ ! -f "$MONITORING_SCRIPT" ]]; then
    echo "[ERROR] Monitoring script not found: $MONITORING_SCRIPT"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Detect pluto binary path
PLUTO_PATH=""
if [[ -x "/usr/local/libexec/ipsec/pluto" ]]; then
    PLUTO_PATH="/usr/local/libexec/ipsec/pluto"
elif [[ -x "/usr/libexec/ipsec/pluto" ]]; then
    PLUTO_PATH="/usr/libexec/ipsec/pluto"
else
    echo "[WARN] Pluto binary not found at standard locations"
    PLUTO_PATH="/usr/local/libexec/ipsec/pluto"  # Will fail later if not found
fi

echo "[*] Pluto binary: $PLUTO_PATH"
echo ""

# Collect PIDs in the namespace
echo "[*] Searching for pluto processes in namespace '$NS'..."
PIDS_RAW="$(sudo ip netns exec "$NS" sh -lc 'pidof pluto || pgrep -x pluto || true' 2>/dev/null || true)"

if [[ -z "${PIDS_RAW// }" ]]; then
    echo "[!] No 'pluto' processes found in netns '$NS'."
    echo ""
    echo "To start a pluto process, run:"
    echo "  cd ${SCRIPT_DIR}/../research_setup"
    echo "  sudo ./net_setup.sh"
    echo "  sudo ./setup_left.sh   # or setup_right.sh"
    echo ""
    echo "Or use the automated experiment:"
    echo "  cd ${SCRIPT_DIR}"
    echo "  sudo ./run_ipsec_experiment.sh --skip-lldb"
    echo "  # Then in another terminal, run this script"
    exit 1
fi

# Normalize into an array
mapfile -t PID_ARR < <(printf '%s\n' $PIDS_RAW | tr ' ' '\n' | sed '/^$/d')

echo ""
echo "Available 'pluto' processes in netns '$NS':"
i=1
for pid in "${PID_ARR[@]}"; do
    # Show process info
    LINE="$(sudo ip netns exec "$NS" sh -lc "ps -o pid=,ppid=,etime=,rss=,cmd= -p $pid | sed -E 's/^ *//'" 2>/dev/null || echo "$pid - <info unavailable>")"
    echo "  $i) $LINE"
    ((i++))
done
echo ""

# Prompt user
read -rp "Select a number [1-${#PID_ARR[@]}] (or 'q' to quit): " choice
if [[ "${choice,,}" == "q" ]]; then
    echo "Aborted."
    exit 0
fi

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#PID_ARR[@]} )); then
    echo "[!] Invalid selection."
    exit 1
fi

PID="${PID_ARR[choice-1]}"

echo ""
echo "========================================"
echo "[*] Attaching LLDB to PID $PID in netns '$NS'"
echo "[*] Output directory: $OUTPUT_DIR"
echo "========================================"
echo ""
echo "LLDB will:"
echo "  1. Import monitoring script: $MONITORING_SCRIPT"
echo "  2. Set up breakpoints (chunk_from_symkey, ikev2_child_sa_keymat, create_symkey)"
echo "  3. Continue the process automatically after setup"
echo "  4. Drop you into interactive LLDB prompt"
echo ""
echo "The monitoring script uses DUAL HOOKS:"
echo "  - Entry callbacks: Capture function arguments"
echo "  - Exit callbacks: Capture return values (chunk_t, PK11SymKey*)"
echo "  - Return address breakpoints for capturing return values"
echo ""
echo "Useful LLDB commands:"
echo "  (lldb) breakpoint list          # Show all breakpoints"
echo "  (lldb) breakpoint disable 1     # Disable breakpoint 1"
echo "  (lldb) breakpoint enable 1      # Enable breakpoint 1"
echo "  (lldb) continue                 # Continue execution"
echo "  (lldb) process status           # Show process state"
echo "  (lldb) thread list              # List all threads"
echo "  (lldb) frame variable           # Show local variables"
echo "  (lldb) bt                       # Show backtrace"
echo "  (lldb) detach                   # Detach from process"
echo "  (lldb) quit                     # Exit LLDB"
echo ""
echo "Note: The process will auto-continue after breakpoint setup."
echo "      Press Ctrl+C during the 3-second countdown to stay at LLDB prompt."
echo ""
read -rp "Press Enter to attach LLDB..."
echo ""

# Set environment variables for monitoring script
export IPSEC_NETNS="$NS"
export IPSEC_OUTPUT_DIR="$OUTPUT_DIR"
export IPSEC_MODE="interactive"  # Interactive mode - no keep-alive loop

# Check if lldb exists in the netns
if ! sudo ip netns exec "$NS" sh -lc 'command -v lldb >/dev/null 2>&1'; then
    echo "[!] lldb not found inside netns '$NS'."
    echo "[*] Trying to attach from host namespace instead..."

    # Attach from host (process is accessible even from outside netns)
    # Command sequence:
    # 1. Import script (registers commands)
    # 2. Attach to process
    # 3. Setup monitoring (sets breakpoints)
    # 4. Auto-continue with 3-second countdown
    echo "[*] Command sequence:"
    echo "    1. Import monitoring script (registers commands)"
    echo "    2. Attach to process $PID"
    echo "    3. Setup monitoring (breakpoints)"
    echo "    4. Auto-continue with 3-second countdown"
    echo ""
    sudo -E lldb \
        -o "command script import '$MONITORING_SCRIPT'" \
        -o "process attach -p $PID" \
        -o "ipsec_setup_monitoring" \
        -o "ipsec_auto_continue 3"
else
    # Attach from within netns
    echo "[*] Command sequence:"
    echo "    1. Import monitoring script (registers commands)"
    echo "    2. Attach to process $PID"
    echo "    3. Setup monitoring (breakpoints)"
    echo "    4. Auto-continue with 3-second countdown"
    echo ""
    sudo ip netns exec "$NS" env \
        IPSEC_NETNS="$IPSEC_NETNS" \
        IPSEC_OUTPUT_DIR="$IPSEC_OUTPUT_DIR" \
        IPSEC_MODE="$IPSEC_MODE" \
        lldb \
            -o "command script import '$MONITORING_SCRIPT'" \
            -o "process attach -p $PID" \
            -o "ipsec_setup_monitoring" \
            -o "ipsec_auto_continue 3"
fi

echo ""
echo "========================================"
echo "[*] LLDB session ended"
echo "[*] Output saved to: $OUTPUT_DIR"
echo "========================================"
echo ""
echo "Check the following files:"
echo "  - $OUTPUT_DIR/events.log           # Human-readable event log"
echo "  - $OUTPUT_DIR/events.jsonl         # Machine-readable events"
echo "  - $OUTPUT_DIR/keys.json            # Extracted IKE/ESP keys"
echo "  - $OUTPUT_DIR/dump_*.bin           # Memory dumps at each stage"
echo "  - $OUTPUT_DIR/lldb_callbacks.log   # LLDB callback output"
echo ""
echo "To decrypt ESP traffic with extracted keys:"
echo "  - Check: $OUTPUT_DIR/ikev2_decryption_table (Wireshark format)"
echo ""
echo "For analysis:"
echo "  # Search for secrets in memory dumps"
echo "  cd ${SCRIPT_DIR}"
echo "  ./find_ipsec_secrets.py $OUTPUT_DIR"
echo ""
echo "  # Convert to TLS-compatible format for analysis"
echo "  ./convert_ipsec_to_tls_format.py $OUTPUT_DIR /tmp/tls_compat"
echo ""
