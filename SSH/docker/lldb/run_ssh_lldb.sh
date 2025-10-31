#!/bin/bash
# Launch LLDB monitoring for SSH server
# Usage: ./run_ssh_lldb.sh [server_type] [sshd_args...]
#
# Example: ./run_ssh_lldb.sh openssh -D -e -p 2222

set -e

SERVER_TYPE=${1:-openssh}
shift
SSHD_ARGS="$@"

# Default to standard sshd arguments if none provided
if [ -z "$SSHD_ARGS" ]; then
    SSHD_ARGS="-D -e"
fi

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
mkdir -p "$RESULTS_DIR"

# Export configuration
export SSH_SERVER_TYPE="$SERVER_TYPE"
export LLDB_RESULTS_DIR="$RESULTS_DIR"

echo "======================================================================"
echo "  SSH LLDB Key Lifecycle Monitor"
echo "======================================================================"
echo ""
echo "Server Type: $SERVER_TYPE"
echo "Results Dir: $RESULTS_DIR"
echo "SSHD Args:   $SSHD_ARGS"
echo ""

# Check if LLDB is installed
if ! command -v lldb &> /dev/null; then
    echo "ERROR: LLDB is not installed"
    echo "Install with: apt-get install lldb python3-lldb"
    exit 1
fi

# Check if sshd exists
SSHD_PATH=$(which sshd)
if [ -z "$SSHD_PATH" ]; then
    echo "ERROR: sshd not found in PATH"
    exit 1
fi

echo "SSHD Path: $SSHD_PATH"
echo ""

# Create LLDB command file
LLDB_SCRIPT=$(mktemp)
cat > "$LLDB_SCRIPT" << 'EOF'
# Enable fork following (LLDB 12+ feature)
# This allows LLDB to follow child processes created by fork()
settings set target.process.follow-fork-mode child

# Load SSH monitoring script
command script import /opt/lldb/ssh_monitor.py

# Load OpenSSH callbacks (which will set up breakpoints automatically)
command script import /opt/lldb/openssh_callbacks.py

# Start process
process launch

# Keep running
continue
EOF

echo "Starting LLDB monitoring..."
echo "LLDB will run sshd in the foreground (Ctrl+C to stop)"
echo ""

# Launch LLDB with the script (no --batch so it stays running)
# The script handles process launch and continue, then LLDB waits for events
lldb \
    --source "$LLDB_SCRIPT" \
    -- "$SSHD_PATH" $SSHD_ARGS

# Cleanup
rm -f "$LLDB_SCRIPT"

echo ""
echo "======================================================================"
echo "  Monitoring Complete"
echo "======================================================================"
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "Files generated:"
echo "  - timing_${SERVER_TYPE}.csv    : Key lifecycle timing data"
echo "  - events_${SERVER_TYPE}.log    : Human-readable event log"
echo "  - events_${SERVER_TYPE}.jsonl  : Machine-readable event log"
