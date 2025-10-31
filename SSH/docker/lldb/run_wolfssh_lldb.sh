#!/bin/bash
# Launch LLDB monitoring for wolfSSH server
# Usage: ./run_wolfssh_lldb.sh [wolfsshd_args...]
#
# Example: ./run_wolfssh_lldb.sh -D -d -p 22

set -e

SERVER_TYPE="wolfssh"
WOLFSSHD_ARGS="$@"

# Default to standard wolfsshd arguments if none provided
if [ -z "$WOLFSSHD_ARGS" ]; then
    WOLFSSHD_ARGS="-D -d -p 22"
fi

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}
mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"

# Export configuration
export SSH_SERVER_TYPE="$SERVER_TYPE"
export LLDB_RESULTS_DIR="$RESULTS_DIR"
export LLDB_DUMPS_DIR="$DUMPS_DIR"

echo "======================================================================"
echo "  wolfSSH LLDB Key Lifecycle Monitor"
echo "======================================================================"
echo ""
echo "Server Type:    $SERVER_TYPE"
echo "Results Dir:    $RESULTS_DIR"
echo "Dumps Dir:      $DUMPS_DIR"
echo "wolfSSHd Args:  $WOLFSSHD_ARGS"
echo ""

# Check if LLDB is installed
if ! command -v lldb &> /dev/null; then
    echo "ERROR: LLDB is not installed"
    echo "Install with: apt-get install lldb-15 python3-lldb-15"
    exit 1
fi

# Check if wolfsshd exists
WOLFSSHD_PATH=$(which wolfsshd)
if [ -z "$WOLFSSHD_PATH" ]; then
    echo "ERROR: wolfsshd not found in PATH"
    exit 1
fi

echo "wolfSSHd Path:  $WOLFSSHD_PATH"
echo "LLDB Version:   $(lldb --version | head -1)"
echo ""

# Update shared library cache (important for wolfSSH)
echo "Updating shared library cache..."
ldconfig
echo ""

# Verify wolfSSL library is found
if ! ldconfig -p | grep -q libwolfssl; then
    echo "WARNING: libwolfssl not in library cache"
    echo "This may cause issues. Check /etc/ld.so.conf.d/"
else
    echo "✓ libwolfssl found in library cache"
fi
echo ""

# Create LLDB command file
LLDB_SCRIPT=$(mktemp)
cat > "$LLDB_SCRIPT" << 'EOF'
# Set fork following mode to child
# SSH servers fork a child for each connection. Follow the child
# where KEX actually happens.
settings set target.process.follow-fork-mode child

# Load SSH monitoring script
command script import /opt/lldb/ssh_monitor.py

# Load wolfSSH callbacks (which will set up breakpoints automatically)
command script import /opt/lldb/wolfssh_callbacks.py

# Start process
process launch

# Keep running
continue
EOF

echo "Starting LLDB monitoring..."
echo "LLDB will run wolfsshd in the foreground (Ctrl+C to stop)"
echo ""
echo "Note: LLDB follows child processes (where KEX happens)"
echo "      Parent listener will respawn after each connection"
echo ""

# Launch LLDB with the script (no --batch so it stays running)
lldb \
    --source "$LLDB_SCRIPT" \
    -- "$WOLFSSHD_PATH" $WOLFSSHD_ARGS

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
echo ""
echo "Memory dumps saved to: $DUMPS_DIR"
echo ""
