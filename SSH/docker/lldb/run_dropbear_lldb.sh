#!/bin/bash
# Launch LLDB monitoring for Dropbear SSH server
# Usage: ./run_dropbear_lldb.sh [dropbear_args...]
#
# Example: ./run_dropbear_lldb.sh -F -E -p 22

set -e

SERVER_TYPE="dropbear"
DROPBEAR_ARGS="$@"

# Default to standard dropbear arguments if none provided
if [ -z "$DROPBEAR_ARGS" ]; then
    DROPBEAR_ARGS="-F -E -p 22"
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
echo "  Dropbear LLDB Key Lifecycle Monitor"
echo "======================================================================"
echo ""
echo "Server Type:  $SERVER_TYPE"
echo "Results Dir:  $RESULTS_DIR"
echo "Dumps Dir:    $DUMPS_DIR"
echo "Dropbear Args: $DROPBEAR_ARGS"
echo ""

# Check if LLDB is installed
if ! command -v lldb &> /dev/null; then
    echo "ERROR: LLDB is not installed"
    echo "Install with: apt-get install lldb-15 python3-lldb-15"
    exit 1
fi

# Check if dropbear exists
DROPBEAR_PATH=$(which dropbear)
if [ -z "$DROPBEAR_PATH" ]; then
    echo "ERROR: dropbear not found in PATH"
    exit 1
fi

echo "Dropbear Path: $DROPBEAR_PATH"
echo "LLDB Version: $(lldb --version | head -1)"
echo ""

# Create LLDB command file
LLDB_SCRIPT=$(mktemp)
cat > "$LLDB_SCRIPT" << 'EOF'
# Set fork following mode to parent
# SSH servers fork a child for each connection. We want to stay with the
# parent process (the main listener) so connections don't fail.
# The breakpoints will still trigger in child processes.
settings set target.process.follow-fork-mode parent

# Load SSH monitoring script
command script import /opt/lldb/ssh_monitor.py

# Load Dropbear callbacks (which will set up breakpoints automatically)
command script import /opt/lldb/dropbear_callbacks.py

# Start process
process launch

# Keep running
continue
EOF

echo "Starting LLDB monitoring..."
echo "LLDB will run dropbear in the foreground (Ctrl+C to stop)"
echo ""
echo "Note: LLDB stays with parent process, child connections will work normally"
echo "      Breakpoints trigger in all processes (parent and children)"
echo ""

# Launch LLDB with the script (no --batch so it stays running)
lldb \
    --source "$LLDB_SCRIPT" \
    -- "$DROPBEAR_PATH" $DROPBEAR_ARGS

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
