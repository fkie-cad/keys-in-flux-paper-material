#!/bin/bash
# Attach LLDB to running Dropbear process for key extraction
# Usage: ./attach_dropbear.sh

set -e

echo "======================================================================"
echo "  Attach LLDB to Running Dropbear"
echo "======================================================================"
echo ""

# Find Dropbear PID
DROPBEAR_PID=$(pgrep -f "^/usr/sbin/dropbear" | head -1)

if [ -z "$DROPBEAR_PID" ]; then
    echo "ERROR: No running Dropbear process found"
    exit 1
fi

echo "Found Dropbear PID: $DROPBEAR_PID"
echo ""

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}
mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"

# Export configuration
export SSH_SERVER_TYPE="dropbear"
export LLDB_RESULTS_DIR="$RESULTS_DIR"
export LLDB_DUMPS_DIR="$DUMPS_DIR"

# Create LLDB attach script
LLDB_SCRIPT=$(mktemp)
cat > "$LLDB_SCRIPT" << EOF
# Attach to process
process attach --pid $DROPBEAR_PID

# Set fork following mode to parent (stay with listener)
settings set target.process.follow-fork-mode parent

# Load SSH monitoring script
command script import /opt/lldb/ssh_monitor.py

# Load Dropbear callbacks
command script import /opt/lldb/dropbear_callbacks.py

# Continue execution
continue
EOF

echo "Attaching LLDB to Dropbear (PID $DROPBEAR_PID)..."
echo "Press Ctrl+C to detach"
echo ""

# Attach LLDB
lldb --source "$LLDB_SCRIPT"

# Cleanup
rm -f "$LLDB_SCRIPT"
