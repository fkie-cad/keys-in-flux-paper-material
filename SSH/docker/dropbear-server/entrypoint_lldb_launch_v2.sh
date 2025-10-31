#!/bin/bash
# Launch Dropbear directly under LLDB - keep container alive

set -e

echo "======================================================================"
echo "  Dropbear with LLDB Launch (V2 Watchpoint Test)"
echo "======================================================================"

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}

mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR"

export SSH_SERVER_TYPE="dropbear"

echo "Starting Dropbear under LLDB..."
echo "LLDB will launch /usr/sbin/dropbear with -F -E -p 22"
echo ""

# Create LLDB command file
cat > /tmp/lldb_launch.txt << 'LLDB_EOF'
settings set target.process.follow-fork-mode child
settings set target.process.stop-on-exec false
command script import /opt/lldb/dropbear_test_minimal_v2.py
file /usr/sbin/dropbear
process launch -- -F -E -p 22
LLDB_EOF

# Launch LLDB and keep output visible
lldb -s /tmp/lldb_launch.txt 2>&1 | tee "$RESULTS_DIR/lldb_output.log"

# If LLDB exits, keep container alive for debugging
echo ""
echo "LLDB exited. Keeping container alive for debugging..."
tail -f /dev/null
