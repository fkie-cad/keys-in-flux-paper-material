#!/bin/bash
# Launch Dropbear under LLDB - Fixed order to load file BEFORE script

set -e

echo "======================================================================"
echo "  Dropbear with LLDB Launch (V3 - Fixed Breakpoint Setup)"
echo "======================================================================"

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}

mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR"

export SSH_SERVER_TYPE="dropbear"

echo "Starting Dropbear under LLDB..."
echo ""

# Create LLDB command file with CORRECT ORDER:
# 1. Load file first
# 2. Set settings
# 3. Import Python script (sets breakpoints)
# 4. Launch process
cat > /tmp/lldb_launch.txt << 'LLDB_EOF'
file /usr/sbin/dropbear
settings set target.process.follow-fork-mode child
settings set target.process.stop-on-exec false
command script import /opt/lldb/dropbear_test_minimal_v2.py
process launch -- -F -E -p 22
LLDB_EOF

echo "LLDB command sequence:"
cat /tmp/lldb_launch.txt
echo ""
echo "Launching LLDB..."
echo "========================================================================"

# Launch LLDB and keep output visible
lldb -s /tmp/lldb_launch.txt 2>&1 | tee "$RESULTS_DIR/lldb_output.log"

# If LLDB exits, keep container alive for debugging
echo ""
echo "LLDB exited. Container staying alive for log inspection..."
tail -f /dev/null
