#!/bin/bash
set -e

# Dropbear Key Extraction Only Entrypoint
# Uses dropbear_callbacks_keyonly.py (NO watchpoints)
#
# This tests if LLDB breakpoints + key extraction work without trace mode.
# Expected result: ✅ Key extracted successfully, 0 trace hits
#
# If this succeeds, we know watchpoint creation is the specific trigger
# for trace mode in Dropbear.

echo "================================================================="
echo "Dropbear Key Extraction Test (NO Watchpoints)"
echo "Testing: LLDB breakpoints + key extraction ONLY"
echo "================================================================="

# Results directory
RESULTS_DIR=/data/lldb_results
mkdir -p "$RESULTS_DIR"
chmod 777 "$RESULTS_DIR"

# Start Dropbear WITHOUT debug flag (normal mode)
echo "Starting Dropbear server on port 22..."
/usr/sbin/dropbear -F -E -p 22 -r /etc/dropbear/dropbear_rsa_host_key &
DROPBEAR_PID=$!

echo "Dropbear started with PID: $DROPBEAR_PID"
echo "Waiting 2 seconds for Dropbear to initialize..."
sleep 2

# Check if Dropbear is still running
if ! kill -0 $DROPBEAR_PID 2>/dev/null; then
    echo "ERROR: Dropbear failed to start"
    exit 1
fi

echo "Attaching LLDB with key-extraction-only callbacks..."

# Attach LLDB with keyonly monitoring script (NO watchpoints)
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_keyonly.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_keyonly_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "Key Extraction Only mode active - NO watchpoints"
echo "Expected: Keys extracted, 0 trace mode hits"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_keyonly_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_keyonly_output.log"
