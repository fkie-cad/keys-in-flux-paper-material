#!/bin/bash
set -e

# Dropbear Minimal Test Entrypoint
# Uses dropbear_callbacks_minimal.py (Test 3 pattern)

echo "========================================="
echo "Dropbear Minimal Monitoring Test"
echo "Based on successful Test 3 pattern"
echo "========================================="

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

echo "Attaching LLDB with minimal callbacks..."

# Attach LLDB with minimal monitoring script
# Uses same two-command pattern as Test 3
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_minimal.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "Minimal monitoring active - Test 3 pattern"
echo "Monitoring for trace mode issues..."
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_output.log"
echo "========================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_output.log"
