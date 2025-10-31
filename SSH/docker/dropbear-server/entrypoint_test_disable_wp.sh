#!/bin/bash
set -e

# Dropbear Immediate Watchpoint Disable Test Entrypoint
# Uses dropbear_callbacks_test_disable_wp.py
#
# HYPOTHESIS 3 VALIDATION TEST
# ============================
# Tests if disabling watchpoint immediately after creation prevents trace mode.
#
# Theory: LLDB's watchpoint disable/reenable cycle during single-step resume
# corrupts ARM64 debug registers, causing trace mode. If immediate disable
# prevents this, the problem is active monitoring, not creation.
#
# Expected Outcomes:
#   ✅ trace_count == 0 → Active monitoring is the problem
#   ❌ trace_count > 10 → Watchpoint creation itself corrupts state

echo "================================================================="
echo "Dropbear Immediate Watchpoint Disable Test - HYPOTHESIS 3"
echo "Testing: Watchpoint created but IMMEDIATELY disabled"
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

echo "Attaching LLDB with immediate watchpoint disable test callbacks..."

# Attach LLDB with immediate disable test script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_test_disable_wp.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_disable_wp_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "HYPOTHESIS 3 TEST: Watchpoint will be DISABLED immediately after creation"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → Active monitoring causes trace mode"
echo "  ❌ 11+ trace hits → Creation itself corrupts debug state"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_disable_wp_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_disable_wp_output.log"
