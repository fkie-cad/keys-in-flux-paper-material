#!/bin/bash
set -e

# Dropbear SIGCHLD Blocking Test Entrypoint
# Uses dropbear_callbacks_test_nosigchld.py
#
# HYPOTHESIS 1 VALIDATION TEST
# ============================
# Tests if blocking SIGCHLD signal delivery prevents trace mode when
# watchpoint is created.
#
# Theory: SIGCHLD handler interferes with LLDB's watchpoint single-step
# resume logic, causing infinite trace mode loop.
#
# Expected Outcomes:
#   ✅ trace_count == 0 → CONFIRMS Hypothesis 1 (SIGCHLD interference)
#   ❌ trace_count > 10 → REJECTS Hypothesis 1, move to Hypothesis 2

echo "================================================================="
echo "Dropbear SIGCHLD Blocking Test - HYPOTHESIS 1 VALIDATION"
echo "Testing: Watchpoint + SIGCHLD blocked via 'process handle'"
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

echo "Attaching LLDB with SIGCHLD blocking test callbacks..."

# Attach LLDB with SIGCHLD blocking test script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_test_nosigchld.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_nosigchld_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "HYPOTHESIS 1 TEST: SIGCHLD will be blocked before watchpoint creation"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → CONFIRMS Hypothesis 1 (SIGCHLD is the cause)"
echo "  ❌ 11+ trace hits → REJECTS Hypothesis 1 (look elsewhere)"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_nosigchld_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_nosigchld_output.log"
