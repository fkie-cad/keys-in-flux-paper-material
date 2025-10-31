#!/bin/bash
set -e

# Dropbear State-Based Watchpoint Test - Phase 6C-Delayed
# Uses dropbear_callbacks_state_delayed.py
#
# STATE-BASED + DELAYED ENABLE (Backup Strategy)
# ===============================================
# Combines two approaches:
#  1. State-based extraction (watch x5 = state->chacha, PERSISTENT)
#  2. Delayed enable (1.5 second delay before watchpoint activation)
#
# This is a backup test if Phase 6C-Immediate fails.
# If 6C-Immediate succeeds, this confirms timing is NOT the issue.
# If 6C-Immediate fails, this tests if delay + location together help.
#
# Expected Outcomes:
#   ✅ trace_count == 0 → Either location works alone OR need both location+delay
#   ❌ trace_count > 10 → Deeper problem (unlikely)

echo "================================================================="
echo "Dropbear State-Based Watchpoint Test - Phase 6C-Delayed"
echo "Testing: Watch state->chacha (persistent) + DELAYED enable (1.5s)"
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

echo "Attaching LLDB with state-based + delayed callbacks (Phase 6C-Delayed)..."

# Attach LLDB with state-based + delayed extraction script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_state_delayed.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_state_delayed_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "PHASE 6C-DELAYED TEST: State-based + delayed enable"
echo "  - Entry breakpoint on dropbear_chachapoly_start"
echo "  - Exit breakpoint via LR register"
echo "  - Read x5 (state pointer - DESTINATION)"
echo "  - Search for key within state structure"
echo "  - Create watchpoint DISABLED on state->chacha"
echo "  - Wait 1.5 seconds"
echo "  - Verify memory stability"
echo "  - ENABLE watchpoint"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → State-based watching works (with or without delay)"
echo "  ❌ 11+ trace hits → Deeper problem (unlikely)"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_state_delayed_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_state_delayed_output.log"
