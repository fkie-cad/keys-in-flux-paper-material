#!/bin/bash
set -e

# Dropbear Register-Based + Delayed Enable Test - Phase 6B
# Uses dropbear_callbacks_register_delayed.py
#
# REGISTER-BASED + DELAYED ENABLE
# =================================
# Combines two strategies:
#  1. Register-based extraction (like IPsec)
#  2. Delayed enable (1.5 second delay)
#
# Expected Outcomes:
#   ✅ trace_count == 0 → Need BOTH register + delay
#   ❌ trace_count > 10 → Problem is deeper

echo "================================================================="
echo "Dropbear Register + Delayed Enable Test - Phase 6B"
echo "Testing: Register reading + DELAYED enable (1.5s delay)"
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

echo "Attaching LLDB with register-based + delayed enable callbacks (Phase 6B)..."

# Attach LLDB with register-based + delayed enable script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_register_delayed.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_register_delayed_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "PHASE 6B TEST: Register-based + delayed enable"
echo "  - Read x2 register for key pointer"
echo "  - Create watchpoint DISABLED"
echo "  - Wait 1.5 seconds"
echo "  - Verify memory stability"
echo "  - ENABLE watchpoint"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → Need both register approach AND delay"
echo "  ❌ 11+ trace hits → Problem is deeper than expected"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_register_delayed_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_register_delayed_output.log"
