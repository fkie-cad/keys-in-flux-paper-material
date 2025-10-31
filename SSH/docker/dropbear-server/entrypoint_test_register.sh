#!/bin/bash
set -e

# Dropbear Register-Based Watchpoint Test - Phase 6A
# Uses dropbear_callbacks_register_based.py
#
# REGISTER-BASED EXTRACTION (Matching IPsec Pattern)
# ===================================================
# This approach matches the proven IPsec/strongSwan pattern:
#  - Direct register reading (x2 = key pointer)
#  - No symbolic navigation
#  - Runtime address from function arguments
#
# Expected Outcomes:
#   ✅ trace_count == 0 → Register approach works like IPsec!
#   ❌ trace_count > 10 → Try Phase 6B (delayed enable)

echo "================================================================="
echo "Dropbear Register-Based Watchpoint Test - Phase 6A"
echo "Testing: Direct register reading + IMMEDIATE enable"
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

echo "Attaching LLDB with register-based callbacks (Phase 6A)..."

# Attach LLDB with register-based extraction script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_register_based.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_register_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "PHASE 6A TEST: Register-based extraction (matching IPsec)"
echo "  - Read x2 register for key pointer"
echo "  - No symbolic navigation"
echo "  - Immediate watchpoint enable"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → Register approach works!"
echo "  ❌ 11+ trace hits → Try Phase 6B (delayed enable)"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_register_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_register_output.log"
