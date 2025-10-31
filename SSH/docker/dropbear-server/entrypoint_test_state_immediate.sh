#!/bin/bash
set -e

# Dropbear State-Based Watchpoint Test - Phase 6C-Immediate
# Uses dropbear_callbacks_state_immediate.py
#
# STATE-BASED EXTRACTION (Matching IPsec Persistent Storage Pattern)
# ===================================================================
# This approach watches the DESTINATION (state->chacha) not SOURCE (key parameter):
#  - Entry breakpoint on dropbear_chachapoly_start
#  - Exit breakpoint set via LR register
#  - On exit: Key has been copied to state->chacha (PERSISTENT)
#  - Watch state->chacha address (heap/persistent, not stack)
#  - Immediate enable (like Phase 6A but correct location)
#
# Expected Outcomes:
#   ✅ trace_count == 0 → Watching persistent storage works like IPsec!
#   ❌ trace_count > 10 → Try Phase 6C-Delayed (backup)

echo "================================================================="
echo "Dropbear State-Based Watchpoint Test - Phase 6C-Immediate"
echo "Testing: Watch state->chacha (persistent) + IMMEDIATE enable"
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

echo "Attaching LLDB with state-based callbacks (Phase 6C-Immediate)..."

# Attach LLDB with state-based extraction script
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_state_immediate.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_test_state_immediate_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "PHASE 6C-IMMEDIATE TEST: Watch persistent state storage"
echo "  - Entry breakpoint on dropbear_chachapoly_start"
echo "  - Exit breakpoint via LR register"
echo "  - Read x5 (state pointer - DESTINATION)"
echo "  - Search for key within state structure"
echo "  - Create watchpoint on state->chacha (PERSISTENT)"
echo "  - Immediate watchpoint enable"
echo ""
echo "Expected Outcomes:"
echo "  ✅ 0 trace hits   → Persistent storage approach works like IPsec!"
echo "  ❌ 11+ trace hits → Try Phase 6C-Delayed (backup)"
echo ""
echo "Connect via: ssh -p 2223 testuser@localhost"
echo "Password: password"
echo ""
echo "Output: $RESULTS_DIR/lldb_test_state_immediate_output.log"
echo "================================================================="

# Keep container running
tail -f "$RESULTS_DIR/lldb_test_state_immediate_output.log"
