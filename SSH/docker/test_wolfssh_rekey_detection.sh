#!/bin/bash

# Test script for wolfSSH rekey detection with all breakpoints enabled
# This script enables all entry dump functions to see which are called during rekey

set -e

echo "=== wolfSSH Rekey Detection Test ==="
echo "Purpose: Identify which crypto functions are invoked during TriggerKeyExchange"
echo

# Clean up previous test data
echo "[1/4] Cleaning up previous test data..."
rm -rf data/keylogs/wolfssh_client_keylog.log \
       data/lldb_results/timing_wolfssh.csv \
       2>/dev/null || true

# Ensure server is running
echo "[2/4] Ensuring openssh_groundtruth server is running..."
docker compose up -d openssh_groundtruth
sleep 3

# Run test with all entry dumps enabled
echo "[3/4] Running wolfSSH client with rekey detection (all breakpoints)..."
echo "      Watchpoints: DISABLED (focus on function calls)"
echo "      Memory dumps: DISABLED (reduce noise)"
echo "      Entry dumps: ENABLED (all functions)"
echo "      Server: openssh_groundtruth"
echo

timeout 120 docker compose run --rm \
  -e LLDB_ENABLE_ENTRY_DUMPS=true \
  -e LLDB_ENTRY_DUMP_FUNCTIONS=all \
  -e LLDB_ENABLE_WATCHPOINTS=false \
  -e LLDB_ENABLE_MEMORY_DUMPS=false \
  -e SSH_SERVER_HOST=openssh_groundtruth \
  -e SSH_SERVER_PORT=22 \
  -e SSH_USER=testuser \
  -e SSH_PASSWORD=password \
  -e WOLFSSH_REKEY_MODE=true \
  wolfssh_client

# Analyze results
echo
echo "[4/4] Test complete! Analyzing results..."
echo

if [ -f data/keylogs/wolfssh_client_keylog.log ]; then
    echo "✓ Keylog created:"
    grep -E "NEWKEYS|TRIGGER" data/keylogs/wolfssh_client_keylog.log || echo "  (no NEWKEYS/TRIGGER messages found)"
else
    echo "✗ No keylog found"
fi

echo
echo "=== Analysis: Which functions were called during rekey? ==="
echo "Check the LLDB output above for lines containing:"
echo "  - [FUNCTION_ENTRY] - Shows which functions were called"
echo "  - REKEY_ - Shows which rekey detection functions fired"
echo "  - trigger_kex - Shows when TriggerKeyExchange was called"
echo
echo "Compare KEX0 (initial handshake) vs KEX2 (rekey) to see differences."
echo
