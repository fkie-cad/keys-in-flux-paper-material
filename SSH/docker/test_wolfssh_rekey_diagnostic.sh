#!/bin/bash
#
# wolfSSH Rekey Diagnostic Test
# Tests whether rekey actually completes and extracts keys
#

set -e

echo "=== wolfSSH Rekey Diagnostic Test ==="
echo "Purpose: Determine why key derivation functions don't fire during rekey"
echo

# Clean up
echo "[1/5] Cleaning previous test data..."
rm -rf data/keylogs/wolfssh_client_keylog.log \
       data/lldb_results/timing_wolfssh.csv \
       2>/dev/null || true

# Ensure server is running
echo "[2/5] Ensuring wolfssh_server is running..."
docker compose up -d wolfssh_server
sleep 3

# Run test WITH entry dumps and fork/thread following
echo "[3/5] Running wolfSSH client with enhanced LLDB settings..."
echo "      - Fork following: ENABLED"
echo "      - Thread following: ENABLED"
echo "      - Entry dumps: ALL functions"
echo "      - Watchpoints: DISABLED (focus on function calls)"
echo

timeout 120 docker compose run --rm \
  -e LLDB_ENABLE_ENTRY_DUMPS=true \
  -e LLDB_ENTRY_DUMP_FUNCTIONS=all \
  -e LLDB_ENABLE_WATCHPOINTS=false \
  -e LLDB_ENABLE_MEMORY_DUMPS=false \
  wolfssh_client \
  bash -c '
# Enhanced LLDB with fork/thread following
lldb -o "settings set target.process.follow-fork-mode child" \
     -o "settings set target.process.extra-startup-command QSetDetachOnError:0" \
     -o "settings set target.process.stop-on-exec false" \
     -o "command script import /opt/lldb/wolfssh_client_callbacks.py" \
     -o "process launch --stop-at-entry -- wolfssh_server 22 testuser password --with-rekey" \
     -o "wolfssh_setup_monitoring" \
     -o "continue" \
     -o "quit"
' 2>&1 | tee /tmp/wolfssh_rekey_diagnostic.log

echo
echo "[4/5] Analyzing results..."
echo

# Check keylog
if [ -f data/keylogs/wolfssh_client_keylog.log ]; then
    echo "✓ Keylog exists"

    KEX0_KEYS=$(grep "KEX0" data/keylogs/wolfssh_client_keylog.log | wc -l)
    KEX2_KEYS=$(grep "KEX2" data/keylogs/wolfssh_client_keylog.log | wc -l)

    echo "  - KEX0 keys: $KEX0_KEYS"
    echo "  - KEX2 keys: $KEX2_KEYS"

    if [ $KEX2_KEYS -gt 0 ]; then
        echo "  ✓ REKEY SUCCESSFUL - New keys were derived!"
    else
        echo "  ✗ REKEY FAILED - No new keys derived during KEX2"
    fi
else
    echo "✗ No keylog found"
fi

echo
echo "[5/5] Checking function invocations..."
echo

# Count function calls in log
TRIGGER_KEX_CALLS=$(grep -c "wolfSSH_TriggerKeyExchange" /tmp/wolfssh_rekey_diagnostic.log || echo "0")
SEND_KEX_INIT_CALLS=$(grep -c "\[FUNCTION_ENTRY\] SendKexInit" /tmp/wolfssh_rekey_diagnostic.log || echo "0")
GENERATE_KEY_CALLS=$(grep -c "\[FUNCTION_ENTRY\] GenerateKey" /tmp/wolfssh_rekey_diagnostic.log || echo "0")
WC_SSH_KDF_CALLS=$(grep -c "wc_SSH_KDF entry" /tmp/wolfssh_rekey_diagnostic.log || echo "0")
ECC_GEN_K_CALLS=$(grep -c "\[FUNCTION_ENTRY\] wc_ecc_gen_k" /tmp/wolfssh_rekey_diagnostic.log || echo "0")

echo "Function call summary:"
echo "  - TriggerKeyExchange: $TRIGGER_KEX_CALLS (should be 1)"
echo "  - SendKexInit: $SEND_KEX_INIT_CALLS (should be 2: KEX0 + KEX2)"
echo "  - GenerateKey: $GENERATE_KEY_CALLS (should be 8: 4 per KEX)"
echo "  - wc_SSH_KDF: $WC_SSH_KDF_CALLS (should be 8: 4 per KEX)"
echo "  - wc_ecc_gen_k: $ECC_GEN_K_CALLS (should be 6+: multiple per KEX)"

echo
echo "=== Diagnostic Analysis ==="

if [ $SEND_KEX_INIT_CALLS -eq 2 ] && [ $GENERATE_KEY_CALLS -eq 8 ]; then
    echo "✓ DIAGNOSIS: Rekey completed successfully, all functions fired"
elif [ $SEND_KEX_INIT_CALLS -eq 2 ] && [ $GENERATE_KEY_CALLS -lt 8 ]; then
    echo "⚠️  DIAGNOSIS: SendKexInit fired twice, but GenerateKey didn't fire for KEX2"
    echo "   Possible causes:"
    echo "   - Fork/thread issue (LLDB not following child process)"
    echo "   - Async processing (KEX happens outside main thread)"
    echo "   - Client exited worker loop too early"
elif [ $SEND_KEX_INIT_CALLS -eq 1 ]; then
    echo "⚠️  DIAGNOSIS: Only one SendKexInit - rekey never initiated"
    echo "   Possible causes:"
    echo "   - TriggerKeyExchange didn't actually trigger KEX"
    echo "   - Worker loop exited before processing KEX messages"
else
    echo "⚠️  DIAGNOSIS: Unexpected function call pattern"
fi

echo
echo "Full diagnostic log: /tmp/wolfssh_rekey_diagnostic.log"
echo
