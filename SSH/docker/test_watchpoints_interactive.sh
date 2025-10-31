#!/bin/bash
# Interactive watchpoint test - runs LLDB directly and logs output

set -e

LOG_DIR="data/watchpoint_test_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/interactive_${TIMESTAMP}.log"

# Create log directory
mkdir -p "$LOG_DIR"

echo "=========================================="
echo "Dropbear Watchpoint Interactive Test"
echo "Timestamp: $TIMESTAMP"
echo "Log file: $LOG_FILE"
echo "=========================================="

# Get Dropbear PID
DROPBEAR_PID=$(docker compose exec -T dropbear_server pgrep -x dropbear | head -1 | tr -d '\r')
echo "Dropbear PID: $DROPBEAR_PID"

# Create LLDB commands with proper expect handling
cat > /tmp/lldb_test_commands.txt << EOF
process attach --pid $DROPBEAR_PID
settings set target.process.follow-fork-mode child
settings set target.process.stop-on-exec false
command script import /opt/lldb/dropbear_test_minimal_v2.py
continue
EOF

echo "Starting LLDB with V2 test script..."
echo "This will run interactively - SSH connection will be made automatically"
echo ""

# Start LLDB and SSH connection in parallel
(
    sleep 5
    echo "[SSH] Waiting 5 seconds for LLDB to initialize..."
    echo "[SSH] Making SSH connection..."
    timeout 10 sshpass -p password ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -p 2223 \
        testuser@localhost \
        "echo 'Connected'; hostname; sleep 2; exit" 2>&1 && \
        echo "[SSH] Connection successful" || \
        echo "[SSH] Connection failed/timeout (may be expected)"
) &
SSH_PID=$!

# Run LLDB with command file
docker compose exec -T dropbear_server lldb -s /tmp/lldb_test_commands.txt 2>&1 | tee "$LOG_FILE"

# Wait for SSH connection process
wait $SSH_PID 2>/dev/null || true

echo ""
echo "=========================================="
echo "Test Complete"
echo "=========================================="
echo "Log saved to: $LOG_FILE"
echo ""

# Analyze results
if grep -q "WATCHPOINT HIT" "$LOG_FILE"; then
    echo "✓ SUCCESS: Watchpoint fired!"
    grep "WATCHPOINT HIT" "$LOG_FILE"
    exit 0
elif grep -q "WATCHPOINT] Set on trans_cipher_key" "$LOG_FILE"; then
    echo "⚠ PARTIAL: Watchpoint set but didn't fire"
    grep "WATCHPOINT] Set on trans_cipher_key" "$LOG_FILE"
    exit 1
else
    echo "✗ FAIL: Watchpoint not set"
    exit 1
fi
