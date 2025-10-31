#!/bin/bash
#
# LLDB Hang Debugging Script
# ==========================
#
# This script allows you to directly test and experiment with LLDB monitoring
# for wolfSSH and Dropbear to debug the hang/excessive-stops issue on ARM64/M1.
#
# Usage:
#   ./debug_lldb_hang.sh [dropbear|wolfssh] [with-watchpoints|without-watchpoints]
#
# Examples:
#   ./debug_lldb_hang.sh dropbear without-watchpoints
#   ./debug_lldb_hang.sh wolfssh with-watchpoints
#

set -e

IMPLEMENTATION=${1:-dropbear}
WATCHPOINTS_MODE=${2:-without-watchpoints}

echo "========================================================================"
echo "  LLDB Hang Debugging Script - ARM64/M1"
echo "========================================================================"
echo ""
echo "Implementation: $IMPLEMENTATION"
echo "Watchpoints:    $WATCHPOINTS_MODE"
echo ""

# Configuration
if [ "$WATCHPOINTS_MODE" = "with-watchpoints" ]; then
    ENABLE_WATCHPOINTS="true"
else
    ENABLE_WATCHPOINTS="false"
fi

echo "=== Step 1: Starting SSH server ==="
docker compose up -d openssh_groundtruth
sleep 3
echo "✓ Server ready"
echo ""

# Clean previous test data
echo "=== Step 2: Cleaning previous test data ==="
rm -rf data/keylogs/* data/dumps/* 2>/dev/null
mkdir -p data/keylogs data/dumps
chmod -R 777 data
echo "✓ Cleanup complete"
echo ""

# Container configuration
if [ "$IMPLEMENTATION" = "dropbear" ]; then
    CONTAINER="dropbear_client"
    SCRIPT_NAME="dropbear_client_rekey"
elif [ "$IMPLEMENTATION" = "wolfssh" ]; then
    CONTAINER="wolfssh_client"
    SCRIPT_NAME="wolfssh_client"  # wolfSSH doesn't use _rekey suffix
else
    echo "ERROR: Unknown implementation: $IMPLEMENTATION"
    echo "Valid options: dropbear, wolfssh"
    exit 1
fi

echo "=== Step 3: Running LLDB monitoring ==="
echo "Container: $CONTAINER"
echo "Watchpoints enabled: $ENABLE_WATCHPOINTS"
echo ""
echo "⚠️  This will run in the FOREGROUND so you can see LLDB output in real-time"
echo "⚠️  Press Ctrl+C to stop"
echo ""
echo "Watch for these patterns:"
echo "  - [CLIENT_AUTO] Continued (stop #X) - should stay low (<50)"
echo "  - [CLIENT_AUTO] WARNING: Hit maximum iteration limit - indicates hang"
echo "  - Process exited after X stops - final count"
echo ""
read -p "Press Enter to start..."
echo ""

# Run the container with LLDB monitoring (NO timeout, so we can observe)
docker compose run --rm \
    -e LLDB_ENABLE_MEMORY_DUMPS=false \
    -e LLDB_ENABLE_WATCHPOINTS=$ENABLE_WATCHPOINTS \
    -e LLDB_EXTRACT_ALL_KEYS=true \
    -e SSH_SERVER_HOST=openssh_groundtruth \
    -e SSH_SERVER_PORT=22 \
    -e SSH_USER=testuser \
    -e SSH_PASSWORD=password \
    $CONTAINER

EXIT_CODE=$?

echo ""
echo "========================================================================"
echo "  Test Complete"
echo "========================================================================"
echo ""
echo "Exit code: $EXIT_CODE"
echo ""

# Analyze results
if [ -f "data/keylogs/${IMPLEMENTATION}_client_keylog.log" ]; then
    KEY_COUNT=$(wc -l < "data/keylogs/${IMPLEMENTATION}_client_keylog.log")
    echo "✓ Keys extracted: $KEY_COUNT"
    echo ""
    cat "data/keylogs/${IMPLEMENTATION}_client_keylog.log"
else
    echo "✗ No keylog found"
fi

echo ""
echo "Cleanup:"
docker compose stop openssh_groundtruth

echo ""
echo "========================================================================"
echo "  Debug Notes"
echo "========================================================================"
echo ""
echo "If you saw 'Hit maximum iteration limit (1000)':"
echo "  → LLDB auto-continue loop is stuck in excessive stops"
echo "  → This happens EVEN WITHOUT watchpoints enabled"
echo "  → Root cause: Something in $IMPLEMENTATION's process behavior"
echo "     triggers repeated LLDB stops (possibly signal handling,"
echo "     threading, or memory operations)"
echo ""
echo "If you saw 'Process exited after X stops' where X < 100:"
echo "  → LLDB monitoring worked correctly!"
echo "  → The issue may be specific to certain test conditions"
echo ""
echo "To experiment further:"
echo "  1. Edit the callback file:"
echo "     lldb/${IMPLEMENTATION}_client_callbacks.py"
echo ""
echo "  2. Try disabling specific features:"
echo "     - Memory dumps: LLDB_ENABLE_MEMORY_DUMPS=false"
echo "     - Extended key extraction: LLDB_EXTRACT_ALL_KEYS=false"
echo "     - Auto-continue loop: Modify auto_continue_command()"
echo ""
echo "  3. Add debug logging to the callback:"
echo "     print(f'[DEBUG] Stop reason: {stop_reason}')"
echo "     print(f'[DEBUG] Thread state: {thread.GetState()}')"
echo ""
echo "  4. Test with simpler SSH commands:"
echo "     Edit dropbear_client_rekey or wolfssh_client scripts"
echo "     to reduce session complexity"
echo ""
