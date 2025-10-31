#!/bin/bash
#
# SSH Lifecycle Wrapper - Creates local trigger file for LLDB dump
#
# This script:
#   1. Launches SSH with commands
#   2. After commands complete, creates LOCAL trigger file
#   3. Waits for LLDB to process the trigger
#   4. Allows SSH to exit naturally
#

set -e

SERVER="$1"
PORT="$2"
USER="$3"
PASSWORD="$4"

echo "[WRAPPER] SSH Lifecycle Wrapper v1.0"
echo "[WRAPPER] Target: ${USER}@${SERVER}:${PORT}"
echo ""

# Phase 1: SSH commands (runs on server)
echo "[WRAPPER] === PHASE 1: SSH Commands ==="
sshpass -p "${PASSWORD}" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=QUIET \
    -p "${PORT}" \
    "${USER}@${SERVER}" \
    'hostname && pwd && echo "OpenSSH lifecycle test" && sleep 2 && echo "Commands complete"' &

SSH_PID=$!
echo "[WRAPPER] SSH launched (PID: ${SSH_PID})"

# Wait for SSH to complete commands
wait ${SSH_PID}
SSH_EXIT_CODE=$?

echo "[WRAPPER] SSH commands finished (exit code: ${SSH_EXIT_CODE})"
echo ""

# Phase 2: Create LOCAL trigger file for pre-exit dump
echo "[WRAPPER] === PHASE 2: Pre-Exit Memory Dump ==="
echo "[WRAPPER] Creating LOCAL trigger file: /tmp/lldb_dump_pre_exit"
touch /tmp/lldb_dump_pre_exit

echo "[WRAPPER] Waiting for LLDB to detect and process trigger..."
sleep 3

# Verify trigger was consumed (LLDB should delete it)
if [ -f /tmp/lldb_dump_pre_exit ]; then
    echo "[WRAPPER] ⚠️  Trigger file still exists (LLDB may not have detected it)"
else
    echo "[WRAPPER] ✓ Trigger file consumed by LLDB"
fi

echo ""
echo "[WRAPPER] === PHASE 3: Exit ==="
echo "[WRAPPER] Wrapper complete - process will exit"
echo "[WRAPPER] (LLDB will detect process exit and trigger SESSION_CLOSED dump)"
exit ${SSH_EXIT_CODE}
