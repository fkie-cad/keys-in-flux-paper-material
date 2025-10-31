#!/bin/bash
# OpenSSH LLDB Monitoring - Phase 3: --waitfor Loop
# Waits for each new sshd-session process and attaches independently

set -e

echo "======================================================================"
echo "  OpenSSH LLDB - waitfor Loop (Phase 3)"
echo "======================================================================"

RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
mkdir -p "$RESULTS_DIR" /data/keylogs /data/dumps
chmod 777 "$RESULTS_DIR" /data/keylogs /data/dumps

export LLDB_KEYLOG="/data/keylogs/ssh_keylog.log"

echo "Starting sshd..."
/usr/sbin/sshd -D -e &
SSHD_PID=$!

echo "sshd started with PID: $SSHD_PID"
sleep 2

echo "Starting LLDB waitfor loop..."

# Background monitoring loop
(
    SESSION_COUNT=0
    while true; do
        SESSION_COUNT=$((SESSION_COUNT + 1))
        echo "[WAITFOR] Waiting for sshd-session #${SESSION_COUNT}..."

        # Wait for ANY new sshd-session process
        # When one appears, attach, set breakpoint, extract keys, detach
        lldb -b \
            -o "process attach --name sshd-session --waitfor" \
            -o "command script import /opt/lldb/openssh_followfork_callbacks.py" \
            -o "breakpoint set --name kex_derive_keys" \
            -o "breakpoint command add 1 -F openssh_followfork_callbacks.kex_extract_callback" \
            -o "continue" \
            >> "$RESULTS_DIR/lldb_waitfor_session_${SESSION_COUNT}.log" 2>&1

        echo "[WAITFOR] Session #${SESSION_COUNT} monitoring complete"
    done
) >> "$RESULTS_DIR/lldb_waitfor_monitor.log" 2>&1 &

LLDB_LOOP_PID=$!

echo "======================================================================"
echo "  Monitoring Active"
echo "======================================================================"
echo "  sshd PID:         $SSHD_PID"
echo "  LLDB Loop PID:    $LLDB_LOOP_PID"
echo "  Keylog:           $LLDB_KEYLOG"
echo "  Monitor log:      $RESULTS_DIR/lldb_waitfor_monitor.log"
echo "======================================================================"
echo ""
echo "Each new SSH connection will spawn sshd-session,"
echo "and LLDB will attach automatically via --waitfor"
echo ""

# Wait for sshd
wait $SSHD_PID
echo "sshd exited, stopping LLDB loop"
kill $LLDB_LOOP_PID 2>/dev/null || true
