#!/bin/bash
# OpenSSH with PID-based LLDB monitoring for sshd-session

set -e

echo "======================================================================"
echo "  OpenSSH with sshd-session PID Monitor"
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

echo "Starting sshd-session monitor..."
/opt/lldb/monitor_and_attach_sshd_session.sh &
MONITOR_PID=$!

echo "======================================================================"
echo "  Monitoring Active"
echo "======================================================================"
echo "  sshd PID:     $SSHD_PID"
echo "  Monitor PID:  $MONITOR_PID"
echo "  Keylog:       $LLDB_KEYLOG"
echo "  Monitor log:  $RESULTS_DIR/monitor.log"
echo "======================================================================"

# Wait for sshd
wait $SSHD_PID
echo "sshd exited, stopping monitor"
kill $MONITOR_PID 2>/dev/null || true
