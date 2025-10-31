#!/bin/bash
# OpenSSH LLDB Monitoring - Approach 2: Follow-Fork + Stop-On-Exec
# Explicitly stops at exec() boundary for perfect timing

set -e

echo "======================================================================"
echo "  OpenSSH LLDB - Follow-Fork + Stop-On-Exec"
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

echo "Attaching LLDB with follow-fork + stop-on-exec + auto-continue..."

# Two-command pattern (proven with Dropbear):
#   1. Import Python module → registers commands
#   2. openssh_setup_monitoring → configure fork/exec/breakpoints
#   3. openssh_auto_continue → keep-alive loop with auto-resume
lldb \
  -o "process attach --pid $SSHD_PID" \
  -o "command script import /opt/lldb/openssh_followfork_callbacks.py" \
  -o "openssh_setup_monitoring" \
  -o "openssh_auto_continue" \
  > "$RESULTS_DIR/lldb_followfork_output.log" 2>&1 &

LLDB_PID=$!

echo "======================================================================"
echo "  Monitoring Active"
echo "======================================================================"
echo "  sshd PID:     $SSHD_PID"
echo "  LLDB PID:     $LLDB_PID"
echo "  Keylog:       $LLDB_KEYLOG"
echo "  LLDB log:     $RESULTS_DIR/lldb_followfork_output.log"
echo "======================================================================"

# Wait for sshd
wait $SSHD_PID
echo "sshd exited"
