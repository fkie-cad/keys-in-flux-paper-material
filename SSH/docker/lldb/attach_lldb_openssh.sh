#!/bin/bash
# Start OpenSSH sshd first, then attach LLDB for key monitoring
# Uses two-command pattern from Dropbear/strongSwan

set -e

echo "======================================================================"
echo "  OpenSSH with Auto-Attach LLDB Monitoring"
echo "======================================================================"
echo ""

# Configuration from environment
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}
KEYLOG=${LLDB_KEYLOG:-/data/keylogs/ssh_keylog.log}

# Ensure directories exist with proper permissions
mkdir -p "$RESULTS_DIR" "$DUMPS_DIR" "$(dirname "$KEYLOG")"
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR" "$(dirname "$KEYLOG")"

# Test write access
touch "$RESULTS_DIR/lldb_openssh_output.log" || {
    echo "ERROR: Cannot write to $RESULTS_DIR"
    exit 1
}

# Export configuration for callbacks
export SSH_SERVER_TYPE="openssh"
export LLDB_RESULTS_DIR="$RESULTS_DIR"
export LLDB_DUMPS_DIR="$DUMPS_DIR"
export LLDB_OUTDIR="$DUMPS_DIR"
export LLDB_KEYLOG="$KEYLOG"
export LLDB_ENABLE_MEMORY_DUMPS="${LLDB_ENABLE_MEMORY_DUMPS:-true}"
export LLDB_ENABLE_WATCHPOINTS="${LLDB_ENABLE_WATCHPOINTS:-false}"  # Phase 5

echo "Configuration:"
echo "  Results:    $RESULTS_DIR"
echo "  Dumps:      $DUMPS_DIR"
echo "  Keylog:     $KEYLOG"
echo "  Memory dumps: $LLDB_ENABLE_MEMORY_DUMPS"
echo "  Watchpoints:  $LLDB_ENABLE_WATCHPOINTS"
echo ""

# Step 1: Start OpenSSH sshd in background
echo "Step 1: Starting OpenSSH sshd..."
/usr/sbin/sshd -D -e &
SSHD_PID=$!

echo "OpenSSH sshd started with PID: $SSHD_PID"
echo ""

# Step 2: Wait for sshd to start listening (up to 10 seconds)
echo "Step 2: Waiting for sshd to listen on port 22..."
for i in {1..20}; do
    if ps -p $SSHD_PID > /dev/null 2>&1; then
        # Check if it's listening
        if timeout 1 bash -c "</dev/tcp/localhost/22" 2>/dev/null; then
            echo "✓ OpenSSH sshd is listening on port 22"
            break
        fi
    else
        echo "ERROR: sshd process died"
        exit 1
    fi
    echo "  Waiting... ($i/20)"
    sleep 0.5
done

# Verify it's actually running
if ! ps -p $SSHD_PID > /dev/null; then
    echo "ERROR: sshd is not running"
    exit 1
fi

echo ""
echo "Step 3: Attaching LLDB for key monitoring..."
echo "Attaching LLDB to sshd (PID $SSHD_PID) in background..."
echo "Output will be logged to: $RESULTS_DIR/lldb_openssh_output.log"
echo ""

# Step 3: Attach LLDB with two-command pattern
# - openssh_setup_monitoring: Register breakpoints (fork, kex_derive_keys)
# - openssh_auto_continue: Keep-alive loop with explicit Continue()
#
# Important LLDB settings for OpenSSH 10.x (sshd → sshd-session fork/exec):
#   - follow-fork-mode child: Follow into sshd-session process
#   - stop-on-exec false: Don't stop when sshd-session is exec'd
#   - detach-on-error false: Keep attached even if errors occur
#
# Note: KEX happens in /usr/libexec/sshd-session, not /usr/sbin/sshd
# The fork callback will detect when we enter sshd-session
lldb \
  -o "process attach --pid $SSHD_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/openssh_callbacks.py" \
  -o "openssh_setup_monitoring" \
  -o "openssh_auto_continue" \
  > "$RESULTS_DIR/lldb_openssh_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "OpenSSH sshd PID: $SSHD_PID"
echo ""
echo "======================================================================"
echo "  Monitoring Active"
echo "======================================================================"
echo "  OpenSSH PID:  $SSHD_PID"
echo "  LLDB PID:     $LLDB_PID"
echo "  Keylog:       $KEYLOG"
echo "  LLDB logs:    $RESULTS_DIR/lldb_openssh_output.log"
echo "  Events:       $DUMPS_DIR/openssh_events.jsonl"
echo ""
echo "Test connection: ssh -p 2222 testuser@localhost (password: password)"
echo "Monitor logs:    tail -f $RESULTS_DIR/lldb_openssh_output.log"
echo "======================================================================"
echo ""

# Keep container alive by waiting for sshd process
wait $SSHD_PID
echo "OpenSSH sshd exited, stopping LLDB"

# Kill LLDB when sshd exits
kill $LLDB_PID 2>/dev/null || true
