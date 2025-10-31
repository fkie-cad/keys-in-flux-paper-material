#!/bin/bash
# Start Dropbear first, then attach LLDB once it's listening
# This avoids LLDB breaking the server startup

set -e

echo "======================================================================"
echo "  Dropbear with Auto-Attach LLDB Monitoring"
echo "======================================================================"
echo ""

# Start Dropbear in background first
echo "Step 1: Starting Dropbear SSH server..."
/usr/sbin/dropbear -F -E -p 22 &
DROPBEAR_PID=$!

echo "Dropbear started with PID: $DROPBEAR_PID"
echo ""

# Wait for Dropbear to start listening (up to 10 seconds)
echo "Step 2: Waiting for Dropbear to listen on port 22..."
for i in {1..20}; do
    if ps -p $DROPBEAR_PID > /dev/null 2>&1; then
        # Check if it's listening (test by trying to read from the socket)
        if timeout 1 bash -c "</dev/tcp/localhost/22" 2>/dev/null; then
            echo "✓ Dropbear is listening on port 22"
            break
        fi
    else
        echo "ERROR: Dropbear process died"
        exit 1
    fi
    echo "  Waiting... ($i/20)"
    sleep 0.5
done

# Verify it's actually listening
if ! ps -p $DROPBEAR_PID > /dev/null; then
    echo "ERROR: Dropbear is not running"
    exit 1
fi

echo ""
echo "Step 3: Attaching LLDB for key monitoring..."

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}

# Ensure directories exist with proper permissions
mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR"

# Test that we can write to results directory
touch "$RESULTS_DIR/lldb_output.log" || {
    echo "ERROR: Cannot write to $RESULTS_DIR"
    exit 1
}

# Export configuration
export SSH_SERVER_TYPE="dropbear"
export LLDB_RESULTS_DIR="$RESULTS_DIR"
export LLDB_DUMPS_DIR="$DUMPS_DIR"

echo "Attaching LLDB to Dropbear (PID $DROPBEAR_PID) in background..."
echo "Output will be logged to: $RESULTS_DIR/lldb_output.log"
echo ""

# Run LLDB with -o (one-liner) commands for reliable execution
# This ensures all commands execute in sequence without stdin buffering issues
# Note: Breakpoints may not reliably transfer to forked child processes in all LLDB versions
# V2: Using corrected fork handling with follow-fork-mode switching
# V3: Using two-command pattern (IPsec-style) for watchpoint auto-continue
#     - dropbear_setup_monitoring: Configure breakpoints/watchpoints
#     - dropbear_auto_continue: Keep-alive loop with explicit Continue()
# TEST: Disable follow-fork-mode to isolate watchpoint+fork issue
lldb \
  -o "process attach --pid $DROPBEAR_PID" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "settings set target.detach-on-error false" \
  -o "command script import /opt/lldb/dropbear_callbacks_v2.py" \
  -o "dropbear_setup_monitoring" \
  -o "dropbear_auto_continue" \
  > "$RESULTS_DIR/lldb_output.log" 2>&1 &
LLDB_PID=$!

echo "LLDB started with PID: $LLDB_PID"
echo "Dropbear PID: $DROPBEAR_PID"
echo ""
echo "Monitoring active - container will stay running"
echo "Check logs: tail -f /data/lldb_results/*"
echo ""

# Keep container alive by waiting for Dropbear process
wait $DROPBEAR_PID
echo "Dropbear exited, stopping LLDB"

# Kill LLDB when Dropbear exits
kill $LLDB_PID 2>/dev/null || true
