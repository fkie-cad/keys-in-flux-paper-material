#!/bin/bash
# Interactive LLDB debugging script for dropbear_callbacks_v2.py
# This script helps debug why V2 callbacks aren't firing

set -e

echo "======================================================================"
echo "  Interactive LLDB Debug Session for Dropbear V2 Callbacks"
echo "======================================================================"
echo ""
echo "This script will:"
echo "  1. Start Dropbear SSH server"
echo "  2. Launch interactive LLDB session"
echo "  3. Load V2 callbacks with full error output visible"
echo "  4. Allow you to inspect breakpoint registration"
echo ""
echo "Run this inside the dropbear_server container."
echo ""

# Check if running inside container
if [ ! -f /opt/lldb/dropbear_callbacks_v2.py ]; then
    echo "ERROR: This script must be run inside the dropbear_server container"
    echo "Usage: docker compose exec dropbear_server bash /tmp/debug_v2_interactive.sh"
    exit 1
fi

# Kill any existing Dropbear processes
echo "Step 1: Cleaning up any existing Dropbear processes..."
pkill dropbear || true
sleep 1

# Start Dropbear in background
echo "Step 2: Starting Dropbear SSH server..."
/usr/sbin/dropbear -F -E -p 22 &
DROPBEAR_PID=$!
echo "Dropbear started with PID: $DROPBEAR_PID"
echo ""

# Wait for it to be listening
echo "Step 3: Waiting for Dropbear to listen on port 22..."
for i in {1..20}; do
    if ps -p $DROPBEAR_PID > /dev/null 2>&1; then
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

echo ""
echo "Step 4: Starting interactive LLDB session..."
echo ""
echo "======================================================================"
echo "  LLDB Commands to Run Manually:"
echo "======================================================================"
echo ""
echo "1. Load V2 callbacks and watch for errors:"
echo "   (lldb) command script import /opt/lldb/dropbear_callbacks_v2.py"
echo ""
echo "2. List all breakpoints to verify they were created:"
echo "   (lldb) breakpoint list"
echo ""
echo "3. Check if callbacks are attached to breakpoints:"
echo "   (lldb) breakpoint list -v"
echo ""
echo "4. Continue execution:"
echo "   (lldb) continue"
echo ""
echo "5. In another terminal, test SSH connection:"
echo "   ssh testuser@localhost -p 2223 'echo test'"
echo ""
echo "6. Check if any breakpoints hit:"
echo "   (watch LLDB output)"
echo ""
echo "7. To exit LLDB:"
echo "   (lldb) quit"
echo ""
echo "======================================================================"
echo ""

# Set up environment variables
export SSH_SERVER_TYPE="dropbear"
export LLDB_RESULTS_DIR="/data/lldb_results"
export LLDB_DUMPS_DIR="/data/dumps"
export LLDB_AUTO_CONTINUE="true"
export LLDB_DEBUG_OUTPUT="true"
export LLDB_FORK_STRATEGY="follow_connection"
export LLDB_ENABLE_WATCHPOINTS="true"
export LLDB_ENABLE_MEMORY_DUMPS="true"

echo "Environment variables set:"
echo "  SSH_SERVER_TYPE=$SSH_SERVER_TYPE"
echo "  LLDB_AUTO_CONTINUE=$LLDB_AUTO_CONTINUE"
echo "  LLDB_DEBUG_OUTPUT=$LLDB_DEBUG_OUTPUT"
echo "  LLDB_FORK_STRATEGY=$LLDB_FORK_STRATEGY"
echo "  LLDB_ENABLE_WATCHPOINTS=$LLDB_ENABLE_WATCHPOINTS"
echo ""

# Launch interactive LLDB
echo "Launching LLDB attached to PID $DROPBEAR_PID..."
echo ""

lldb -p $DROPBEAR_PID \
     -o "settings set target.process.follow-fork-mode child" \
     -o "settings set target.process.stop-on-exec false" \
     -o "settings set target.detach-on-error false"

# Note: Not loading V2 automatically - user will do it manually to see errors

echo ""
echo "LLDB session ended."
