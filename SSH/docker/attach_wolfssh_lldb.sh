#!/bin/bash
# Manual LLDB Attachment Script for wolfSSH
#
# Usage:
#   ./attach_wolfssh_lldb.sh                    # Attach to running wolfsshd
#   ./attach_wolfssh_lldb.sh <PID>              # Attach to specific PID
#   ./attach_wolfssh_lldb.sh --wait             # Wait for new connection (child process)
#
# This script loads the wolfssh_callbacks.py with all breakpoints configured.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALLBACKS_SCRIPT="$SCRIPT_DIR/lldb/wolfssh_callbacks.py"

# Check if running inside container or on host
if [ -f /.dockerenv ]; then
    CONTAINER_MODE=true
else
    CONTAINER_MODE=false
fi

# Function to find wolfsshd process
find_wolfsshd_pid() {
    if [ "$CONTAINER_MODE" = true ]; then
        # Inside container
        ps aux | grep wolfsshd | grep -v grep | awk '{print $2}' | head -1
    else
        # On host - look inside container
        docker compose exec wolfssh_server ps aux | grep wolfsshd | grep -v grep | awk '{print $2}' | head -1
    fi
}

# Parse arguments
MODE="attach"
TARGET_PID=""

if [ "$1" = "--wait" ]; then
    MODE="wait"
elif [ -n "$1" ]; then
    TARGET_PID="$1"
fi

echo "========================================================================"
echo "  wolfSSH Manual LLDB Attachment"
echo "========================================================================"
echo ""

# Get PID
if [ -z "$TARGET_PID" ]; then
    echo "Finding wolfsshd process..."
    TARGET_PID=$(find_wolfsshd_pid)

    if [ -z "$TARGET_PID" ]; then
        echo "ERROR: No wolfsshd process found"
        echo ""
        echo "Start the wolfSSH container first:"
        echo "  docker compose up -d wolfssh_server"
        exit 1
    fi

    echo "Found wolfsshd PID: $TARGET_PID"
else
    echo "Using specified PID: $TARGET_PID"
fi

echo ""
echo "Callbacks: $CALLBACKS_SCRIPT"
echo ""
echo "========================================================================"
echo ""

# Check if inside container
if [ "$CONTAINER_MODE" = false ]; then
    echo "Entering wolfSSH container..."
    echo ""

    # Execute inside container
    docker compose exec wolfssh_server bash -c "
        echo 'Attaching LLDB to PID $TARGET_PID with callbacks...'
        echo ''

        # Create LLDB init file
        cat > /tmp/lldb_attach.txt << 'LLDB_EOF'
# Attach to process
process attach -p $TARGET_PID

# Load wolfSSH callbacks
command script import /opt/lldb/wolfssh_callbacks.py

# Show breakpoints
breakpoint list

# Instructions
echo ''
echo '========================================================================'
echo '  LLDB Attached Successfully'
echo '========================================================================'
echo ''
echo 'Breakpoints configured:'
echo '  1. wolfSSH_accept (for visibility)'
echo '  2. wolfSSH_KDF (KEX function - not triggering)'
echo '  3. ForceZero (memory clearing - working)'
echo ''
echo 'Useful commands:'
echo '  (lldb) c              # Continue execution'
echo '  (lldb) bt             # Show backtrace when stopped'
echo '  (lldb) frame variable # Show local variables'
echo '  (lldb) breakpoint list # List all breakpoints'
echo '  (lldb) image lookup -n wolfSSH_KDF # Check symbol resolution'
echo '  (lldb) image lookup -rn \".*KEX.*\" # Search for KEX-related functions'
echo '  (lldb) image lookup -rn \".*[Gg]enerate.*[Kk]ey.*\" # Search for key generation'
echo ''
echo 'To test:'
echo '  1. Type \"c\" to continue process'
echo '  2. In another terminal: ssh -p 2224 testuser@localhost'
echo '  3. Watch for breakpoint hits'
echo ''
echo '========================================================================'
echo ''

LLDB_EOF

        # Run LLDB
        lldb --source /tmp/lldb_attach.txt
    "
else
    # Already inside container
    echo 'Attaching LLDB to PID $TARGET_PID with callbacks...'
    echo ''

    # Create LLDB init file
    cat > /tmp/lldb_attach.txt << 'LLDB_EOF'
# Attach to process
process attach -p $TARGET_PID

# Load wolfSSH callbacks
command script import /opt/lldb/wolfssh_callbacks.py

# Show breakpoints
breakpoint list

# Instructions
echo ''
echo '========================================================================'
echo '  LLDB Attached Successfully'
echo '========================================================================'
echo ''
echo 'Breakpoints configured:'
echo '  1. wolfSSH_accept (for visibility)'
echo '  2. wolfSSH_KDF (KEX function - not triggering)'
echo '  3. ForceZero (memory clearing - working)'
echo ''
echo 'Useful commands:'
echo '  (lldb) c              # Continue execution'
echo '  (lldb) bt             # Show backtrace when stopped'
echo '  (lldb) frame variable # Show local variables'
echo '  (lldb) breakpoint list # List all breakpoints'
echo '  (lldb) image lookup -n wolfSSH_KDF # Check symbol resolution'
echo '  (lldb) image lookup -rn ".*KEX.*" # Search for KEX-related functions'
echo '  (lldb) image lookup -rn ".*[Gg]enerate.*[Kk]ey.*" # Search for key generation'
echo ''
echo 'To test:'
echo '  1. Type "c" to continue process'
echo '  2. In another terminal: ssh -p 2224 testuser@localhost'
echo '  3. Watch for breakpoint hits'
echo ''
echo '========================================================================'
echo ''

LLDB_EOF

    # Run LLDB
    lldb --source /tmp/lldb_attach.txt
fi
