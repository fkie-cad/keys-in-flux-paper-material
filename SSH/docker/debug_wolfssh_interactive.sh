#!/bin/bash
#
# Interactive LLDB Session for wolfSSH Client Debugging
# Opens an LLDB session with breakpoints set, allowing manual investigation
#

# Default settings
CLIENT_VERSION="v2"
SERVER="openssh_wolfssh_compat"
SERVER_PORT=22

# Parse arguments
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --client <v1|v2>              Choose client version (default: v2)"
    echo "  --server <server_name>         Choose server (default: openssh_wolfssh_compat)"
    echo "                                 Options: wolfssh_server, openssh_groundtruth, openssh_wolfssh_compat"
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                             # Use defaults (v1 client, openssh_groundtruth)"
    echo "  $0 --client v2                 # Use V2 client with default server"
    echo "  $0 --client v1 --server wolfssh_server  # Use V1 with wolfSSH server"
    echo "  $0 --client v2 --server openssh_groundtruth  # Use V2 with OpenSSH"
    echo ""
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --client)
            CLIENT_VERSION="$2"
            shift 2
            ;;
        --server)
            SERVER="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Validate client version
if [[ "$CLIENT_VERSION" != "v1" && "$CLIENT_VERSION" != "v2" ]]; then
    echo "Error: Client version must be 'v1' or 'v2'"
    exit 1
fi

# Validate server and set port
case "$SERVER" in
    wolfssh_server)
        SERVER_PORT=22
        ;;
    openssh_groundtruth)
        SERVER_PORT=22
        ;;
    openssh_wolfssh_compat)
        SERVER_PORT=22
        ;;
    *)
        echo "Error: Unknown server '$SERVER'"
        echo "Valid options: wolfssh_server, openssh_groundtruth, openssh_wolfssh_compat"
        exit 1
        ;;
esac

# Determine binary path
CLIENT_BINARY="/usr/local/bin/wolfssh-client-rekey-${CLIENT_VERSION}"

echo "========================================================================"
echo "  wolfSSH Client - Interactive LLDB Debugging (Updated 2025-10-29)"
echo "========================================================================"
echo ""
echo "Configuration:"
echo "  Client: wolfssh-client-rekey-${CLIENT_VERSION}"
echo "  Server: ${SERVER}:${SERVER_PORT}"
echo ""
echo "IMPORTANT: wolfSSH client compatibility:"
echo "  ✓ BEST with openssh_groundtruth server (full rekey support)"
echo "  ⚠️  wolfssh_server may not respond to rekey requests"
echo "  ✓ Supports explicit rekey via wolfSSH_TriggerKeyExchange()"
echo "  ✓ Supports file trigger for PRE_SESSION_CLOSE dumps"
echo ""
echo "This script will:"
echo "  1. Start ${SERVER} server"
echo "  2. Launch LLDB with wolfSSH custom client (${CLIENT_VERSION}) loaded"
echo "  3. Set breakpoints on wolfSSH_KDF and session close functions"
echo "  4. Enable rekey detection hooks (13 functions total)"
echo "  5. Drop you into an interactive LLDB session"
echo ""
echo "You can then manually:"
echo "  - (lldb) process launch -- ${SERVER} ${SERVER_PORT} testuser password --with-rekey"
echo "  - (lldb) continue"
echo "  - Watch for [FUNCTION_ENTRY] messages during initial KEX and rekey"
echo "  - Test file trigger: platform shell touch /tmp/lldb_dump_pre_exit"
echo "  - Investigate breakpoints, memory, state transitions"
echo ""
echo "========================================================================"
echo ""

# Ensure server is running
echo "Starting ${SERVER}..."
docker compose up -d "${SERVER}"
sleep 3

echo ""
echo "Entering wolfSSH client container with interactive LLDB..."
echo ""
echo "========================================================================"
echo "  LLDB Commands You Can Use:"
echo "========================================================================"
echo ""
echo "1. Launch process (custom client with lifecycle support and REKEY):"
echo "   (lldb) process launch --stop-at-entry -- ${SERVER} ${SERVER_PORT} testuser password --with-rekey"
echo "   (lldb) wolfssh_setup_monitoring"
echo "   (lldb) continue"
echo ""
echo "2. Set breakpoints manually:"
echo "   (lldb) breakpoint set -n wolfSSH_KDF"
echo "   (lldb) breakpoint set -n DoNewKeys"
echo "   (lldb) breakpoint set -n wolfSSH_shutdown"
echo "   (lldb) breakpoint set -n wolfSSH_free"
echo "   (lldb) breakpoint set -n wolfSSH_TriggerKeyExchange"
echo ""
echo "3. Import Python callbacks for automated monitoring:"
echo "   (lldb) command script import /opt/lldb/wolfssh_client_callbacks.py"
echo "   (lldb) wolfssh_setup_monitoring"
echo "   (lldb) wolfssh_auto_continue"
echo ""
echo "4. Test file trigger for PRE_SESSION_CLOSE dump:"
echo "   (lldb) process interrupt"
echo "   (lldb) platform shell touch /tmp/lldb_dump_pre_exit"
echo "   (lldb) platform shell ls -la /tmp/lldb_dump_pre_exit"
echo "   (lldb) continue  # LLDB will detect file and trigger dump"
echo ""
echo "5. Examine state when stopped:"
echo "   (lldb) bt                         # Backtrace"
echo "   (lldb) frame variable             # Local variables"
echo "   (lldb) register read              # CPU registers"
echo "   (lldb) memory read <addr>         # Memory at address"
echo ""
echo "6. Check state machine status:"
echo "   (lldb) script"
echo "   >>> import wolfssh_client_callbacks"
echo "   >>> if wolfssh_client_callbacks._state_machine:"
echo "   ...     print(f\"State: {wolfssh_client_callbacks._state_machine.current_state}\")"
echo "   >>> quit()"
echo ""
echo "7. Step through code:"
echo "   (lldb) step                       # Step into"
echo "   (lldb) next                       # Step over"
echo "   (lldb) finish                     # Step out"
echo ""
echo "8. Manual memory dumps (available immediately):"
echo "   (lldb) d                            # Quick dump (one-letter)"
echo "   (lldb) dump post_kex                # Named dump"
echo "   (lldb) manual_dump_now after_rekey  # Full-featured"
echo ""
echo "9. Watchpoint management (NEW - runtime control):"
echo "   (lldb) watchpoints_toggle           # Enable/disable all watchpoints"
echo "   (lldb) watchpoints_status           # Show current state and count"
echo "   (lldb) watchpoints_list             # Detailed list with addresses"
echo "   "
echo "   # Example workflow:"
echo "   (lldb) watchpoints_status           # Check current state"
echo "   (lldb) watchpoints_toggle           # Disable to avoid noise"
echo "   (lldb) continue                     # Run without watchpoints"
echo "   (lldb) watchpoints_toggle           # Re-enable for next KEX"
echo "   (lldb) watchpoints_list             # Inspect active watchpoints"
echo ""
echo "10. Exit LLDB:"
echo "   (lldb) quit"
echo ""
echo "========================================================================"
echo ""
read -p "Press Enter to start interactive LLDB session..."

# Execute in container with interactive LLDB
docker compose run --rm \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_ENABLE_WATCHPOINTS=true \
    -e LLDB_ENABLE_ENTRY_DUMPS=true \
    -e LLDB_ENTRY_DUMP_FUNCTIONS=all \
    wolfssh_client bash -c "
    echo ''
    echo '=== Starting Interactive LLDB for wolfSSH Client ==='
    echo ''
    echo \"Binary: ${CLIENT_BINARY} (custom lifecycle client ${CLIENT_VERSION})\"
    echo \"Server: ${SERVER}:${SERVER_PORT}\"
    echo ''
    echo 'The client will be launched with these parameters:'
    echo \"  - ${SERVER} (server host)\"
    echo \"  - ${SERVER_PORT} (port)\"
    echo '  - testuser (username)'
    echo '  - password (password)'
    echo '  - --with-rekey (enables programmatic rekey via TriggerKeyExchange)'
    echo ''
    echo 'Breakpoints will be automatically set on:'
    echo '  - wolfSSH_KDF (key derivation - called 4 times per KEX: A-D)'
    echo '  - wolfSSH_shutdown (session close detection)'
    echo '  - wolfSSH_free (cleanup detection)'
    echo ''
    echo 'Rekey detection hooks (enabled via wolfssh_setup_monitoring):'
    echo '  - 3 lifecycle functions: shutdown, free, trigger_kex'
    echo '  - 10 crypto functions: SendKexInit, GenerateKey, wc_* (wolfCrypt)'
    echo ''
    echo 'They will show as \"pending\" until process is launched.'
    echo ''
    echo 'Quick start:'
    echo \"  1. (lldb) process launch --stop-at-entry -- ${SERVER} ${SERVER_PORT} testuser password --with-rekey\"
    echo '  2. (lldb) wolfssh_setup_monitoring'
    echo '  3. (lldb) continue'
    echo '  4. Watch for [FUNCTION_ENTRY] messages during KEX0 (initial) and KEX2 (rekey)'
    echo ''

    # Launch LLDB with selected custom binary
    lldb -o \"file ${CLIENT_BINARY}\" \
         -o 'breakpoint set -n wolfSSH_KDF' \
         -o 'breakpoint set -n wolfSSH_shutdown' \
         -o 'breakpoint set -n wolfSSH_free' \
         -o 'command script import /opt/lldb/wolfssh_client_callbacks.py' \
         -o 'command script import /opt/lldb/manual_dump_helper.py'
"

echo ""
echo "========================================================================"
echo "  Interactive Session Ended"
echo "========================================================================"
