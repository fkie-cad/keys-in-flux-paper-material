#!/bin/bash
#
# Interactive LLDB Session for Dropbear Client Debugging
# Opens an LLDB session with breakpoints set, allowing manual investigation
#

# Default settings
WITH_REKEY=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-rekey|--rekey)
            WITH_REKEY=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --with-rekey, --rekey     Enable rekey functionality (default: disabled)"
            echo "  -h, --help                Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                        # Base lifecycle (no rekey)"
            echo "  $0 --with-rekey           # Full lifecycle with automatic rekey"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "========================================================================"
echo "  Dropbear Client - Interactive LLDB Debugging (Updated 2025-10-30)"
echo "========================================================================"
echo ""
echo "Configuration:"
echo "  Rekey: $([ $WITH_REKEY -eq 1 ] && echo 'ENABLED' || echo 'disabled')"
echo ""
echo "Using: dbclient (via Expect wrapper - dropbear_client_rekey.exp)"
echo ""
echo "IMPORTANT: Dropbear client characteristics:"
echo "  ✓ Works with openssh_groundtruth server"
echo "  ✓ Uses gen_new_keys() instead of derive_key()"
echo "  ✓ Supports file trigger for PRE_SESSION_CLOSE dumps"
if [ $WITH_REKEY -eq 1 ]; then
    echo "  ✓ Automatic rekey after data transfer"
fi
echo ""
echo "This script will:"
echo "  1. Start openssh_groundtruth server"
echo "  2. Launch LLDB with Expect interpreter running Dropbear client"
echo "  3. Set breakpoints on gen_new_keys and session cleanup"
echo "  4. Drop you into an interactive LLDB session"
echo ""
echo "You can then manually:"
echo "  - (lldb) process launch"
echo "  - (lldb) continue"
if [ $WITH_REKEY -eq 1 ]; then
    echo "  - Watch initial KEX + automatic rekey after data transfer"
fi
echo "  - Test file trigger: platform shell touch /tmp/lldb_dump_pre_exit"
echo "  - Investigate breakpoints, memory, state transitions"
echo ""
echo "IMPORTANT: Architecture Notes"
echo "  - LLDB loads: /usr/bin/expect (the interpreter)"
echo "  - Which runs: /usr/local/bin/dropbear_client_rekey (Expect script)"
echo "  - Which spawns: /usr/bin/dbclient (actual Dropbear client binary)"
echo "  - Breakpoints target dbclient, so they show as 'pending' until fork"
echo "  - Use 'settings set target.process.follow-fork-mode child' (already set)"
echo ""
echo "========================================================================"
echo ""

# Ensure server is running
echo "Starting openssh_groundtruth server..."
docker compose up -d openssh_groundtruth
sleep 3

echo ""
echo "Entering Dropbear client container with interactive LLDB..."
echo ""
echo "========================================================================"
echo "  LLDB Commands You Can Use:"
echo "========================================================================"
echo ""
echo "1. Launch process (Expect interpreter running dropbear_client_rekey script):"
echo "   (lldb) process launch --stop-at-entry -- /usr/local/bin/dropbear_client_rekey openssh_groundtruth 22 testuser password"
echo "   (lldb) dropbear_setup_monitoring"
echo "   (lldb) continue"
echo ""
echo "2. Set breakpoints manually on Dropbear functions (will be pending until fork):"
echo "   (lldb) breakpoint set -n gen_new_keys"
echo "   (lldb) breakpoint set -n session_cleanup"
echo "   (lldb) breakpoint set -n dropbear_exit"
echo "   (lldb) breakpoint set -n m_burn"
echo ""
echo "3. Import Python callbacks for automated monitoring:"
echo "   (lldb) command script import /opt/lldb/dropbear_client_callbacks.py"
echo "   (lldb) dropbear_setup_monitoring"
echo "   (lldb) dropbear_auto_continue"
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
echo "   (lldb) process status             # Check current process"
echo ""
echo "6. Check state machine status:"
echo "   (lldb) script"
echo "   >>> import dropbear_client_callbacks"
echo "   >>> if dropbear_client_callbacks._state_machine:"
echo "   ...     print(f\"State: {dropbear_client_callbacks._state_machine.current_state}\")"
echo "   >>> quit()"
echo ""
echo "7. Debug fork-following (if dbclient not hit):"
echo "   (lldb) settings show target.process.follow-fork-mode"
echo "   (lldb) process status  # Check PID and name"
echo "   (lldb) image list      # Show loaded binaries"
echo ""
echo "8. Step through code:"
echo "   (lldb) step                       # Step into"
echo "   (lldb) next                       # Step over"
echo "   (lldb) finish                     # Step out"
echo ""
echo "9. Manual memory dumps (available immediately):"
echo "   (lldb) d                            # Quick dump (one-letter)"
echo "   (lldb) dump post_kex                # Named dump"
echo "   (lldb) manual_dump_now after_rekey  # Full-featured"
echo ""
echo "10. Watchpoint management (NEW - runtime control):"
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
echo "11. Exit LLDB:"
echo "   (lldb) quit"
echo ""
echo "========================================================================"
echo ""
echo "Dropbear-Specific Key Functions:"
echo "  - gen_new_keys()    : Called at KEX exit (extracts 6 keys: A-F)"
echo "  - session_cleanup() : Called when session closes"
echo "  - dropbear_exit()   : Called on process termination"
echo "  - m_burn()          : Dropbear's memory clearing function"
echo ""
echo "========================================================================"
echo ""
read -p "Press Enter to start interactive LLDB session..."

# Execute in container with interactive LLDB
if [ $WITH_REKEY -eq 1 ]; then
    # Rekey mode: Use Expect wrapper with rekey support
    docker compose run --rm \
        -e LLDB_ENABLE_MEMORY_DUMPS=true \
        -e LLDB_DUMP_TYPE=heap \
        -e LLDB_ENABLE_WATCHPOINTS=true \
        -e INTERACTIVE_MODE=true \
        dropbear_client bash -c "
        echo ''
        echo '=== Starting Interactive LLDB for Dropbear Client (WITH REKEY) ==='
        echo ''
        echo 'NOTE: Process will launch via Expect wrapper with rekey support'
        echo '  Target: /usr/bin/expect (running dropbear_client_rekey.exp script)'
        echo '  Binary: /usr/bin/dbclient (Dropbear SSH client, forked from Expect)'
        echo '  Server: openssh_groundtruth:22'
        echo '  Rekey: ENABLED (automatic after data transfer)'
        echo ''
        echo 'The client will be launched via Expect wrapper with these parameters:'
        echo '  - openssh_groundtruth (server host)'
        echo '  - 22 (port)'
        echo '  - testuser (username)'
        echo '  - password (password)'
        echo '  - --with-rekey (enables automatic rekey)'
        echo ''
        echo 'Breakpoints will be automatically set on:'
        echo '  - gen_new_keys (key derivation at KEX exit)'
        echo '  - session_cleanup (session close detection)'
        echo '  - dropbear_exit (cleanup detection)'
        echo ''
        echo 'They will show as \\\"pending\\\" until dbclient process is forked.'
        echo ''
        echo 'Quick start:'
        echo '  1. (lldb) process launch --stop-at-entry -- /usr/local/bin/dropbear_client_rekey openssh_groundtruth 22 testuser password --with-rekey'
        echo '  2. (lldb) dropbear_setup_monitoring'
        echo '  3. (lldb) continue'
        echo '  4. Watch initial KEX + automatic rekey after data transfer'
        echo ''

        # Launch LLDB with Expect interpreter (not the script itself)
        lldb -o 'file /usr/bin/expect' \
             -o 'settings set target.process.follow-fork-mode child' \
             -o 'process launch --stop-at-entry -- /usr/local/bin/dropbear_client_rekey openssh_groundtruth 22 testuser password --with-rekey' \
             -o 'breakpoint set -n gen_new_keys' \
             -o 'breakpoint set -n session_cleanup' \
             -o 'breakpoint set -n dropbear_exit' \
             -o 'command script import /opt/lldb/manual_dump_helper.py' \
             -o 'command script import /opt/lldb/dropbear_client_callbacks.py'
    "
else
    # Base mode: Use Expect wrapper without rekey
    docker compose run --rm \
        -e LLDB_ENABLE_MEMORY_DUMPS=true \
        -e LLDB_DUMP_TYPE=heap \
        -e LLDB_ENABLE_WATCHPOINTS=true \
        -e INTERACTIVE_MODE=true \
        dropbear_client bash -c "
        echo ''
        echo '=== Starting Interactive LLDB for Dropbear Client (BASE MODE) ==='
        echo ''
        echo 'NOTE: Process will launch via Expect wrapper (no rekey)'
        echo '  Target: /usr/bin/expect (running dropbear_client_rekey.exp script)'
        echo '  Binary: /usr/bin/dbclient (Dropbear SSH client, forked from Expect)'
        echo '  Server: openssh_groundtruth:22'
        echo '  Rekey: DISABLED'
        echo ''
        echo 'The client will be launched via Expect wrapper with these parameters:'
        echo '  - openssh_groundtruth (server host)'
        echo '  - 22 (port)'
        echo '  - testuser (username)'
        echo '  - password (password)'
        echo ''
        echo 'Breakpoints will be automatically set on:'
        echo '  - gen_new_keys (key derivation at KEX exit)'
        echo '  - session_cleanup (session close detection)'
        echo '  - dropbear_exit (cleanup detection)'
        echo ''
        echo 'They will show as \\\"pending\\\" until dbclient process is forked.'
        echo ''
        echo 'Quick start:'
        echo '  1. (lldb) process launch --stop-at-entry -- /usr/local/bin/dropbear_client_rekey openssh_groundtruth 22 testuser password'
        echo '  2. (lldb) dropbear_setup_monitoring'
        echo '  3. (lldb) continue'
        echo ''

        # Launch LLDB with Expect interpreter (not the script itself)
        lldb -o 'file /usr/bin/expect' \
             -o 'settings set target.process.follow-fork-mode child' \
             -o 'process launch --stop-at-entry -- /usr/local/bin/dropbear_client_rekey openssh_groundtruth 22 testuser password' \
             -o 'breakpoint set -n gen_new_keys' \
             -o 'breakpoint set -n session_cleanup' \
             -o 'breakpoint set -n dropbear_exit' \
             -o 'command script import /opt/lldb/manual_dump_helper.py' \
             -o 'command script import /opt/lldb/dropbear_client_callbacks.py'
    "
fi

echo ""
echo "========================================================================"
echo "  Interactive Session Ended"
echo "========================================================================"
