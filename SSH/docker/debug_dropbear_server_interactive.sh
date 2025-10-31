#!/bin/bash
#
# Interactive LLDB Session for Dropbear SSH Server Debugging
# Opens an LLDB session with dual key extraction (gen_new_keys + hashkeys)
#
# Features:
# - Fork tracking (follows first fork only - connection handler)
# - Dual extraction: gen_new_keys() + hashkeys() validation
# - Watchpoints disabled by default (enable with watchpoints_toggle)
# - Manual dump commands (d, dump, manual_dump_now)
# - Server-specific keylog: dropbear_server_keylog.log
#

# Default settings
WITH_REKEY=0
AUTO_DISABLE_BREAKPOINTS=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-rekey|--rekey)
            WITH_REKEY=1
            shift
            ;;
        --no-auto-disable|--keep-breakpoints)
            AUTO_DISABLE_BREAKPOINTS=false
            shift
            ;;
        --auto-disable)
            AUTO_DISABLE_BREAKPOINTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --with-rekey, --rekey          Enable rekey testing (client triggers)"
            echo "  --no-auto-disable              Keep breakpoints active after KEX"
            echo "  --keep-breakpoints             (same as --no-auto-disable)"
            echo "  --auto-disable                 Auto-disable breakpoints after KEX (default)"
            echo "  -h, --help                     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                             # Base lifecycle (auto-disable ON)"
            echo "  $0 --with-rekey                # Full lifecycle with rekey"
            echo "  $0 --no-auto-disable           # Keep breakpoints for debugging"
            echo ""
            echo "Breakpoint Behavior:"
            echo "  Default (--auto-disable): Breakpoints disabled after KEX extraction"
            echo "    ✓ Allows normal interactive session (fork #2 proceeds)"
            echo "    ✓ Recommended for interactive SSH connections"
            echo ""
            echo "  With --no-auto-disable: Breakpoints remain active"
            echo "    ⚠ May interfere with fork #2 (session handler)"
            echo "    ✓ Useful for debugging additional events after KEX"
            echo ""
            echo "Note: Server starts in foreground. Connect from host:"
            echo "  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\"
            echo "      -p 2223 testuser@localhost"
            echo "  Password: password"
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
echo "  Dropbear Server - Interactive LLDB Debugging (v5.0 Dual Extraction)"
echo "========================================================================"
echo ""
echo "Configuration:"
echo "  Rekey: $([ $WITH_REKEY -eq 1 ] && echo 'ENABLED (client triggers)' || echo 'disabled')"
echo "  Auto-disable breakpoints: $([ "$AUTO_DISABLE_BREAKPOINTS" = true ] && echo 'ENABLED (recommended)' || echo 'DISABLED')"
echo "  Fork tracking: Follow first fork only (connection handler)"
echo "  Extraction: DUAL (gen_new_keys + hashkeys validation)"
echo "  Watchpoints: DISABLED by default (toggle in LLDB)"
echo ""
echo "IMPORTANT: Dropbear server characteristics:"
echo "  ✓ Two forks: #1 connection handler (FOLLOW), #2 auth process (STOP)"
echo "  ✓ Dual extraction validates KDF derivation"
echo "  ✓ Keys logged to: data/keylogs/dropbear_server_keylog.log"
echo "  ✓ Timing data: data/lldb_results/timing_dropbear_server.csv"
echo ""
echo "This script will:"
echo "  1. Launch Dropbear server in foreground mode (-F)"
echo "  2. Attach LLDB with dual extraction callbacks"
echo "  3. Set breakpoints: fork, gen_new_keys, hashkeys"
echo "  4. Drop you into an interactive LLDB session"
echo ""
echo "You can then:"
echo "  - (lldb) process launch"
echo "  - (lldb) server_setup_monitoring"
echo "  - (lldb) server_auto_continue"
if [ $WITH_REKEY -eq 1 ]; then
    echo "  - Connect with client and trigger rekey"
fi
echo "  - Use manual commands: d, dump, watchpoints_toggle, etc."
echo ""
echo "========================================================================"
echo ""
read -p "Press Enter to start interactive LLDB session..."

# Ensure dropbear_server service is NOT running (we'll start in LLDB)
echo "Stopping any existing dropbear_server container..."
docker compose stop dropbear_server 2>/dev/null || true
sleep 2

echo ""
echo "Entering Dropbear server container with interactive LLDB..."
echo ""
echo "========================================================================"
echo "  LLDB Commands You Can Use:"
echo "========================================================================"
echo ""
echo "1. Launch Dropbear server (foreground mode):"
echo "   (lldb) process launch --stop-at-entry -- -F -E -p 22 \\"
echo "          -r /etc/dropbear/dropbear_rsa_host_key"
echo ""
echo "2. Setup monitoring and start:"
echo "   (lldb) server_setup_monitoring"
echo "   (lldb) server_auto_continue"
echo ""
echo "3. Manual breakpoints (already set by server_setup_monitoring):"
echo "   (lldb) breakpoint set -n fork              # Fork tracking"
echo "   (lldb) breakpoint set -n gen_new_keys      # Primary extraction"
echo "   (lldb) breakpoint set -n hashkeys          # KDF validation"
echo ""
echo "4. Examine fork behavior:"
echo "   (lldb) process status                      # Check current process"
echo "   (lldb) thread list                         # Show all threads"
echo "   # Fork #1 will show connection handler"
echo "   # Fork #2 NOT followed (LLDB config)"
echo ""
echo "5. Dual extraction monitoring:"
echo "   # gen_new_keys: Extracts 6 keys (A-F) from ses.newkeys"
echo "   # hashkeys: Called 6 times (A-F) for KDF validation"
echo "   # Both extractions compared automatically"
echo ""
echo "6. Examine extraction at breakpoints:"
echo "   (lldb) frame variable                      # Local variables"
echo "   (lldb) bt                                  # Backtrace"
echo ""
echo "   # At gen_new_keys exit:"
echo "   (lldb) script"
echo "   >>> _gen_new_keys_data  # Extracted keys"
echo "   >>> quit()"
echo ""
echo "   # At hashkeys:"
echo "   (lldb) frame variable keybuf keylen letter"
echo "   (lldb) memory read -c 32 <keybuf_addr>     # Read derived key"
echo ""
echo "7. Manual memory dumps:"
echo "   (lldb) d                            # Quick dump (one-letter)"
echo "   (lldb) dump post_kex                # Named dump"
echo "   (lldb) dump server_session_start    # Custom label"
echo ""
echo "8. Search for keys in memory:"
echo "   (lldb) findkey <hex_string>         # Search for key pattern"
echo "   (lldb) findkey 1a2b3c4d5e6f...      # Example: 32-byte key"
echo "   "
echo "   # Use case: Verify keys are present after extraction"
echo "   # The command will search all memory regions and report matches"
echo ""
echo "8. Watchpoint management (runtime control):"
echo "   (lldb) watchpoints_toggle           # Enable/disable all"
echo "   (lldb) watchpoints_status           # Show current state"
echo "   (lldb) watchpoints_list             # Detailed list"
echo "   "
echo "   # Example workflow:"
echo "   (lldb) watchpoints_status           # Check (disabled by default)"
echo "   (lldb) watchpoints_toggle           # Enable for testing"
echo "   (lldb) continue                     # Run with watchpoints"
echo "   (lldb) watchpoints_toggle           # Disable to avoid noise"
echo ""
echo "9. Connect client (from another terminal):"
if [ $WITH_REKEY -eq 1 ]; then
    echo "   # Use Dropbear client with rekey wrapper:"
    echo "   docker compose run --rm dropbear_client \\"
    echo "       /usr/local/bin/dropbear_client_rekey \\"
    echo "       localhost 2223 testuser password --with-rekey"
else
    echo "   # Use standard Dropbear client:"
    echo "   docker compose run --rm --entrypoint "" dropbear_client \\"
    echo "       dbclient -y -p 2223 testuser@host.docker.internal"
    echo "   # Or from host:"
    echo "   dbclient -y -p 2223 testuser@localhost"
fi
echo ""
echo "10. Step through code:"
echo "   (lldb) step                         # Step into"
echo "   (lldb) next                         # Step over"
echo "   (lldb) finish                       # Step out"
echo "   (lldb) continue                     # Resume"
echo ""
echo "11. Debug fork-following (if issues):"
echo "   (lldb) settings show target.process.follow-fork-mode"
echo "   (lldb) process status               # Check PID"
echo "   (lldb) image list                   # Loaded binaries"
echo ""
echo "12. Exit LLDB:"
echo "   (lldb) quit"
echo ""
echo "========================================================================"
echo ""
echo "Dropbear Server Key Extraction Points:"
echo "  - gen_new_keys()  : Primary - extract 6 keys (A-F) from ses.newkeys"
echo "  - hashkeys()      : Validation - capture KDF parameters (called 6x)"
echo ""
echo "Keys extracted (per KEX):"
echo "  Key A: IV client→server"
echo "  Key B: IV server→client  "
echo "  Key C: Encryption client→server"
echo "  Key D: Encryption server→client"
echo "  Key E: MAC client→server"
echo "  Key F: MAC server→client"
echo ""
echo "Fork Behavior:"
echo "  Fork #1: Connection handler (LLDB follows this)"
echo "  Fork #2: Auth/session process (LLDB does NOT follow)"
echo ""
echo "========================================================================"
echo ""
read -p "Press Enter to launch LLDB..."

# Execute in container with interactive LLDB
docker compose run --rm --service-ports \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_ENABLE_WATCHPOINTS=false \
    -e LLDB_AUTO_DISABLE_BREAKPOINTS=$AUTO_DISABLE_BREAKPOINTS \
    -e LLDB_KEYLOG=/data/keylogs/dropbear_server_keylog.log \
    dropbear_server bash -c "
    echo ''
    echo '=== Starting Interactive LLDB for Dropbear Server (v5.0) ==='
    echo ''
    echo 'NOTE: Server will launch in foreground mode'
    echo '  Binary: /usr/sbin/dropbear'
    echo '  Port: 2223'
    echo '  Foreground: -F (required for LLDB)'
    echo '  Stderr: -E (show errors)'
    echo '  Host key: /etc/dropbear/dropbear_rsa_host_key'
    echo '  Extraction: DUAL (gen_new_keys + hashkeys)'
    echo '  Fork tracking: Follow first fork only'
    echo ''
    echo 'Breakpoints will be automatically set on:'
    echo '  - fork() - Track fork count'
    echo '  - gen_new_keys() - Primary key extraction (entry+exit)'
    echo '  - hashkeys() - KDF validation (entry+exit, called 6x)'
    echo ''
    echo 'Quick start:'
    echo '  1. (lldb) process launch --stop-at-entry -- -F -E -p 22 -r /etc/dropbear/dropbear_rsa_host_key'
    echo '  2. (lldb) server_setup_monitoring'
    echo '  3. (lldb) server_auto_continue'
    echo '  4. Connect client from another terminal'
    echo ''
    echo 'Keylog output: /data/keylogs/dropbear_server_keylog.log'
    echo 'Timing data: /data/lldb_results/timing_dropbear_server.csv'
    echo ''

    # Launch LLDB with Dropbear server
    lldb -o 'file /usr/sbin/dropbear' \
         -o 'settings set target.process.follow-fork-mode child' \
         -o 'settings set target.process.stop-on-exec false' \
         -o 'process handle SIGCHLD -s false -p true -n false' \
         -o 'process launch --stop-at-entry -- -F -E -p 22 -r /etc/dropbear/dropbear_rsa_host_key' \
         -o 'breakpoint set -n fork' \
         -o 'breakpoint set -n gen_new_keys' \
         -o 'breakpoint set -n hashkeys' \
         -o 'command script import /opt/lldb/manual_dump_helper.py' \
         -o 'command script import /opt/lldb/dropbear_server_callbacks.py'
"

echo ""
echo "========================================================================"
echo "  Interactive Session Ended"
echo "========================================================================"
echo ""
echo "Output files:"
echo "  Keylog: data/keylogs/dropbear_server_keylog.log"
echo "  Timing: data/lldb_results/timing_dropbear_server.csv"
echo "  Dumps:  data/dumps/*dropbear_server*.dump"
echo ""
