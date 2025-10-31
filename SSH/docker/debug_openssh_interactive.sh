#!/bin/bash
#
# Interactive LLDB Session for OpenSSH Client Debugging
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
            echo "  $0 --with-rekey           # Full lifecycle with rekey"
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
echo "  OpenSSH Client - Interactive LLDB Debugging (Updated 2025-10-30)"
echo "========================================================================"
echo ""
echo "Configuration:"
echo "  Rekey: $([ $WITH_REKEY -eq 1 ] && echo 'ENABLED' || echo 'disabled')"
echo ""
echo "This script will:"
echo "  1. Start the openssh_groundtruth server"
if [ $WITH_REKEY -eq 1 ]; then
    echo "  2. Launch LLDB with OpenSSH client (Expect wrapper with rekey)"
    echo "     REKEY LIMIT: 5k (5KB of data transfer triggers automatic rekey)"
    echo "     NOTE: To adjust RekeyLimit, edit openssh-client-lldb/openssh_client_rekey.exp:96"
    echo "           - Lower values (1k-2k): More frequent rekeys, may cause instability"
    echo "           - Current (5k): Balanced - triggers rekey with moderate data transfer"
    echo "           - Higher values (10k-50k): Fewer rekeys, more stable sessions"
else
    echo "  2. Launch LLDB with OpenSSH client (via sshpass, no rekey)"
fi
echo "  3. Set breakpoints on derive_key and EVP_KDF_derive"
echo "  4. Drop you into an interactive LLDB session"
echo ""
echo "You can then manually:"
echo "  - (lldb) process launch"
echo "  - (lldb) continue"
if [ $WITH_REKEY -eq 1 ]; then
    echo "  - Watch initial KEX + rekey KEX (automatic via RekeyLimit)"
fi
echo "  - Investigate breakpoints, memory, parameters, etc."
echo ""
echo "========================================================================"
echo ""

# Ensure server is running
echo "Starting openssh_groundtruth server..."
docker compose up -d openssh_groundtruth
sleep 3

echo ""
echo "Entering openssh_client_lldb container with interactive LLDB..."
echo ""
echo "========================================================================"
echo "  LLDB Commands You Can Use:"
echo "========================================================================"
echo ""
echo "1. Launch process (pre-configured with sshpass):"
echo "   (lldb) process launch"
echo "   # Connects to: testuser@openssh_groundtruth:22 with password"
echo ""
echo "2. Set breakpoints manually:"
echo "   (lldb) breakpoint set -n derive_key"
echo "   # derive_key is called 6 times per KEX (id=65-70 for A-F keys)"
echo "   (lldb) breakpoint set -n EVP_KDF_derive"
echo ""
echo "3. Continue execution:"
echo "   (lldb) continue"
echo ""
echo "4. Examine derive_key parameters (called 6 times per KEX):"
echo "   (lldb) bt                           # Backtrace"
echo "   (lldb) frame variable               # All parameters"
echo "   (lldb) frame variable id            # Key ID (65-70 = A-F)"
echo "   (lldb) frame variable need          # Bytes needed"
echo "   (lldb) frame variable keyp          # Output pointer address"
echo "   (lldb) register read                # CPU registers"
echo "   "
echo "   # On ARM64, parameters are in x0-x6:"
echo "   (lldb) register read x0             # ssh pointer"
echo "   (lldb) register read w1             # id (65=A, 66=B, ...70=F)"
echo "   (lldb) register read w2             # need (bytes)"
echo "   (lldb) register read x3             # hash"
echo "   (lldb) register read w4             # hashlen"
echo "   (lldb) register read x5             # shared_secret (sshbuf*)"
echo "   (lldb) register read x6             # keyp (u_char**)"
echo "   "
echo "   # On x86-64, parameters are in rdi, esi, edx, rcx, r8d, r9, [rsp+8]:"
echo "   (lldb) register read rdi            # ssh pointer"
echo "   (lldb) register read esi            # id"
echo "   (lldb) register read edx            # need"
echo "   (lldb) register read rcx            # hash"
echo "   (lldb) register read r8d            # hashlen"
echo "   (lldb) register read r9             # shared_secret"
echo "   (lldb) memory read -f x -c 1 \`$rsp+8\`  # keyp (7th param on stack)"
echo ""
echo "5. Extract key AFTER derive_key returns:"
echo "   (lldb) finish                       # Step out of derive_key"
echo "   # Now *keyp points to the allocated key buffer"
echo "   (lldb) memory read -f x -c 1 <keyp_addr>     # Dereference keyp"
echo "   (lldb) memory read -c 64 <key_buffer_addr>   # Read actual key"
echo "   "
echo "   # ID mapping (RFC 4253):"
echo "   # 65 (A) = IV client→server"
echo "   # 66 (B) = IV server→client"
echo "   # 67 (C) = Encryption key client→server"
echo "   # 68 (D) = Encryption key server→client"
echo "   # 69 (E) = MAC key client→server"
echo "   # 70 (F) = MAC key server→client"
echo ""
echo "6. Step through code:"
echo "   (lldb) step                         # Step into"
echo "   (lldb) next                         # Step over"
echo "   (lldb) finish                       # Step out"
echo ""
echo "7. Import Python callbacks (hybrid derive_key extraction):"
echo "   (lldb) command script import /opt/lldb/openssh_client_callbacks.py"
echo "   (lldb) openssh_setup_monitoring"
echo "   (lldb) openssh_auto_continue"
echo "   "
echo "   # Then check keylogs at:"
echo "   # /data/keylogs/openssh_client_keylog.log      (6 keys per KEX: A-F)"
echo "   # /data/keylogs/openssh_client_keylog_debug.log  (+ shared secrets)"
echo ""
echo "8. Manual memory dumps (available immediately):"
echo "   (lldb) d                            # Quick dump (one-letter)"
echo "   (lldb) dump post_kex                # Named dump"
echo "   (lldb) manual_dump_now after_rekey  # Full-featured"
echo ""
echo "9. Test hybrid extraction manually:"
echo "   # At derive_key entry:"
echo "   (lldb) script"
echo "   >>> import sys"
echo "   >>> sys.path.insert(0, '/opt/lldb')"
echo "   >>> from ssh_extraction_utils import *"
echo "   >>> target = lldb.debugger.GetSelectedTarget()"
echo "   >>> frame = lldb.thread.GetFrameAtIndex(0)"
echo "   >>> process = target.GetProcess()"
echo "   >>> result = extract_derive_key_params_hybrid_aarch64(frame)  # or _x86_64(frame, process)"
echo "   >>> print(result)  # Shows id, need, keyp, shared_secret, method"
echo "   >>> quit()"
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
read -p "Press Enter to start interactive LLDB session..."

# Execute in container with interactive LLDB
if [ $WITH_REKEY -eq 1 ]; then
    # Rekey mode: Use Expect wrapper
    docker compose run --rm openssh_client_lldb bash -c "
        echo ''
        echo '=== Starting Interactive LLDB for OpenSSH Client (WITH REKEY) ==='
        echo ''
        echo 'NOTE: Process will launch via Expect wrapper with rekey support'
        echo '  Host: openssh_groundtruth'
        echo '  Port: 22'
        echo '  User: testuser'
        echo '  Password: password'
        echo '  Rekey: ENABLED (automatic via RekeyLimit=5k)'
        echo '  NOTE: To adjust RekeyLimit, edit openssh-client-lldb/openssh_client_rekey.exp:96'
        echo ''
        echo 'Breakpoints will be automatically set on:'
        echo '  - derive_key (called 6 times per KEX for A-F keys)'
        echo '  - EVP_KDF_derive (OpenSSL 3.0+ KDF function - fallback)'
        echo ''
        echo 'They will show as \"pending\" until process is launched.'
        echo ''
        echo 'IMPORTANT: To see hybrid extraction in action, use:'
        echo '  (lldb) command script import /opt/lldb/openssh_client_callbacks.py'
        echo '  (lldb) openssh_setup_monitoring'
        echo '  (lldb) openssh_auto_continue'
        echo ''

        # Launch LLDB with Expect wrapper
        lldb -o 'file /usr/bin/expect' \
             -o 'settings set target.process.follow-fork-mode child' \
             -o 'process launch --stop-at-entry -- /usr/local/bin/openssh_client_rekey openssh_groundtruth 22 testuser password --with-rekey' \
             -o 'breakpoint set -n derive_key' \
             -o 'breakpoint set -n EVP_KDF_derive' \
             -o 'command script import /opt/lldb/manual_dump_helper.py' \
             -o 'command script import /opt/lldb/openssh_client_callbacks.py'
    "
else
    # Base mode: Use sshpass (no rekey)
    docker compose run --rm openssh_client_lldb bash -c "
        echo ''
        echo '=== Starting Interactive LLDB for OpenSSH Client (BASE MODE) ==='
        echo ''
        echo 'NOTE: Process will launch via sshpass with these parameters:'
        echo '  Host: openssh_groundtruth'
        echo '  Port: 22'
        echo '  User: testuser'
        echo '  Password: password'
        echo '  Command: hostname && pwd'
        echo '  Rekey: DISABLED'
        echo ''
        echo 'Breakpoints will be automatically set on:'
        echo '  - derive_key (called 6 times per KEX for A-F keys)'
        echo '  - EVP_KDF_derive (OpenSSL 3.0+ KDF function - fallback)'
        echo ''
        echo 'They will show as \"pending\" until process is launched.'
        echo ''
        echo 'IMPORTANT: To see hybrid extraction in action, use:'
        echo '  (lldb) command script import /opt/lldb/openssh_client_callbacks.py'
        echo '  (lldb) openssh_setup_monitoring'
        echo '  (lldb) openssh_auto_continue'
        echo ''

        # Launch LLDB with sshpass -> ssh configured
        lldb -o 'file /usr/bin/sshpass' \
             -o 'settings set target.process.follow-fork-mode child' \
             -o 'process launch --stop-at-entry -- -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 testuser@openssh_groundtruth \"hostname && pwd\"' \
             -o 'breakpoint set -n derive_key' \
             -o 'breakpoint set -n EVP_KDF_derive' \
             -o 'command script import /opt/lldb/manual_dump_helper.py' \
             -o 'command script import /opt/lldb/openssh_client_callbacks.py'
    "
fi

echo ""
echo "========================================================================"
echo "  Interactive Session Ended"
echo "========================================================================"
