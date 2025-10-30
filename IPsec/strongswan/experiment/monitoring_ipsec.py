#!/usr/bin/env python3
"""
monitoring_ipsec.py

LLDB monitoring script for strongSwan/charon IPsec key lifecycle tracking

Usage:
    lldb -p <charon_pid> -o "command script import monitoring_ipsec.py"

Or from experiment orchestration script

Supports: x86_64, aarch64
Tracks: IKE handshake keys (SK_*) and ESP keys (ENCR_*, INTEG_*)
"""
import lldb
import os
import sys
from datetime import datetime

# Configuration from environment or defaults
NETNS = os.environ.get("IPSEC_NETNS", "left")
OUTPUT_DIR = os.environ.get("IPSEC_OUTPUT_DIR", f"./results/{datetime.now().strftime('%Y%m%d_%H%M%S')}")
EXPERIMENT_MODE = os.environ.get("IPSEC_MODE", "interactive")  # or "batch"

# Import shared utilities
sys.path.insert(0, os.path.dirname(__file__))
from shared_ipsec import (
    ArchitectureHelper,
    MemoryDumper,
    EventLogger,
    TimingLogger,
    get_process_info
)
import strongswan_callbacks


# Function name to callback mapping
# Only use VERIFIED breakpoints that exist in this strongSwan build:
# - ike_derived_keys: libcharon.so.0 (IKE SA key derivation)
# - child_keys: libcharon.so.0 (CHILD_SA nonce extraction)
# - child_derived_keys: libcharon.so.0 (CHILD_SA/ESP derived keys - encr_i/r, integ_i/r)
# - chunk_split: libstrongswan.so.0 (chunk_t extraction - fallback/verification)
# - Lifecycle functions: terminate/rekey operations
BREAKPOINT_MAP = {
    # IKE key derivation (primary - libcharon.so.0)
    "ike_derived_keys": strongswan_callbacks.ike_derived_keys_callback,

    # CHILD_SA key derivation (ESP/AH keys - libcharon.so.0)
    "child_keys": strongswan_callbacks.child_keys_callback,
    "child_derived_keys": strongswan_callbacks.child_derived_keys_callback,

    # PRF operations (SKEYSEED tracking - libstrongswan.so.0)
    "set_key": strongswan_callbacks.prf_set_key_callback,
    "prf_plus_create": strongswan_callbacks.prf_plus_create_callback,

    # Chunk operations (fallback/verification - libstrongswan.so.0)
    "chunk_split": strongswan_callbacks.chunk_split_callback,

    # Lifecycle functions - terminate operations
    # These may or may not exist in all strongSwan builds - will be checked at runtime
    "terminate_child_execute": strongswan_callbacks.terminate_child_execute_callback,
    "terminate_ike_execute": strongswan_callbacks.terminate_ike_execute_callback,

    # State change functions
    "ike_state_change_terminate": strongswan_callbacks.ike_state_change_terminate_callback,
    "child_state_change_terminate": strongswan_callbacks.child_state_change_terminate_callback,

    # Rekey operations
    "ike_rekey": strongswan_callbacks.ike_rekey_callback,
    "child_rekey": strongswan_callbacks.child_rekey_callback,
}


def setup_monitoring(debugger):
    """Main setup function called when script is loaded"""
    print("=" * 70)
    print("strongSwan/charon LLDB Monitoring")
    print("Tracking IKE and ESP key lifecycle")
    print("=" * 70)

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        print("[ERROR] No target process attached")
        return

    process = target.GetProcess()
    if not process or not process.IsValid():
        print("[ERROR] No valid process")
        return

    # Display process info
    info = get_process_info(process)
    print(f"\nProcess Info:")
    print(f"  PID: {info['pid']}")
    print(f"  Name: {info['name']}")
    print(f"  Architecture: {info['architecture']}")
    print(f"  Threads: {info['num_threads']}")
    print(f"  Network Namespace: {NETNS}")

    # Setup output directory (OUTPUT_DIR already points to the correct location)
    userspace_dir = OUTPUT_DIR
    os.makedirs(userspace_dir, exist_ok=True)
    print(f"  Output: {userspace_dir}")

    # Initialize dumper, logger, keylog writer, and timing logger
    dumper = MemoryDumper(process, userspace_dir)
    logger = EventLogger(userspace_dir)
    from shared_ipsec import KeylogWriter
    keylog_writer = KeylogWriter(userspace_dir)
    timing_logger = TimingLogger(userspace_dir)

    # Set global handlers in callbacks module
    strongswan_callbacks.set_global_handlers(dumper, logger, keylog_writer, timing_logger)

    # Take initial memory dump
    print("\n[*] Taking initial memory dump...")
    dumper.dump_full_memory("init")
    logger.log_event("monitoring_start", {
        "pid": info['pid'],
        "architecture": info['architecture'],
        "netns": NETNS
    })

    # Setup breakpoints
    print("\n[*] Setting up breakpoints...")
    bp_count = 0
    for func_name, callback in BREAKPOINT_MAP.items():
        bp = target.BreakpointCreateByName(func_name)
        if bp and bp.GetNumLocations() > 0:
            # CRITICAL: Inject callback wrapper into THIS module's global namespace
            # LLDB can only find callbacks in the importing module's globals, not in
            # external modules like strongswan_callbacks
            # This is why breakpoints were hitting but callbacks weren't running!

            # Create a unique wrapper name for this breakpoint
            wrapper_name = f"_bp_{bp.GetID()}_{func_name}_wrapper"

            # Create wrapper function that calls the actual callback
            # This is necessary because LLDB can't resolve "strongswan_callbacks.func"
            def make_wrapper(actual_callback):
                def wrapper(frame, bp_loc, internal_dict):
                    return actual_callback(frame, bp_loc, internal_dict)
                return wrapper

            # Inject wrapper into this module's global namespace
            wrapper_func = make_wrapper(callback)
            globals()[wrapper_name] = wrapper_func

            # Register wrapper with LLDB using just the function name (no module prefix)
            bp.SetScriptCallbackFunction(f"monitoring_ipsec.{wrapper_name}")
            bp.SetAutoContinue(True)  # Don't stop execution - just run callback and continue

            print(f"  ✓ Breakpoint {bp.GetID()}: {func_name} -> {callback.__name__}")
            print(f"     Callback: monitoring_ipsec.{wrapper_name}")
            bp_count += 1
        else:
            print(f"  ✗ Failed: {func_name} (symbol not found)")

    if bp_count == 0:
        print("\n[WARNING] No breakpoints set! Possible reasons:")
        print("  - Binary is stripped (no symbols)")
        print("  - Function names don't match this strongSwan version")
        print("  - Debug info not loaded")
        print("\nContinuing anyway - you may need to set breakpoints manually.")
    else:
        print(f"\n[SUCCESS] Set {bp_count} breakpoints")

    # Set LLDB target and debugger for watchpoint management
    print("\n[*] Enabling hardware watchpoint support...")
    strongswan_callbacks.set_target(target, debugger)
    print("[SUCCESS] Watchpoints enabled - will track sk_ei, sk_er, ENCR_i, ENCR_r")

    print("\n" + "=" * 70)
    print("Monitoring active.")
    print("Breakpoints will trigger on key events.")
    print("Process continuation is handled by shell script's '-o continue' command.")
    print("=" * 70)
    print()

    # NOTE: Process continuation is now handled by the shell script's `-o "continue"` command
    # This follows the working pattern from research_experiment/run_lldb_on_charon_processes.sh
    # The script does: lldb -o "import script" -o "attach -p PID" -o "continue"
    # So we do NOT call process.Continue() here - it will be called automatically

    print(f"[SUCCESS] Monitoring setup complete for process {info['pid']}")

    # NOTE: Keep-alive behavior depends on mode:
    # - interactive: No keep-alive, user controls LLDB manually
    # - automated/batch: Keep-alive loop to keep LLDB alive (prevents charon crash)
    #
    # The keep-alive loop is CRITICAL for batch mode because:
    # - When Python script exits, LLDB detaches
    # - When LLDB detaches, attached process can crash
    # - We create readiness marker BEFORE the loop via ipsec_auto_continue command


def ipsec_setup_monitoring_command(debugger, command, result, internal_dict):
    """Custom LLDB command to set up IPsec monitoring after attaching to process

    This command is called AFTER the process is attached, ensuring that
    a valid target exists when we try to set up breakpoints.

    Usage:
        (lldb) ipsec_setup_monitoring
    """
    try:
        print("\n" + "=" * 70)
        print("IPsec Monitoring Setup")
        print("=" * 70)
        print()

        setup_monitoring(debugger)

    except Exception as e:
        print(f"[FATAL] Monitoring setup failed: {e}")
        import traceback
        traceback.print_exc()
        print("[ERROR] Process remains stopped - use 'continue' to resume it")


def ipsec_auto_continue_command(debugger, command, result, internal_dict):
    """Auto-continue with a smooth delay to see setup messages

    Usage:
        (lldb) ipsec_auto_continue [delay_seconds]

    Default delay is 2 seconds.
    """
    import time

    # Parse delay from command argument (default 2 seconds)
    try:
        delay = float(command.strip()) if command.strip() else 2.0
    except ValueError:
        delay = 2.0

    print("\n" + "=" * 70)
    print(f"Auto-continuing in {delay} seconds...")
    print("(Press Ctrl+C to cancel and stay in LLDB prompt)")
    print("=" * 70)

    try:
        time.sleep(delay)

        # Get the process and continue
        target = debugger.GetSelectedTarget()
        if target and target.IsValid():
            process = target.GetProcess()
            if process and process.IsValid():
                # CRITICAL: Create readiness marker BEFORE continuing process
                # This prevents timeout in shell script during callback execution
                try:
                    readiness_file = os.path.join(OUTPUT_DIR, f".lldb_ready_{NETNS}")
                    with open(readiness_file, 'w') as f:
                        f.write(f"ready\npid={process.GetProcessID()}\nnetns={NETNS}\nmode={EXPERIMENT_MODE}\n")
                    print(f"[*] Readiness marker created: {readiness_file}")
                except Exception as e:
                    print(f"[WARNING] Failed to create readiness marker: {e}")
                    # Non-fatal - continue anyway

                print("\n[*] Continuing process execution...")
                process.Continue()
                print("[SUCCESS] Process running - breakpoints will fire on key events")

                # CRITICAL: Enter keep-alive loop for ALL modes (automated, batch, AND interactive)
                # This keeps LLDB attached and prevents charon from crashing
                # More importantly: keeps LLDB in script mode so SetAutoContinue(True) works correctly
                if EXPERIMENT_MODE in ["automated", "batch", "interactive"]:
                    print(f"\n[*] Entering keep-alive loop (mode={EXPERIMENT_MODE})")
                    if EXPERIMENT_MODE == "interactive":
                        print("[*] Running in interactive mode - breakpoints will auto-continue")
                        print("[*] Check tmux window for callback output")
                    else:
                        print("[*] This keeps LLDB attached to prevent process crash")
                        print("[*] Breakpoints will fire and log events automatically")
                    print("[*] Press Ctrl+C to detach and exit\n")

                    import time
                    import sys
                    sys.stdout.flush()  # Ensure all output is written

                    try:
                        while process.IsValid() and process.GetState() != lldb.eStateExited:
                            # Log process state periodically (every 30 seconds)
                            import datetime
                            if not hasattr(ipsec_auto_continue_command, 'last_state_log'):
                                ipsec_auto_continue_command.last_state_log = 0
                                # Set to -31 so first write happens immediately (within 1 second)
                                ipsec_auto_continue_command.last_keylog_write = -31

                            now = time.time()

                            # Periodic keylog writing (every 5 seconds)
                            # This is done outside of callbacks to avoid LLDB state corruption
                            if now - ipsec_auto_continue_command.last_keylog_write > 5:
                                try:
                                    import strongswan_callbacks
                                    if strongswan_callbacks._keylog_writer:
                                        strongswan_callbacks._keylog_writer.write_keylogs()
                                        timestamp = datetime.datetime.now().isoformat()
                                        print(f"[{timestamp}] Periodic keylog write complete")
                                        sys.stdout.flush()
                                    ipsec_auto_continue_command.last_keylog_write = now
                                except Exception as e:
                                    print(f"[WARNING] Periodic keylog write failed: {e}")
                                    import traceback
                                    traceback.print_exc()

                            # Check for manual dump request marker file
                            # This allows external scripts to trigger dumps via marker files
                            try:
                                import strongswan_callbacks
                                marker_file = os.path.join(OUTPUT_DIR, ".dump_request")
                                if os.path.exists(marker_file):
                                    # Read checkpoint name from marker file
                                    checkpoint_name = "manual"
                                    try:
                                        with open(marker_file, 'r') as f:
                                            for line in f:
                                                if line.startswith("checkpoint="):
                                                    checkpoint_name = line.split("=", 1)[1].strip()
                                                    break
                                    except Exception:
                                        pass  # Use default if read fails

                                    # Trigger the dump
                                    timestamp = datetime.datetime.now().isoformat()
                                    print(f"[{timestamp}] Dump request detected: {checkpoint_name}")
                                    strongswan_callbacks.manual_dump(checkpoint_name)

                                    # Remove marker file after processing
                                    try:
                                        os.remove(marker_file)
                                        print(f"[{timestamp}] Dump request processed and marker removed")
                                    except Exception as e:
                                        print(f"[WARNING] Failed to remove dump marker: {e}")

                                    sys.stdout.flush()
                            except Exception as e:
                                print(f"[WARNING] Dump request check failed: {e}")
                                import traceback
                                traceback.print_exc()

                            # CRITICAL: Ensure process is running (handle cases where SetAutoContinue doesn't work)
                            # This is especially important in interactive mode
                            current_state = process.GetState()
                            if current_state == lldb.eStateStopped:
                                # Process stopped (probably by breakpoint) - continue it
                                process.Continue()
                                timestamp = datetime.datetime.now().isoformat()
                                print(f"[{timestamp}] [AUTO-RESUME] Process was STOPPED, continuing...")
                                sys.stdout.flush()

                            # Periodic state logging (every 30 seconds)
                            if now - ipsec_auto_continue_command.last_state_log > 30:
                                state_name = {
                                    lldb.eStateRunning: "RUNNING",
                                    lldb.eStateStopped: "STOPPED",
                                    lldb.eStateSuspended: "SUSPENDED",
                                    lldb.eStateExited: "EXITED",
                                    lldb.eStateCrashed: "CRASHED"
                                }.get(current_state, f"UNKNOWN({current_state})")

                                timestamp = datetime.datetime.now().isoformat()
                                print(f"[{timestamp}] Keep-alive: process state = {state_name}")
                                sys.stdout.flush()
                                ipsec_auto_continue_command.last_state_log = now

                            time.sleep(1)

                        # Process exited
                        state = process.GetState()
                        exit_code = process.GetExitStatus()
                        print(f"\n[*] Process exited with state={state}, code={exit_code}")

                    except KeyboardInterrupt:
                        print("\n[*] Keep-alive interrupted by user")

                    finally:
                        # Take final memory dump before exit
                        print("[*] Taking final memory dump before exit...")
                        sys.stdout.flush()
                        try:
                            import strongswan_callbacks
                            if strongswan_callbacks._dumper and not strongswan_callbacks._checkpoint_counter.get("final"):
                                strongswan_callbacks._dumper.dump_full_memory("final")
                                strongswan_callbacks._checkpoint_counter["final"] = True
                                print("[SUCCESS] Final dump complete")
                            else:
                                print("[INFO] Final dump already taken or dumper not available")
                        except Exception as e:
                            print(f"[WARNING] Final dump failed (non-fatal): {e}")

                        # Write keylogs before exiting
                        print("[*] Writing final keylogs...")
                        sys.stdout.flush()

                        # Get keylog writer from globals
                        try:
                            import strongswan_callbacks
                            if strongswan_callbacks._keylog_writer:
                                strongswan_callbacks._keylog_writer.write_keylogs()
                                print("[SUCCESS] Keylogs written")
                            else:
                                print("[WARNING] No keylog writer available")
                        except Exception as e:
                            print(f"[ERROR] Failed to write keylogs: {e}")

                        sys.stdout.flush()
                        print("[*] LLDB monitoring session ended")

            else:
                print("[ERROR] No valid process to continue")
        else:
            print("[ERROR] No valid target")

    except KeyboardInterrupt:
        print("\n[*] Auto-continue cancelled - staying at LLDB prompt")
        print("    Type 'continue' or 'c' when ready")


def __lldb_init_module(debugger, internal_dict):
    """Called automatically when script is imported by LLDB

    This function registers custom LLDB commands instead of setting up
    monitoring immediately. This allows the script to be imported before
    attaching to a process.

    The registered commands must be invoked AFTER attaching to the process.
    """
    # Register custom commands
    debugger.HandleCommand(
        'command script add -f monitoring_ipsec.ipsec_setup_monitoring_command ipsec_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f monitoring_ipsec.ipsec_auto_continue_command ipsec_auto_continue'
    )

    print("\n" + "=" * 70)
    print("IPsec Monitoring Script Loaded")
    print("=" * 70)
    print()
    print("Commands registered:")
    print("  - ipsec_setup_monitoring : Set up breakpoints and monitoring")
    print("  - ipsec_auto_continue    : Auto-continue after delay (default 2s)")
    print()
    print("IMPORTANT: These commands must be run AFTER attaching to a process!")
    print()
    print("Typical usage:")
    print("  1. Import this script")
    print("  2. Attach to process")
    print("  3. Run: ipsec_setup_monitoring")
    print("  4. Run: ipsec_auto_continue [delay]")
    print()


if __name__ == "__main__":
    print("This script should be run from LLDB using:")
    print('  lldb -o "command script import monitoring_ipsec.py" -o "process attach -p <pid>" -o "ipsec_setup_monitoring" -o "continue"')
    sys.exit(1)
