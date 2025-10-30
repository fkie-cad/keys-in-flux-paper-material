#!/usr/bin/env python3
"""
monitoring_ipsec.py

LLDB monitoring script for libreswan/pluto IPsec key lifecycle tracking
with DUAL HOOK architecture (entry + exit callbacks)

Usage:
    lldb -p <pluto_pid> -o "command script import monitoring_ipsec.py"

Or from experiment orchestration script

Supports: x86_64, aarch64
Tracks: IKE handshake keys (SK_*) and ESP keys (ENCR_*, INTEG_*)

Key Features:
- Entry hooks: Capture function arguments
- Exit hooks: Capture return values (via return address breakpoints)
- Multi-strategy PK11SymKey parsing (NSS)
- Dual logging (console + file)
- Symbol-based + pattern-based breakpoints
"""
import lldb
import os
import sys
import yaml
from datetime import datetime

# Configuration from environment or defaults
NETNS = os.environ.get("IPSEC_NETNS", "left")
OUTPUT_DIR = os.environ.get("IPSEC_OUTPUT_DIR", f"./results/{datetime.now().strftime('%Y%m%d_%H%M%S')}")
EXPERIMENT_MODE = os.environ.get("IPSEC_MODE", "interactive")

# Import shared utilities
sys.path.insert(0, os.path.dirname(__file__))
from shared_ipsec import (
    ArchitectureHelper,
    MemoryDumper,
    EventLogger,
    TimingLogger,
    KeylogWriter,
    get_process_info
)

# Import libreswan-specific callbacks
import libreswan_callbacks

# Global references
_dumper = None
_logger = None


def load_config():
    """Load configuration from config.yaml"""
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    if not os.path.exists(config_path):
        print(f"[WARN] Config file not found: {config_path}")
        return {}

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            print(f"[*] Loaded config from {config_path}")
            return config
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        return {}


def get_process_architecture(process):
    """Detect process architecture (x86_64 or aarch64)"""
    target = process.GetTarget()
    triple = target.GetTriple()
    triple_str = str(triple).lower()

    if "aarch64" in triple_str or "arm64" in triple_str:
        return "aarch64"
    elif "x86_64" in triple_str or "x86-64" in triple_str:
        return "x86_64"
    else:
        return "unknown"


def find_function_by_pattern(target, module_name: str, pattern: str) -> int:
    """Find function by bytecode pattern

    Args:
        target: LLDB target
        module_name: Module name (e.g., "pluto")
        pattern: Hex byte pattern with spaces (e.g., "f3 0f 1e fa 55")

    Returns:
        Function start address or 0 if not found
    """
    # Pattern matching not implemented yet - requires memory scanning
    # For now, return 0 (symbol mode will be tried first)
    return 0


def setup_breakpoint(target, debugger, func_config: dict, func_name: str, arch: str) -> bool:
    """Set up entry (and optionally exit) breakpoints for a function

    Args:
        target: LLDB target
        debugger: LLDB debugger
        func_config: Function configuration from config.yaml
        func_name: Function name (key in config)
        arch: Architecture name ("x86_64" or "aarch64")

    Returns:
        True if breakpoint was set successfully
    """
    if not func_config.get('enabled', False):
        return False

    symbol_name = func_config.get('symbol_name', func_name)
    callbacks = func_config.get('callbacks', {})
    entry_callback = callbacks.get('entry')

    if not entry_callback:
        print(f"  [!] No entry callback defined for {func_name}")
        return False

    # Try symbol-based breakpoint first
    bp = target.BreakpointCreateByName(symbol_name)

    if not bp or not bp.IsValid() or bp.GetNumLocations() == 0:
        print(f"  [!] Symbol '{symbol_name}' not found, trying pattern mode...")

        # Try pattern-based matching
        patterns = func_config.get('patterns', {})
        pattern = patterns.get(arch)

        if not pattern:
            print(f"  [!] No pattern defined for {arch}")
            return False

        addr = find_function_by_pattern(target, "pluto", pattern)
        if addr == 0:
            print(f"  [!] Pattern matching not implemented yet")
            return False

        bp = target.BreakpointCreateByAddress(addr)

    if not bp or not bp.IsValid():
        print(f"  [!] Failed to create breakpoint for {func_name}")
        return False

    # CRITICAL: Inject callback wrapper into THIS module's global namespace
    # LLDB can only find callbacks in the importing module's globals, not in
    # external modules like libreswan_callbacks
    # This is why we need to create wrappers here

    bp_id = bp.GetID()
    wrapper_name = f"_bp_{bp_id}_{func_name}_entry_wrapper"

    # Get the actual callback function from libreswan_callbacks
    import libreswan_callbacks
    actual_callback = getattr(libreswan_callbacks, entry_callback)

    # Create wrapper function that calls the actual callback
    # Using closure to capture the actual callback
    def make_wrapper(cb):
        def wrapper(frame, bp_loc, internal_dict):
            return cb(frame, bp_loc, internal_dict)
        return wrapper

    # Inject wrapper into this module's global namespace
    wrapper_func = make_wrapper(actual_callback)
    globals()[wrapper_name] = wrapper_func

    # Set entry callback using SetScriptCallbackFunction (correct API)
    bp.SetScriptCallbackFunction(f"monitoring_ipsec.{wrapper_name}")
    bp.SetAutoContinue(True)

    # Note: Exit callback will be set dynamically by entry callback
    # using return address breakpoint mechanism

    num_locs = bp.GetNumLocations()

    print(f"  [✓] Breakpoint {bp_id}: {symbol_name} (entry)")
    print(f"      Locations: {num_locs}")
    print(f"      Entry callback: {entry_callback} -> {wrapper_name}")

    exit_callback = callbacks.get('exit')
    if exit_callback:
        print(f"      Exit callback: {exit_callback} (set dynamically at runtime)")

    return True


def setup_monitoring(debugger):
    """Main setup function called when script is loaded"""
    print("=" * 70)
    print("Libreswan/Pluto LLDB Monitoring with Dual Hooks")
    print("Entry + Exit Callbacks with Return Value Capture")
    print("=" * 70)
    print("")

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
    arch = get_process_architecture(process)

    print(f"Process Info:")
    print(f"  PID: {info['pid']}")
    print(f"  Name: {info['name']}")
    print(f"  Architecture: {arch}")
    print(f"  Threads: {info['num_threads']}")
    print(f"  Network Namespace: {NETNS}")

    # Setup output directory
    userspace_dir = OUTPUT_DIR
    os.makedirs(userspace_dir, exist_ok=True)
    print(f"  Output: {userspace_dir}")

    # Initialize dumper, logger, keylog writer, and timing logger
    global _dumper, _logger
    _dumper = MemoryDumper(process, userspace_dir)
    _logger = EventLogger(userspace_dir)
    keylog_writer = KeylogWriter(userspace_dir)
    timing_logger = TimingLogger(userspace_dir)

    # Initialize dual output logger (console + file) for manual/interactive mode
    dual_logger = None
    if EXPERIMENT_MODE in ["interactive", "manual"]:
        lldb_log_path = os.path.join(userspace_dir, "lldb_callbacks.log")
        dual_logger = libreswan_callbacks.DualOutputLogger(lldb_log_path)
        print(f"  LLDB Log: {lldb_log_path} (dual output enabled)")

    # Set global handlers in callbacks module
    libreswan_callbacks.set_global_handlers(_dumper, _logger, keylog_writer, timing_logger, dual_logger)

    # IMPORTANT: Pass target to callbacks for return breakpoint management
    libreswan_callbacks.set_target(target)

    # IMPORTANT: Pass debugger to callbacks for hardware watchpoint management
    libreswan_callbacks.set_debugger(debugger)

    # Load configuration
    config = load_config()
    functions_config = config.get('functions', {})
    monitoring_config = config.get('monitoring', {})

    # Take initial memory dump
    print("\n[*] Taking initial memory dump...")
    _dumper.dump_full_memory("init")
    _logger.log_event("monitoring_start", {
        "pid": info['pid'],
        "architecture": arch,
        "netns": NETNS,
        "checkpoint": "init",
        "mode": EXPERIMENT_MODE
    })
    print(f"[✓] Initial dump: dump_init.bin")

    # Setup breakpoints for configured functions
    print(f"\n[*] Setting up breakpoints for {arch}...")
    bp_count = 0

    for func_name, func_config in functions_config.items():
        if setup_breakpoint(target, debugger, func_config, func_name, arch):
            bp_count += 1

    if bp_count == 0:
        print("\n[WARN] No breakpoints were set!")
        print("       Check that:")
        print("       1. Symbols are available (compile pluto with -g)")
        print("       2. Or update patterns in config.yaml for your binary")
        print("\nTo extract patterns:")
        print("  objdump -d /usr/local/libexec/ipsec/pluto | grep -A20 'chunk_from_symkey'")
    else:
        print(f"\n[✓] Set {bp_count} breakpoint(s)")

    # Write readiness marker for orchestration script
    readiness_file = f"{userspace_dir}/.lldb_ready_{NETNS}"
    try:
        with open(readiness_file, 'w') as f:
            f.write(f"ready\npid={info['pid']}\nnetns={NETNS}\nmode={EXPERIMENT_MODE}\n")
        print(f"[*] Readiness marker created: {readiness_file}")
    except Exception as e:
        print(f"[WARN] Failed to create readiness marker: {e}")

    # Display monitoring status
    print("\n" + "=" * 70)
    print("Monitoring Status:")
    print(f"  Breakpoints: {bp_count} active")
    print(f"  Mode: {EXPERIMENT_MODE}")
    print(f"  Entry hooks: Capture function arguments")
    print(f"  Exit hooks: Capture return values (dynamic breakpoints)")
    print(f"  Return value capture: Enabled (ARM64: x0/x1, x86_64: rax/rdx)")
    print(f"  PK11SymKey parsing: Multi-strategy (5 offsets)")
    print(f"  File logging: {'Enabled' if dual_logger else 'Disabled'}")
    print("=" * 70)
    print("\n[✓] Monitoring ready")
    print("    Continue execution with: process continue")
    print("")


def ipsec_setup_monitoring_command(debugger, command, result, internal_dict):
    """Custom LLDB command: ipsec_setup_monitoring

    Sets up breakpoints and monitoring infrastructure.
    Must be called AFTER attaching to a process.

    Usage: (lldb) ipsec_setup_monitoring
    """
    setup_monitoring(debugger)


def ipsec_auto_continue_command(debugger, command, result, internal_dict):
    """Custom LLDB command: ipsec_auto_continue [delay]

    Auto-continues the process after a countdown, then enters keep-alive loop.

    Usage: (lldb) ipsec_auto_continue 3

    Args:
        delay: Number of seconds to wait before continuing (default: 2)
    """
    try:
        # Parse delay argument
        import time
        import sys

        delay = 2
        if command and command.strip():
            try:
                delay = int(command.strip())
            except ValueError:
                print(f"[ERROR] Invalid delay: {command}")
                print("Usage: ipsec_auto_continue [delay_in_seconds]")
                return

        # Get the process and continue
        target = debugger.GetSelectedTarget()
        if target and target.IsValid():
            process = target.GetProcess()
            if process and process.IsValid():
                # Countdown
                print(f"\n[*] Auto-continuing in {delay} seconds... (Press Ctrl+C to cancel)")
                for i in range(delay, 0, -1):
                    print(f"[*] {i}...")
                    sys.stdout.flush()
                    time.sleep(1)

                print("\n[*] Continuing process execution...")
                process.Continue()
                print("[SUCCESS] Process running - breakpoints will fire on key events")

                # Enter keep-alive loop for ALL modes
                # This keeps LLDB attached and prevents process crash
                if EXPERIMENT_MODE in ["automated", "batch", "interactive", "manual"]:
                    print(f"\n[*] Entering keep-alive loop (mode={EXPERIMENT_MODE})")
                    if EXPERIMENT_MODE in ["interactive", "manual"]:
                        print("[*] Running in interactive mode - breakpoints will auto-continue")
                        print("[*] Callback output will appear in real-time")
                    else:
                        print("[*] This keeps LLDB attached to prevent process crash")
                        print("[*] Breakpoints will fire and log events automatically")
                    print("[*] Press Ctrl+C to detach and exit\n")

                    sys.stdout.flush()

                    try:
                        # Initialize timing tracking for periodic keylog writes
                        if not hasattr(ipsec_auto_continue_command, 'last_keylog_write'):
                            ipsec_auto_continue_command.last_keylog_write = -6  # First write happens immediately

                        while process.IsValid() and process.GetState() != lldb.eStateExited:
                            time.sleep(1)  # Check every second

                            # Periodic keylog write every 5 seconds
                            # This ensures keylog files are available during execution, not just at exit
                            now = time.time()
                            if now - ipsec_auto_continue_command.last_keylog_write > 5:
                                try:
                                    import libreswan_callbacks
                                    if libreswan_callbacks._keylog_writer:
                                        libreswan_callbacks._keylog_writer.write_keylogs()
                                        timestamp = datetime.now().isoformat()
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
                                import libreswan_callbacks
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
                                    timestamp = datetime.now().isoformat()
                                    print(f"[{timestamp}] Dump request detected: {checkpoint_name}")
                                    libreswan_callbacks.manual_dump(checkpoint_name)

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

                    except KeyboardInterrupt:
                        print("\n[*] Keep-alive loop interrupted")
                        print("[*] Process is still running, but LLDB will detach")

                    finally:
                        # Write final keylogs
                        try:
                            import libreswan_callbacks
                            if libreswan_callbacks._keylog_writer:
                                libreswan_callbacks._keylog_writer.write_keylogs()
                                print("[SUCCESS] Final keylogs written")
                            else:
                                print("[WARNING] No keylog writer available")
                        except Exception as e:
                            print(f"[ERROR] Failed to write final keylogs: {e}")

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
    """Entry point when loaded with 'command script import'

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
    print("Libreswan/Pluto LLDB Monitoring Script Loaded")
    print("=" * 70)
    print()
    print("Custom commands registered:")
    print("  - ipsec_setup_monitoring")
    print("  - ipsec_auto_continue <delay>")
    print()
    print("Usage:")
    print("  1. Attach to process:  process attach -p <PID>")
    print("  2. Setup monitoring:   ipsec_setup_monitoring")
    print("  3. Auto-continue:      ipsec_auto_continue 3")
    print()
    print("=" * 70)
    print()
