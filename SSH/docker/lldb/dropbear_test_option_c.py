#!/usr/bin/env python3
"""
Minimal Dropbear watchpoint test - Option C (stack variable fallback)

Tests if hardware watchpoints work AT ALL by watching a stack local variable
in a frequently-called function. No fork complexity, just pure watchpoint test.

Use this ONLY if Option B fails (watchpoint sets but never fires).
"""

import lldb
import time

# Global state
_target = None
_debugger = None
_watchpoints = {}

print(f"[OPTION_C] Loading stack variable watchpoint test")
print(f"[OPTION_C] Version: 2025.10.22-option-c-fallback")


def _set_watchpoint(key_name, address):
    """Set hardware watchpoint using EXACT IPsec pattern"""
    global _watchpoints, _target, _debugger

    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    if not _debugger or not _target:
        print(f"[WATCHPOINT] No debugger/target for {key_name}")
        return

    try:
        error = lldb.SBError()

        # Set write watchpoint on 4 bytes
        watchpoint = _target.WatchAddress(address, 4, False, True, error)

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] Failed to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()
        print(f"[WATCHPOINT] Created watchpoint ID {wp_id} for {key_name}")

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}"

        # Fixed values
        fixed_addr = address
        fixed_key_name = key_name

        # Generate callback code (IPsec pattern)
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_key_name}' at 0x{fixed_addr:x} on {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    new_data = process.ReadMemory({fixed_addr}, 16, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in new_data[:16])
        print(f"[WATCHPOINT] New value: {{data_hex}}")

    import dropbear_test_option_c
    dropbear_test_option_c._watchpoints.pop("{fixed_key_name}", None)

    return False
'''

        # Inject callback (IPsec pattern)
        _debugger.HandleCommand(f"script {callback_code}")

        # Backup
        try:
            exec(callback_code, globals())
        except:
            pass

        # Attach callback
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # Store watchpoint info
        _watchpoints[key_name] = (wp_id, address)

        print(f"[WATCHPOINT] Set on {key_name} at 0x{address:x} (wp {wp_id})")

    except Exception as e:
        print(f"[WATCHPOINT] Exception: {e}")
        import traceback
        traceback.print_exc()


def svr_dropbear_log_callback(frame, bp_loc, internal_dict):
    """
    Hook svr_dropbear_log() which is called frequently.
    Watch a stack local variable that gets modified.
    """
    global _target, _debugger

    if not _target:
        process = frame.GetThread().GetProcess()
        target = process.GetTarget()
        _target = target
        _debugger = target.GetDebugger()

    # Get stack pointer and watch a local variable
    # We'll watch the area just below SP (stack locals)
    sp = frame.GetSP()

    # Watch stack location at SP+16 (local variable area)
    watch_addr = sp + 16

    print(f"[TEST] svr_dropbear_log() called, SP=0x{sp:x}")
    print(f"[TEST] Setting watchpoint on stack at 0x{watch_addr:x}")

    _set_watchpoint("stack_local", watch_addr)

    # Disable this breakpoint after first hit (we only need to set watchpoint once)
    bp_loc.GetBreakpoint().SetEnabled(False)

    return False


def __lldb_init_module(debugger, internal_dict):
    """Initialize Option C test"""
    print("="*60)
    print("[OPTION_C] Dropbear Stack Watchpoint Test")
    print("[OPTION_C] Tests if hardware watchpoints work at all")
    print("="*60)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[ERROR] No valid target available")
        return

    # Hook svr_dropbear_log (called frequently)
    bp = target.BreakpointCreateByName("svr_dropbear_log")
    if bp.IsValid() and bp.GetNumLocations() > 0:
        bp.SetScriptCallbackFunction("dropbear_test_option_c.svr_dropbear_log_callback")
        bp.SetAutoContinue(True)
        print(f"✓ Set breakpoint on svr_dropbear_log (bp {bp.GetID()})")
    else:
        # Try alternative function
        bp_alt = target.BreakpointCreateByName("dropbear_log")
        if bp_alt.IsValid():
            bp_alt.SetScriptCallbackFunction("dropbear_test_option_c.svr_dropbear_log_callback")
            bp_alt.SetAutoContinue(True)
            print(f"✓ Set breakpoint on dropbear_log (bp {bp_alt.GetID()})")
        else:
            print("[WARNING] Could not find logging function - watchpoint test may not work")

    print("="*60)
    print("[OPTION_C] Initialization complete")
    print("[OPTION_C] Watchpoint will be set on first log call")
    print("="*60)

    # Auto-continue
    process = target.GetProcess()
    if process.IsValid() and process.GetState() == lldb.eStateStopped:
        print(f"[AUTO_CONTINUE] Continuing process...")
        error = process.Continue()
        if error.Success():
            print(f"[AUTO_CONTINUE] ✓ Process continued")
