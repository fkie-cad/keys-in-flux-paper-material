#!/usr/bin/env python3
"""
Minimal Dropbear watchpoint test - Version 2 with improved trace mode handling

Based on manual test results showing "stop reason = trace", this version:
1. Uses process.Continue() instead of returning False
2. Adds more debug output
3. Disables watchpoint immediately after first hit
"""

import lldb
import time
import struct

# Global state
_target = None
_debugger = None
_watchpoints = {}

print(f"[MINIMAL_V2] Loading improved watchpoint test")
print(f"[MINIMAL_V2] Version: 2025.10.22-v2-trace-fix")


def _hex_dump(data, max_len=16):
    """Convert bytes to hex string"""
    if not data:
        return "(empty)"
    if len(data) > max_len:
        return data[:max_len].hex() + f"... ({len(data)} bytes)"
    return data.hex()


def _read_bytes(process, address, size):
    """Read bytes from memory"""
    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Fail():
        return None
    return data


def _set_watchpoint(key_name, address, key_data):
    """Set hardware watchpoint with improved callback"""
    global _watchpoints, _target, _debugger

    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    if not _debugger or not _target:
        print(f"[WATCHPOINT] No debugger/target for {key_name}")
        return

    try:
        error = lldb.SBError()

        # Set write watchpoint on 32 bytes (full ChaCha20 key)
        # Note: Hardware watchpoints typically support up to 8 bytes on most CPUs
        # We'll watch the first 8 bytes which should catch any memset operation
        watchpoint = _target.WatchAddress(address, 8, False, True, error)

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] Failed to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()
        print(f"[WATCHPOINT] Created watchpoint ID {wp_id} for {key_name}")

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name.replace('-', '_')}"

        # Fixed values
        fixed_addr = address
        fixed_key_name = key_name
        fixed_wp_id = wp_id

        # Improved callback with explicit process.Continue()
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    """Watchpoint callback - V2 with trace mode fix"""
    from datetime import datetime
    import lldb

    hit_time = datetime.now()
    print(f"")
    print(f"{'='*70}")
    print(f"==!!!== WATCHPOINT HIT for '{fixed_key_name}' ==!!!==")
    print(f"Address: 0x{fixed_addr:x}")
    print(f"Time: {{hit_time}}")
    print(f"{'='*70}")

    try:
        thread = frame.GetThread()
        process = thread.GetProcess()

        # Read new memory value
        error = lldb.SBError()
        new_data = process.ReadMemory({fixed_addr}, 16, error)
        if error.Success():
            data_hex = ' '.join(f'{{b:02x}}' for b in new_data[:16])
            print(f"[WATCHPOINT] New value: {{data_hex}}")
        else:
            print(f"[WATCHPOINT] Could not read new value: {{error.GetCString()}}")

        # Get current stop reason
        stop_reason = thread.GetStopReason()
        stop_desc = lldb.SBThread.GetStopReasonDataAtIndex(thread, 0)
        print(f"[WATCHPOINT] Thread stop reason: {{stop_reason}} ({{stop_desc}})")

        # Disable this watchpoint to prevent repeated hits
        watchpoint = bp_loc.GetWatchpoint()
        if watchpoint and watchpoint.IsValid():
            print(f"[WATCHPOINT] Disabling watchpoint {{watchpoint.GetID()}} after hit")
            watchpoint.SetEnabled(False)

        # Clean up tracking
        import dropbear_test_minimal_v2
        dropbear_test_minimal_v2._watchpoints.pop("{fixed_key_name}", None)

        # CRITICAL: Explicitly continue the process to exit trace mode
        print(f"[WATCHPOINT] Calling process.Continue() to exit trace mode...")
        error = lldb.SBError()
        process.Continue()
        print(f"[WATCHPOINT] Process.Continue() called")

    except Exception as e:
        print(f"[WATCHPOINT_ERROR] Exception in callback: {{e}}")
        import traceback
        traceback.print_exc()

    print(f"{'='*70}")
    print(f"")

    # Return False to indicate we handled the stop
    return False
'''

        # Inject callback into module namespace
        print(f"[WATCHPOINT] Injecting callback function...")

        # Execute callback code in module's globals (makes it accessible to LLDB)
        exec(callback_code, globals())
        print(f"[WATCHPOINT] Callback defined in module namespace")

        # Also register via LLDB command (dual approach)
        _debugger.HandleCommand(f"script {callback_code}")
        print(f"[WATCHPOINT] Callback also registered via LLDB command")

        # SIMPLEST TEST: No callback at all - just see if watchpoint fires
        print(f"[WATCHPOINT] TEST MODE: No callback - will stop when watchpoint fires")
        print(f"[WATCHPOINT] Expected: Stop with 'stop reason = watchpoint {wp_id}'")

        # Store watchpoint info
        _watchpoints[key_name] = (wp_id, address)

        print(f"[WATCHPOINT] Successfully configured watchpoint {wp_id}")
        print(f"[WATCHPOINT] Address: 0x{address:x}")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")
        import traceback
        traceback.print_exc()


def fork_callback(frame, bp_loc, internal_dict):
    """Fork detection callback"""
    thread = frame.GetThread()
    process = thread.GetProcess()

    print(f"")
    print(f"{'='*60}")
    print(f"[FORK] fork() called in PID {process.GetProcessID()}")
    print(f"[FORK] Dropbear forking to handle SSH connection")
    print(f"{'='*60}")
    print(f"")

    # Return False - SetAutoContinue(True) should handle continuation
    print(f"[FORK] Returning False - SetAutoContinue should continue process")

    return False


def gen_new_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint for gen_new_keys()"""
    print(f"[KEX_ENTRY] Entered gen_new_keys()")

    # Set return breakpoint
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    sp = frame.GetSP()
    error = lldb.SBError()
    arch = target.GetTriple().split('-')[0]

    if 'x86_64' in arch or 'amd64' in arch:
        ret_addr_data = process.ReadMemory(sp, 8, error)
        if not error.Fail():
            ret_addr = struct.unpack('<Q', ret_addr_data)[0]
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetAutoContinue(True)  # Auto-continue after callback
            bp.SetScriptCallbackFunction("dropbear_test_minimal_v2.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetAutoContinue(True)  # Auto-continue after callback
            bp.SetScriptCallbackFunction("dropbear_test_minimal_v2.gen_new_keys_exit")

    # Return False - SetAutoContinue(True) should handle continuation
    print(f"[KEX_ENTRY] Returning False - SetAutoContinue should continue process")

    return False


def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """Exit callback - extract trans_cipher_key and set watchpoint"""
    global _target, _debugger

    print(f"[KEX_EXIT] Exited gen_new_keys() - extracting keys")

    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    _target = target
    _debugger = target.GetDebugger()

    # Find 'ses' global variable
    ses_var = target.FindFirstGlobalVariable("ses")
    if not ses_var.IsValid():
        print(f"[KEY_EXTRACT_ERROR] 'ses' global variable not found")
        return False

    ses_addr = ses_var.GetLoadAddress()
    print(f"[KEY_EXTRACT] Found ses at 0x{ses_addr:x}")

    # Navigate to ses.newkeys->trans.cipher_state
    newkeys_var = ses_var.GetChildMemberWithName("newkeys")
    if not newkeys_var.IsValid():
        print(f"[KEY_EXTRACT_ERROR] ses.newkeys not found")
        return False

    newkeys_addr = newkeys_var.GetValueAsUnsigned()
    if newkeys_addr == 0:
        print(f"[KEY_EXTRACT_ERROR] ses.newkeys is NULL")
        return False

    trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
    if not trans_var.IsValid():
        print(f"[KEY_EXTRACT_ERROR] trans structure not found")
        return False

    trans_cipher_state = trans_var.GetChildMemberWithName("cipher_state")
    if not trans_cipher_state.IsValid():
        print(f"[KEY_EXTRACT_ERROR] cipher_state not found")
        return False

    trans_cipher_addr = trans_cipher_state.GetLoadAddress()
    print(f"[KEY_EXTRACT] trans.cipher_state at 0x{trans_cipher_addr:x}")

    # Read cipher_state to find ChaCha20 key
    trans_cipher_data = _read_bytes(process, trans_cipher_addr, 128)
    if not trans_cipher_data:
        print(f"[KEY_EXTRACT_ERROR] Failed to read cipher_state")
        return False

    # ChaCha20-Poly1305: offset 16-47 is ChaCha20 key
    if trans_cipher_data[:16] == b"expand 32-byte k":
        trans_cipher_key = trans_cipher_data[16:48]
        trans_cipher_key_addr = trans_cipher_addr + 16
        print(f"[KEY_EXTRACT_SUCCESS] Found ChaCha20 key: {_hex_dump(trans_cipher_key, 32)}")

        # Set watchpoint
        _set_watchpoint("trans_cipher_key", trans_cipher_key_addr, trans_cipher_key)
    else:
        print(f"[KEY_EXTRACT_INFO] Not ChaCha20, cipher_state: {_hex_dump(trans_cipher_data, 32)}")

    # Try using debugger command instead of Python API
    print(f"[KEX_EXIT] Watchpoint set, using 'c' command to continue...")
    target = process.GetTarget()
    debugger = target.GetDebugger()
    debugger.SetAsync(True)  # Enable async mode
    debugger.HandleCommand("c")
    print(f"[KEX_EXIT] Continue command sent - watchpoint should fire when key is overwritten")

    return False


def __lldb_init_module(debugger, internal_dict):
    """Initialize V2 test module"""
    print("="*60)
    print("[MINIMAL_V2] Dropbear Watchpoint Test V2")
    print("[MINIMAL_V2] Improved trace mode handling")
    print("="*60)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[ERROR] No valid target available")
        return

    # Breakpoint 1: fork detection
    # Note: Don't check GetNumLocations() - libc symbols load after process launch
    bp_fork = target.BreakpointCreateByName("fork")
    if bp_fork.IsValid():
        bp_fork.SetScriptCallbackFunction("dropbear_test_minimal_v2.fork_callback")
        bp_fork.SetAutoContinue(True)
        print(f"✓ Set breakpoint on fork() (bp {bp_fork.GetID()}) - pending until libc loads")

    # Breakpoint 2: gen_new_keys
    bp_kex = target.BreakpointCreateByName("gen_new_keys")
    if bp_kex.IsValid():
        bp_kex.SetScriptCallbackFunction("dropbear_test_minimal_v2.gen_new_keys_entry")
        bp_kex.SetAutoContinue(True)
        print(f"✓ Set breakpoint on gen_new_keys (bp {bp_kex.GetID()})")

    print("="*60)
    print("[MINIMAL_V2] Initialization complete")
    print("[MINIMAL_V2] Waiting for SSH connection...")
    print("="*60)

    # Auto-continue
    process = target.GetProcess()
    if process.IsValid():
        state = process.GetState()
        if state == lldb.eStateStopped:
            print(f"[AUTO_CONTINUE] Process stopped - continuing...")
            error = process.Continue()
            if error.Success():
                print(f"[AUTO_CONTINUE] ✓ Process continued")
            else:
                print(f"[AUTO_CONTINUE] ✗ Failed: {error.GetCString()}")
