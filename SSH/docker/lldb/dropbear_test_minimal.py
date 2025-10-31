#!/usr/bin/env python3
"""
Minimal Dropbear watchpoint test - Option B (with fork)

Tests hardware watchpoints on trans_cipher_key using exact IPsec pattern.
NO memory dumps, NO rekey detection, NO extra features.

Goal: Prove watchpoint mechanism works with Dropbear's fork model.
"""

import lldb
import time
import struct

# Global state
_target = None
_debugger = None
_watchpoints = {}  # key_name -> (wp_id, address)

print(f"[MINIMAL] Loading minimal Dropbear watchpoint test")
print(f"[MINIMAL] Version: 2025.10.22-minimal-b")


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
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name.replace('-', '_')}"

        # Fixed values for f-string substitution
        fixed_addr = address
        fixed_key_name = key_name

        # Generate callback code (IPsec pattern - simple version)
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_key_name}' at 0x{fixed_addr:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    new_data = process.ReadMemory({fixed_addr}, 16, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in new_data[:16])
        print(f"[WATCHPOINT] New value: {{data_hex}}")

    import dropbear_test_minimal
    dropbear_test_minimal._watchpoints.pop("{fixed_key_name}", None)

    return False
'''

        # Inject callback (IPsec pattern: debugger.HandleCommand + exec backup)
        _debugger.HandleCommand(f"script {callback_code}")

        # Backup: exec into module namespace
        try:
            exec(callback_code, globals())
        except:
            pass

        # Attach callback to watchpoint with -F flag
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # Store watchpoint info
        _watchpoints[key_name] = (wp_id, address)

        print(f"[WATCHPOINT] Set on {key_name} at 0x{address:x} (wp {wp_id})")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")
        import traceback
        traceback.print_exc()


def fork_callback(frame, bp_loc, internal_dict):
    """Fork detection callback"""
    thread = frame.GetThread()
    process = thread.GetProcess()

    print(f"\n{'='*60}")
    print(f"[FORK] fork() called in PID {process.GetProcessID()}")
    print(f"[FORK] Dropbear forking to handle SSH connection")
    print(f"{'='*60}\n")

    return False  # Auto-continue


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
            bp.SetScriptCallbackFunction("dropbear_test_minimal.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_test_minimal.gen_new_keys_exit")

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

        # Set watchpoint on trans_cipher_key
        _set_watchpoint("trans_cipher_key", trans_cipher_key_addr, trans_cipher_key)
    else:
        print(f"[KEY_EXTRACT_INFO] Not ChaCha20, cipher_state data: {_hex_dump(trans_cipher_data, 32)}")

    return False


def __lldb_init_module(debugger, internal_dict):
    """Initialize minimal test module"""
    print("="*60)
    print("[MINIMAL] Dropbear Watchpoint Test - Option B")
    print("[MINIMAL] Fork + Single Watchpoint on trans_cipher_key")
    print("="*60)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[ERROR] No valid target available")
        return

    # Breakpoint 1: fork detection
    bp_fork = target.BreakpointCreateByName("fork")
    if bp_fork.IsValid() and bp_fork.GetNumLocations() > 0:
        bp_fork.SetScriptCallbackFunction("dropbear_test_minimal.fork_callback")
        bp_fork.SetAutoContinue(True)
        print(f"✓ Set breakpoint on fork() (bp {bp_fork.GetID()})")

    # Breakpoint 2: gen_new_keys
    bp_kex = target.BreakpointCreateByName("gen_new_keys")
    if bp_kex.IsValid():
        bp_kex.SetScriptCallbackFunction("dropbear_test_minimal.gen_new_keys_entry")
        bp_kex.SetAutoContinue(True)
        print(f"✓ Set breakpoint on gen_new_keys (bp {bp_kex.GetID()})")

    print("="*60)
    print("[MINIMAL] Initialization complete")
    print("[MINIMAL] Waiting for SSH connection...")
    print("="*60)

    # Auto-continue if process is stopped
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
