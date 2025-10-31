#!/usr/bin/env python3
"""
Dropbear LLDB callbacks with hardware watchpoints for precise key lifecycle tracking.

This implementation follows the proven IPsec strongSwan pattern to:
1. Extract actual key values from memory at KEX exit
2. Set hardware watchpoints (CPU-level monitoring)
3. Detect when keys are overwritten (not just when functions are called)
4. Log precise timing data

Key structures (from Dropbear source):
- Global: ses (struct sshsession)
- ses.newkeys->trans.mackey[MAX_MAC_LEN] - Client->Server MAC
- ses.newkeys->recv.mackey[MAX_MAC_LEN] - Server->Client MAC
"""

import lldb
import json
import time
import os
import struct

# Import from main monitor
import sys
sys.path.append(os.path.dirname(__file__))
try:
    from ssh_monitor import (log_event, log_timing, active_keys, next_key_id,
                            dump_memory, dump_full_memory)
except ImportError:
    def log_event(event_type, msg, metadata=None):
        print(f"[{event_type}] {msg}")
    def log_timing(key_id, event, ts=None):
        pass
    def dump_memory(*args, **kwargs):
        return None
    def dump_full_memory(*args, **kwargs):
        return []
    active_keys = {}
    next_key_id = 0

# Global state for watchpoints
_watchpoints = {}  # key_name -> (watchpoint_id, address, key_bytes)
_target = None
_debugger = None
_process = None

def _hex_dump(data, max_len=32):
    """Convert bytes to hex string"""
    if not data:
        return "(empty)"
    if len(data) > max_len:
        return data[:max_len].hex() + f"... ({len(data)} bytes)"
    return data.hex()

def _read_pointer(process, address, ptr_size=8):
    """Read a pointer from memory"""
    error = lldb.SBError()
    data = process.ReadMemory(address, ptr_size, error)
    if error.Fail():
        return None
    if ptr_size == 8:
        return struct.unpack('<Q', data)[0]
    else:
        return struct.unpack('<I', data)[0]

def _read_bytes(process, address, size):
    """Read bytes from memory"""
    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Fail():
        return None
    return data

def _set_watchpoint(key_name, address, key_data, key_id):
    """Set hardware watchpoint on a key using the proven IPsec pattern

    Pattern:
    1. Generate callback as f-string with full function definition
    2. Inject into Python namespace with debugger.HandleCommand("script ...")
    3. Attach to watchpoint with debugger.HandleCommand("watchpoint command add -F ...")

    The -F flag means "function name" - LLDB automatically passes frame, bp_loc, internal_dict
    """
    global _watchpoints, _target, _debugger, _timing_logger

    # Skip if already watching this key
    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    if not _debugger or not _target:
        print(f"[WATCHPOINT] No debugger/target for {key_name}")
        return

    try:
        error = lldb.SBError()

        # Set write watchpoint on first 4 bytes of key
        watchpoint = _target.WatchAddress(address, 4, False, True, error)

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] Failed to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name.replace('-', '_')}"

        # Fixed values for f-string substitution
        fixed_addr = address
        fixed_key_name = key_name
        fixed_key_id = key_id
        fixed_key_hex = key_data.hex() if key_data else "unknown"

        # Generate callback code (IPsec pattern)
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    """Watchpoint callback for {fixed_key_name} at 0x{fixed_addr:x}"""
    import time
    timestamp = time.time()

    # Log the overwrite event
    print(f"[KEY_OVERWRITE] {fixed_key_name} overwritten at {{timestamp}}")
    print(f"[KEY_OVERWRITE] Address: 0x{fixed_addr:x}")
    print(f"[KEY_OVERWRITE] Original key: {fixed_key_hex[:64]}...")

    # Log timing data
    try:
        from ssh_monitor import log_timing
        log_timing("{fixed_key_id}", "overwritten", timestamp)
    except:
        pass

    return False  # Continue execution
'''

        # Inject callback into Python namespace
        _debugger.HandleCommand(f"script {callback_code}")

        # Attach callback to watchpoint with -F flag
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # Store watchpoint info
        _watchpoints[key_name] = (wp_id, address, key_data)

        print(f"[WATCHPOINT] Set on {key_name} at 0x{address:x} (wp {wp_id})")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")

def _extract_and_watch_keys(frame, key_id):
    """Extract keys from ses.newkeys and set hardware watchpoints"""
    global _target, _debugger, _process

    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    _target = target
    _debugger = target.GetDebugger()
    _process = process

    # Determine pointer size
    ptr_size = target.GetAddressByteSize()

    log_event("KEY_EXTRACT", f"Extracting keys from ses.newkeys for {key_id}")

    # Find 'ses' global variable
    ses_var = target.FindFirstGlobalVariable("ses")
    if not ses_var.IsValid():
        log_event("KEY_EXTRACT_ERROR", "'ses' global variable not found")
        return

    ses_addr = ses_var.GetLoadAddress()
    log_event("KEY_EXTRACT", f"Found ses at 0x{ses_addr:x}")

    # Get ses.newkeys pointer (offset varies, try to find it via type info)
    # For simplicity, we'll use debug symbols if available
    newkeys_var = ses_var.GetChildMemberWithName("newkeys")
    if not newkeys_var.IsValid():
        log_event("KEY_EXTRACT_ERROR", "ses.newkeys not found in structure")
        return

    newkeys_addr = newkeys_var.GetValueAsUnsigned()
    if newkeys_addr == 0:
        log_event("KEY_EXTRACT_ERROR", "ses.newkeys is NULL")
        return

    log_event("KEY_EXTRACT", f"Found ses.newkeys at 0x{newkeys_addr:x}")

    # Get trans and recv structures
    trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
    recv_var = newkeys_var.Dereference().GetChildMemberWithName("recv")

    if not trans_var.IsValid() or not recv_var.IsValid():
        log_event("KEY_EXTRACT_ERROR", "trans/recv structures not found")
        return

    # Get MAC keys
    trans_mackey = trans_var.GetChildMemberWithName("mackey")
    recv_mackey = recv_var.GetChildMemberWithName("mackey")

    if not trans_mackey.IsValid() or not recv_mackey.IsValid():
        log_event("KEY_EXTRACT_ERROR", "mackey fields not found")
        return

    trans_mackey_addr = trans_mackey.GetLoadAddress()
    recv_mackey_addr = recv_mackey.GetLoadAddress()

    log_event("KEY_EXTRACT", f"trans.mackey at 0x{trans_mackey_addr:x}")
    log_event("KEY_EXTRACT", f"recv.mackey at 0x{recv_mackey_addr:x}")

    # Read actual key bytes (assume 32 bytes for HMAC-SHA256, adjust as needed)
    trans_mackey_data = _read_bytes(process, trans_mackey_addr, 32)
    recv_mackey_data = _read_bytes(process, recv_mackey_addr, 32)

    if not trans_mackey_data or not recv_mackey_data:
        log_event("KEY_EXTRACT_ERROR", "Failed to read MAC key data")
        return

    log_event("KEY_EXTRACT_SUCCESS", f"Extracted trans MAC key: {_hex_dump(trans_mackey_data, 16)}")
    log_event("KEY_EXTRACT_SUCCESS", f"Extracted recv MAC key: {_hex_dump(recv_mackey_data, 16)}")

    # Set hardware watchpoints (limited to 4, we use 2 for now)
    _set_watchpoint("trans_mackey", trans_mackey_addr, trans_mackey_data, key_id)
    _set_watchpoint("recv_mackey", recv_mackey_addr, recv_mackey_data, key_id)

    # Store in active_keys for tracking
    active_keys[key_id]['trans_mackey_addr'] = trans_mackey_addr
    active_keys[key_id]['recv_mackey_addr'] = recv_mackey_addr
    active_keys[key_id]['trans_mackey'] = trans_mackey_data.hex()
    active_keys[key_id]['recv_mackey'] = recv_mackey_data.hex()

def gen_new_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint for gen_new_keys()"""
    timestamp = time.time()
    log_event("KEX_ENTRY", "Entered gen_new_keys()", {'timestamp': timestamp})

    # Dump memory before key generation
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory before key generation")
    dump_full_memory(process, "kex_entry")

    # Set return breakpoint
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
            bp.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.gen_new_keys_exit")

    return False

def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys() - NOW WITH KEY EXTRACTION"""
    global next_key_id
    timestamp = time.time()

    key_id = f"dropbear_key_{next_key_id}"
    next_key_id += 1

    log_event("KEX_EXIT", f"Key {key_id} generated", {'timestamp': timestamp})
    log_timing(key_id, "generated", timestamp)

    # Dump full memory after key generation
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", f"Dumping memory after key generation for {key_id}")
    dump_full_memory(process, "kex_exit", key_id)

    # Initialize key tracking
    active_keys[key_id] = {
        'generated_at': timestamp,
        'status': 'active'
    }

    # EXTRACT KEYS AND SET WATCHPOINTS
    _extract_and_watch_keys(frame, key_id)

    return False

def m_burn_entry(frame, bp_loc, internal_dict):
    """Breakpoint for m_burn() - passive detection"""
    timestamp = time.time()

    thread = frame.GetThread()
    process = thread.GetProcess()
    arch = process.GetTarget().GetTriple().split('-')[0]

    if 'x86_64' in arch or 'amd64' in arch:
        addr_reg = frame.FindRegister("rdi")
        len_reg = frame.FindRegister("rsi")
    elif 'aarch64' in arch or 'arm64' in arch:
        addr_reg = frame.FindRegister("x0")
        len_reg = frame.FindRegister("x1")
    else:
        return False

    if addr_reg and len_reg:
        addr = addr_reg.GetValueAsUnsigned()
        length = len_reg.GetValueAsUnsigned()

        log_event("M_BURN_CALL", f"m_burn called at {addr:#x}, size {length} bytes", {
            'timestamp': timestamp,
            'address': addr,
            'size': length
        })

        # Check if this matches any watchpoint addresses
        for key_id, key_info in active_keys.items():
            if 'trans_mackey_addr' in key_info and key_info['trans_mackey_addr'] == addr:
                log_event("KEY_CLEARED", f"Key {key_id} trans_mackey cleared with m_burn")
                log_timing(key_id, "cleared", timestamp)
            elif 'recv_mackey_addr' in key_info and key_info['recv_mackey_addr'] == addr:
                log_event("KEY_CLEARED", f"Key {key_id} recv_mackey cleared with m_burn")
                log_timing(key_id, "cleared", timestamp)

        # Dump large clears (may contain keys)
        if length >= 16:
            log_event("DUMP_START", f"Dumping m_burn at {addr:#x} ({length} bytes)")
            dump_memory(process, addr, length, "m_burn_large")

    return False

def switch_keys_callback(frame, bp_loc, internal_dict):
    """Breakpoint for switch_keys()"""
    timestamp = time.time()

    log_event("KEYS_ACTIVATED", "Keys activated via switch_keys()", {
        'timestamp': timestamp
    })

    if active_keys:
        latest_key = max(active_keys.keys(), key=lambda k: active_keys[k].get('generated_at', 0))
        log_timing(latest_key, "activated", timestamp)

    return False

def recv_msg_kexdh_init_callback(frame, bp_loc, internal_dict):
    """KEX DH init callback"""
    timestamp = time.time()
    log_event("KEX_DH_INIT", "Received KEX DH init message", {'timestamp': timestamp})
    return False

def send_msg_kexdh_reply_callback(frame, bp_loc, internal_dict):
    """KEX DH reply callback"""
    timestamp = time.time()
    log_event("KEX_DH_REPLY", "Sending KEX DH reply message", {'timestamp': timestamp})
    return False

# Export callbacks
__all__ = [
    'gen_new_keys_entry',
    'gen_new_keys_exit',
    'm_burn_entry',
    'switch_keys_callback',
    'recv_msg_kexdh_init_callback',
    'send_msg_kexdh_reply_callback',
]

def __lldb_init_module(debugger, internal_dict):
    """Initialize module when imported by LLDB"""
    print("Loading Dropbear callbacks with hardware watchpoints...")

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("ERROR: No valid target available")
        return

    # Set breakpoints
    bp1 = target.BreakpointCreateByName("gen_new_keys")
    bp1.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.gen_new_keys_entry")
    bp1.SetAutoContinue(True)
    print(f"✓ Set breakpoint on gen_new_keys (bp {bp1.GetID()})")

    for alt_name in ["recv_msg_kexdh_init", "send_msg_kexdh_reply", "switch_keys"]:
        bp_alt = target.BreakpointCreateByName(alt_name)
        if bp_alt.IsValid():
            if alt_name == "switch_keys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.switch_keys_callback")
            elif alt_name == "recv_msg_kexdh_init":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.recv_msg_kexdh_init_callback")
            elif alt_name == "send_msg_kexdh_reply":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.send_msg_kexdh_reply_callback")
            bp_alt.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {alt_name} (bp {bp_alt.GetID()})")

    bp2 = target.BreakpointCreateByName("m_burn")
    bp2.SetScriptCallbackFunction("dropbear_callbacks_watchpoints.m_burn_entry")
    bp2.SetAutoContinue(True)
    print(f"✓ Set breakpoint on m_burn (bp {bp2.GetID()})")

    for func_name in ["session_cleanup", "cleanup_keys"]:
        bp = target.BreakpointCreateByName(func_name)
        if bp.IsValid():
            bp.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {func_name} (bp {bp.GetID()})")

    print("Dropbear callbacks with hardware watchpoints loaded successfully")
    print("Hardware watchpoints will be set when keys are generated")
