#!/usr/bin/env python3
"""
Dropbear-specific LLDB callbacks for key lifecycle monitoring

Extracts key memory addresses from Dropbear internal structures and
sets hardware watchpoints to detect when keys are cleared.

Dropbear Key Management (based on Dropbear 2022.83):
- gen_new_keys() generates encryption/MAC keys after KEX
- Keys are stored in ses.newkeys and ses.keys structures
- Key material is in key arrays and cipher contexts
- Keys are cleared with m_burn() (Dropbear's secure memory clearing)

Key differences from OpenSSH:
- Simpler structure (embedded/lightweight focus)
- Uses m_burn() instead of explicit_bzero()
- Single global session structure (ses)
- Less privilege separation complexity
"""

import lldb
import json
import time
import os

# Import from main monitor
import sys
sys.path.append(os.path.dirname(__file__))
try:
    from ssh_monitor import (log_event, log_timing, setup_key_watchpoint,
                            active_keys, next_key_id, dump_memory, dump_full_memory)
except ImportError:
    # Fallback for standalone testing
    def log_event(event_type, msg, metadata=None):
        print(f"[{event_type}] {msg}")
    def log_timing(key_id, event, ts=None):
        pass
    def setup_key_watchpoint(*args):
        return None
    def dump_memory(*args, **kwargs):
        return None
    def dump_full_memory(*args, **kwargs):
        return []
    active_keys = {}
    next_key_id = 0

def read_pointer(frame, address):
    """Read a pointer value from memory"""
    error = lldb.SBError()
    process = frame.GetThread().GetProcess()

    # Determine pointer size based on architecture
    target = process.GetTarget()
    addr_size = target.GetAddressByteSize()

    data = process.ReadMemory(address, addr_size, error)
    if error.Fail():
        return None

    if addr_size == 8:  # 64-bit
        import struct
        return struct.unpack('<Q', data)[0]
    elif addr_size == 4:  # 32-bit
        import struct
        return struct.unpack('<I', data)[0]
    return None

def read_uint32(frame, address):
    """Read a uint32 value from memory"""
    error = lldb.SBError()
    process = frame.GetThread().GetProcess()

    data = process.ReadMemory(address, 4, error)
    if error.Fail():
        return None

    import struct
    return struct.unpack('<I', data)[0]

def gen_new_keys_entry(frame, bp_loc, internal_dict):
    """
    Entry breakpoint callback for gen_new_keys().

    Function signature (Dropbear 2022.83):
    void gen_new_keys()

    Generates session keys from key exchange hash.
    We want to capture the results after generation completes.
    """
    timestamp = time.time()

    # Log that we entered key generation
    log_event("KEX_ENTRY", "Entered gen_new_keys()", {'timestamp': timestamp})

    # Dump full memory before key generation
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory before key generation")
    dump_full_memory(process, "kex_entry")

    # Set a one-shot breakpoint at function return
    target = process.GetTarget()

    # Get return address from stack
    sp = frame.GetSP()
    error = lldb.SBError()

    # Read return address (architecture-specific)
    arch = target.GetTriple().split('-')[0]

    if 'x86_64' in arch or 'amd64' in arch:
        ret_addr_data = process.ReadMemory(sp, 8, error)
        if not error.Fail():
            import struct
            ret_addr = struct.unpack('<Q', ret_addr_data)[0]
            log_event("RETURN_BP", f"Setting return breakpoint at {ret_addr:#x}")
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        # On ARM64, return address is in LR (x30) register
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            log_event("RETURN_BP", f"Setting return breakpoint at {ret_addr:#x}")
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_exit")

    return False  # Continue execution

def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """
    Exit breakpoint callback for gen_new_keys().
    Keys have been generated - now we need to find them in memory.
    """
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

    # Try to find the session keys structure (ses.keys in Dropbear)
    # This requires either debug symbols or hardcoded offsets

    # For now, just log that we detected key generation
    # The actual key extraction needs more work based on Dropbear structure

    active_keys[key_id] = {
        'generated_at': timestamp,
        'status': 'active'
    }

    return False  # Continue execution

def m_burn_entry(frame, bp_loc, internal_dict):
    """
    Breakpoint callback for m_burn() - Dropbear's memory clearing function.

    Function signature:
    void m_burn(void *data, unsigned int len)

    This is called when Dropbear actively clears key material from memory.
    Similar to explicit_bzero() in OpenSSH but Dropbear-specific.
    """
    timestamp = time.time()

    # Get arguments
    thread = frame.GetThread()
    process = thread.GetProcess()
    arch = process.GetTarget().GetTriple().split('-')[0]

    if 'x86_64' in arch or 'amd64' in arch:
        addr_reg = frame.FindRegister("rdi")  # void *data
        len_reg = frame.FindRegister("rsi")   # unsigned int len
    elif 'aarch64' in arch or 'arm64' in arch:
        addr_reg = frame.FindRegister("x0")   # void *data
        len_reg = frame.FindRegister("x1")    # unsigned int len
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

        # Check if this address belongs to any of our tracked keys
        key_found = False
        for key_id, key_info in active_keys.items():
            if key_info.get('address') == addr:
                key_found = True
                log_event("KEY_CLEARED", f"Key {key_id} cleared with m_burn", {
                    'timestamp': timestamp,
                    'key_id': key_id
                })
                log_timing(key_id, "cleared", timestamp)

                # Dump memory before clearing (to capture the key)
                log_event("DUMP_START", f"Dumping key {key_id} before m_burn")
                dump_memory(process, addr, length, "m_burn_before", key_id)

                key_info['cleared_at'] = timestamp
                key_info['status'] = 'cleared'
                break

        # Also dump large m_burn calls (may contain keys)
        # Dropbear keys are typically 16-32 bytes (AES-128/256)
        if not key_found and length >= 16:
            log_event("DUMP_START", f"Dumping large m_burn at {addr:#x} ({length} bytes)")
            dump_memory(process, addr, length, "m_burn_large")

    return False  # Continue execution

def switch_keys_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint callback for switch_keys() - activates newly generated keys.

    This happens after gen_new_keys() completes.
    Useful for tracking when keys become active vs when they're generated.
    """
    timestamp = time.time()

    log_event("KEYS_ACTIVATED", "Keys activated via switch_keys()", {
        'timestamp': timestamp
    })

    # Log to timing CSV
    if active_keys:
        # Get the most recent key
        latest_key = max(active_keys.keys(), key=lambda k: active_keys[k].get('generated_at', 0))
        log_timing(latest_key, "activated", timestamp)

    return False  # Continue execution

def recv_msg_kexdh_init_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint callback for recv_msg_kexdh_init() - KEX Diffie-Hellman init.

    This marks the start of the KEX process.
    """
    timestamp = time.time()

    log_event("KEX_DH_INIT", "Received KEX DH init message", {
        'timestamp': timestamp
    })

    return False  # Continue execution

def send_msg_kexdh_reply_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint callback for send_msg_kexdh_reply() - KEX DH reply.

    This is part of the KEX exchange.
    """
    timestamp = time.time()

    log_event("KEX_DH_REPLY", "Sending KEX DH reply message", {
        'timestamp': timestamp
    })

    return False  # Continue execution

# Export callbacks for use in main monitor
__all__ = [
    'gen_new_keys_entry',
    'gen_new_keys_exit',
    'm_burn_entry',
    'switch_keys_callback',
    'recv_msg_kexdh_init_callback',
    'send_msg_kexdh_reply_callback',
]

def __lldb_init_module(debugger, internal_dict):
    """
    Initialize the module when imported by LLDB.
    This function is automatically called by LLDB when using 'command script import'.
    """
    print("Loading Dropbear callbacks...")

    # Get the target
    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("ERROR: No valid target available")
        return

    # Set breakpoint on gen_new_keys (deferred - will resolve when process starts)
    bp1 = target.BreakpointCreateByName("gen_new_keys")
    bp1.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_entry")
    bp1.SetAutoContinue(True)  # Don't stop debugger, just run callback
    print(f"✓ Set deferred breakpoint on gen_new_keys (bp {bp1.GetID()}, {bp1.GetNumLocations()} locations now)")

    # Try alternate KEX functions
    for alt_name in ["recv_msg_kexdh_init", "send_msg_kexdh_reply", "switch_keys"]:
        bp_alt = target.BreakpointCreateByName(alt_name)
        if bp_alt.IsValid():
            if alt_name == "switch_keys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.switch_keys_callback")
            elif alt_name == "recv_msg_kexdh_init":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.recv_msg_kexdh_init_callback")
            elif alt_name == "send_msg_kexdh_reply":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.send_msg_kexdh_reply_callback")
            bp_alt.SetAutoContinue(True)
            print(f"✓ Set alternate KEX breakpoint on {alt_name} (bp {bp_alt.GetID()})")

    # Set breakpoint on m_burn (Dropbear's memory clearing function)
    bp2 = target.BreakpointCreateByName("m_burn")
    bp2.SetScriptCallbackFunction("dropbear_callbacks.m_burn_entry")
    bp2.SetAutoContinue(True)  # Don't stop debugger, just run callback
    print(f"✓ Set deferred breakpoint on m_burn (bp {bp2.GetID()}, {bp2.GetNumLocations()} locations now)")

    # Optional: Set breakpoints on other cleanup functions
    for func_name in ["session_cleanup", "cleanup_keys"]:
        bp = target.BreakpointCreateByName(func_name)
        if bp.IsValid():
            bp.SetAutoContinue(True)  # Don't stop debugger, just observe
            print(f"✓ Set deferred breakpoint on {func_name} (bp {bp.GetID()}, auto-continue)")

    print("Dropbear callbacks loaded successfully")
    print("Note: Breakpoints will resolve when dropbear process starts and libraries load")
