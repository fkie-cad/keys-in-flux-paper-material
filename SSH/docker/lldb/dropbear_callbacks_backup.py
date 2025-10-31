#!/usr/bin/env python3
"""
Dropbear LLDB callbacks with hardware watchpoints for precise key lifecycle tracking.
Updated: 2025-10-15 09:53 with ChaCha20 cipher key extraction and watchpoints

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

# Configuration
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/ssh_keylog_dropbear.log')
_wp_env = os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')
ENABLE_WATCHPOINTS = _wp_env.lower() in ('true', '1', 'yes')

# Log configuration at module load time
print(f"[CONFIG] LLDB_ENABLE_WATCHPOINTS env var: '{_wp_env}'")
print(f"[CONFIG] Watchpoints enabled: {ENABLE_WATCHPOINTS}")

def write_keylog(timestamp, mode, cipher, key_hex, iv="unknown", cookie=None, session_id=None):
    """Write SSH key to keylog file in groundtruth format"""
    try:
        with open(KEYLOG_PATH, 'a') as f:
            if cookie and session_id:
                f.write(f"{int(timestamp)} COOKIE {cookie} CIPHER_IN unknown CIPHER_OUT unknown SESSION_ID {session_id}\n")
            else:
                f.write(f"{int(timestamp)} NEWKEYS MODE {mode} CIPHER {cipher} KEY {key_hex} IV {iv}\n")
            f.flush()
        log_event("KEYLOG_WRITE", f"Wrote {mode} key to keylog")
    except Exception as e:
        log_event("KEYLOG_ERROR", f"Failed to write keylog: {e}")

# Global state for watchpoints
_watchpoints = {}  # key_name -> (watchpoint_id, address, key_bytes)
_target = None
_debugger = None
_process = None
__version__ = "dropbear-cb 2025.10.22-r4"
_load_time = __import__("time").time()
_kex_counter = 0  # Track number of KEX operations (0 = first/init, >0 = rekey)
_dumped_mburn_keys = set()  # Track which keys have been dumped during m_burn (for deduplication)

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
        print(f"[WATCHPOINT] ERROR: No debugger/target for {key_name}")
        print(f"[WATCHPOINT] _debugger is None: {_debugger is None}")
        print(f"[WATCHPOINT] _target is None: {_target is None}")
        return

    try:
        print(f"[WATCHPOINT] Attempting to set watchpoint on {key_name} at 0x{address:x}")
        print(f"[WATCHPOINT] Key data length: {len(key_data)} bytes")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

        error = lldb.SBError()

        # Set write watchpoint on first 4 bytes of key
        print(f"[WATCHPOINT] Calling WatchAddress(0x{address:x}, 4, False, True)")
        watchpoint = _target.WatchAddress(address, 4, False, True, error)

        print(f"[WATCHPOINT] WatchAddress returned, checking status...")
        print(f"[WATCHPOINT] error.Success(): {error.Success()}")
        print(f"[WATCHPOINT] error message: {error.GetCString()}")
        print(f"[WATCHPOINT] watchpoint.IsValid(): {watchpoint.IsValid() if watchpoint else 'watchpoint is None'}")

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] FAILED to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()
        print(f"[WATCHPOINT] Successfully created watchpoint ID {wp_id} for {key_name}")

        # NOTE: SBWatchpoint doesn't support SetAutoContinue() unlike SBBreakpoint
        # Watchpoints will stop execution when they fire - this is an LLDB limitation
        # To disable watchpoints, set environment: DISABLE_WATCHPOINTS=true

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name.replace('-', '_')}"

        # Fixed values for f-string substitution
        fixed_addr = address
        fixed_key_name = key_name
        fixed_key_id = key_id
        fixed_key_hex = key_data.hex() if key_data else "unknown"

        # Generate callback code with explicit trace mode handling
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    """Watchpoint callback for {fixed_key_name} at 0x{fixed_addr:x}"""
    import time
    import lldb
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

    # CRITICAL: Clear single-step/trace mode and continue
    # Watchpoints can leave thread in trace mode, causing stops at every instruction
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()

        # Force process to continue (exit trace mode)
        # Using async mode to avoid blocking the callback
        process.Continue()

        print(f"[WATCHPOINT] Process continued after {{frame.GetFunctionName() or 'unknown'}}")
    except Exception as e:
        print(f"[WATCHPOINT_ERROR] Failed to continue: {{e}}")

    # Return False to tell LLDB not to stop again at this location
    return False
'''

        # Inject callback into module namespace first
        exec(callback_code, globals())

        # Register callback in LLDB's Python interpreter
        import sys
        module_name = __name__
        _debugger.HandleCommand(f"script import {module_name}")
        _debugger.HandleCommand(f"script {callback_func_name} = {module_name}.{callback_func_name}")

        # Attach callback to watchpoint
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # CRITICAL: Force watchpoint to auto-continue to exit trace mode
        # This addresses the issue where watchpoints leave thread in single-step mode
        # causing it to stop at every instruction in tight loops (like memset)
        try:
            # Try using Python API first (LLDB 11+)
            if hasattr(watchpoint, 'SetAutoContinue'):
                watchpoint.SetAutoContinue(True)
                print(f"[WATCHPOINT] Auto-continue enabled via API for wp {wp_id}")
            else:
                # Fallback: use command (but this replaces callback, so we keep callback and handle in code)
                print(f"[WATCHPOINT] SetAutoContinue not available, relying on callback to continue")
        except Exception as e:
            print(f"[WATCHPOINT] Could not set auto-continue: {e}")

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

    # Check if watchpoints are disabled (use global config)
    global ENABLE_WATCHPOINTS

    # Log watchpoint configuration explicitly
    log_event("WATCHPOINT_CONFIG", f"ENABLE_WATCHPOINTS = {ENABLE_WATCHPOINTS}")
    if not ENABLE_WATCHPOINTS:
        log_event("WATCHPOINTS_DISABLED", "Hardware watchpoints SKIPPED - configured via LLDB_ENABLE_WATCHPOINTS=false")
        log_event("WATCHPOINTS_DISABLED", "Memory dumps and key extraction will continue without watchpoints")
    else:
        log_event("WATCHPOINTS_ENABLED", "Hardware watchpoints will be installed after key extraction")

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

    # Check algo_crypt to see what cipher is being used
    trans_algo_crypt = trans_var.GetChildMemberWithName("algo_crypt")
    recv_algo_crypt = recv_var.GetChildMemberWithName("algo_crypt")

    # Check cipher_state union for actual keys
    trans_cipher_state = trans_var.GetChildMemberWithName("cipher_state")
    recv_cipher_state = recv_var.GetChildMemberWithName("cipher_state")

    # Extract cipher keys from cipher_state
    trans_cipher_key = None
    recv_cipher_key = None
    trans_cipher_key_addr = None
    recv_cipher_key_addr = None

    # Extract both ChaCha20 and Poly1305 keys
    trans_poly1305_key = None
    recv_poly1305_key = None

    if trans_cipher_state.IsValid():
        trans_cipher_addr = trans_cipher_state.GetLoadAddress()
        log_event("KEY_EXTRACT", f"trans.cipher_state at 0x{trans_cipher_addr:x}")
        # Read first 128 bytes of cipher_state to see if there's key material
        trans_cipher_data = _read_bytes(process, trans_cipher_addr, 128)
        if trans_cipher_data:
            log_event("KEY_EXTRACT", f"trans.cipher_state data: {_hex_dump(trans_cipher_data, 64)}")

            # ChaCha20-Poly1305 structure:
            # 0-15: "expand 32-byte k" constant
            # 16-47: ChaCha20 encryption key (32 bytes)
            # 48-79: Poly1305 MAC key (32 bytes)
            if trans_cipher_data[:16] == b"expand 32-byte k":
                trans_cipher_key = trans_cipher_data[16:48]  # ChaCha20 key
                trans_cipher_key_addr = trans_cipher_addr + 16
                trans_poly1305_key = trans_cipher_data[48:80]  # Poly1305 key
                log_event("KEY_EXTRACT_SUCCESS", f"Extracted trans ChaCha20 key: {_hex_dump(trans_cipher_key, 32)}")
                log_event("KEY_EXTRACT_SUCCESS", f"Extracted trans Poly1305 key: {_hex_dump(trans_poly1305_key, 32)}")
            else:
                log_event("KEY_EXTRACT_INFO", f"trans.cipher_state doesn't match ChaCha20 pattern, might be different cipher")

    if recv_cipher_state.IsValid():
        recv_cipher_addr = recv_cipher_state.GetLoadAddress()
        log_event("KEY_EXTRACT", f"recv.cipher_state at 0x{recv_cipher_addr:x}")
        recv_cipher_data = _read_bytes(process, recv_cipher_addr, 128)
        if recv_cipher_data:
            log_event("KEY_EXTRACT", f"recv.cipher_state data: {_hex_dump(recv_cipher_data, 64)}")

            # ChaCha20-Poly1305 structure:
            # 0-15: "expand 32-byte k" constant
            # 16-47: ChaCha20 encryption key (32 bytes)
            # 48-79: Poly1305 MAC key (32 bytes)
            if recv_cipher_data[:16] == b"expand 32-byte k":
                recv_cipher_key = recv_cipher_data[16:48]  # ChaCha20 key
                recv_cipher_key_addr = recv_cipher_addr + 16
                recv_poly1305_key = recv_cipher_data[48:80]  # Poly1305 key
                log_event("KEY_EXTRACT_SUCCESS", f"Extracted recv ChaCha20 key: {_hex_dump(recv_cipher_key, 32)}")
                log_event("KEY_EXTRACT_SUCCESS", f"Extracted recv Poly1305 key: {_hex_dump(recv_poly1305_key, 32)}")
            else:
                log_event("KEY_EXTRACT_INFO", f"recv.cipher_state doesn't match ChaCha20 pattern, might be different cipher")

    # Read actual key bytes (assume 32 bytes for HMAC-SHA256, adjust as needed)
    trans_mackey_data = _read_bytes(process, trans_mackey_addr, 32)
    recv_mackey_data = _read_bytes(process, recv_mackey_addr, 32)

    if not trans_mackey_data or not recv_mackey_data:
        log_event("KEY_EXTRACT_ERROR", "Failed to read MAC key data")
        return

    log_event("KEY_EXTRACT_SUCCESS", f"Extracted trans MAC key: {_hex_dump(trans_mackey_data, 16)}")
    log_event("KEY_EXTRACT_SUCCESS", f"Extracted recv MAC key: {_hex_dump(recv_mackey_data, 16)}")

    # Set hardware watchpoints (limited to 4 total) - unless disabled
    # Priority: cipher keys over MAC keys (since MAC keys might be unused in AEAD)
    log_event("WATCHPOINT_DECISION", f"Checking ENABLE_WATCHPOINTS: {ENABLE_WATCHPOINTS}")
    if ENABLE_WATCHPOINTS:
        log_event("WATCHPOINT_INSTALL_START", "Installing hardware watchpoints on extracted keys...")
        if trans_cipher_key and trans_cipher_key_addr:
            _set_watchpoint("trans_cipher_key", trans_cipher_key_addr, trans_cipher_key, key_id)
            active_keys[key_id]['trans_cipher_key'] = trans_cipher_key.hex()
            active_keys[key_id]['trans_cipher_key_addr'] = trans_cipher_key_addr
        else:
            # Fallback to MAC key if cipher key not found
            _set_watchpoint("trans_mackey", trans_mackey_addr, trans_mackey_data, key_id)

        if recv_cipher_key and recv_cipher_key_addr:
            _set_watchpoint("recv_cipher_key", recv_cipher_key_addr, recv_cipher_key, key_id)
            active_keys[key_id]['recv_cipher_key'] = recv_cipher_key.hex()
            active_keys[key_id]['recv_cipher_key_addr'] = recv_cipher_key_addr
        else:
            # Fallback to MAC key if cipher key not found
            _set_watchpoint("recv_mackey", recv_mackey_addr, recv_mackey_data, key_id)
    else:
        log_event("WATCHPOINT_SKIP", "Skipping watchpoint installation (disabled)")
        # Store key info even when watchpoints disabled
        if trans_cipher_key and trans_cipher_key_addr:
            active_keys[key_id]['trans_cipher_key'] = trans_cipher_key.hex()
            active_keys[key_id]['trans_cipher_key_addr'] = trans_cipher_key_addr
        if recv_cipher_key and recv_cipher_key_addr:
            active_keys[key_id]['recv_cipher_key'] = recv_cipher_key.hex()
            active_keys[key_id]['recv_cipher_key_addr'] = recv_cipher_key_addr

    # Store in active_keys for tracking
    active_keys[key_id]['trans_mackey_addr'] = trans_mackey_addr
    active_keys[key_id]['recv_mackey_addr'] = recv_mackey_addr
    active_keys[key_id]['trans_mackey'] = trans_mackey_data.hex()
    active_keys[key_id]['recv_mackey'] = recv_mackey_data.hex()

    # Write keys to keylog file
    timestamp = active_keys[key_id].get('generated_at', time.time())
    cipher_name = "chacha20-poly1305@openssh.com"

    # For Dropbear as server: trans=OUT (server->client), recv=IN (client->server)
    if trans_cipher_key and trans_poly1305_key:
        # Concatenate ChaCha20 key + Poly1305 key (64 bytes total)
        trans_full_key = trans_cipher_key.hex() + trans_poly1305_key.hex()
        write_keylog(timestamp, "OUT", cipher_name, trans_full_key, iv="unknown")
        log_event("KEYLOG_EXPORT", f"Exported trans (OUT) key: {trans_full_key[:32]}...")

    if recv_cipher_key and recv_poly1305_key:
        # Concatenate ChaCha20 key + Poly1305 key (64 bytes total)
        recv_full_key = recv_cipher_key.hex() + recv_poly1305_key.hex()
        write_keylog(timestamp, "IN", cipher_name, recv_full_key, iv="unknown")
        log_event("KEYLOG_EXPORT", f"Exported recv (IN) key: {recv_full_key[:32]}...")

def _recheck_keys(frame, key_id):
    """Re-extract keys after switch_keys() to see if they've been populated"""
    global _target, _debugger, _process

    process = frame.GetThread().GetProcess()
    target = process.GetTarget()

    # Check if watchpoints are disabled
    disable_watchpoints = os.environ.get('DISABLE_WATCHPOINTS', 'false').lower() == 'true'

    log_event("KEY_RECHECK", f"Re-checking keys for {key_id} after switch")

    # Find 'ses' global variable
    ses_var = target.FindFirstGlobalVariable("ses")
    if not ses_var.IsValid():
        log_event("KEY_RECHECK_ERROR", "'ses' global variable not found")
        return

    # Navigate to newkeys
    newkeys_var = ses_var.GetChildMemberWithName("newkeys")
    if not newkeys_var.IsValid():
        log_event("KEY_RECHECK_ERROR", "ses.newkeys not found")
        return

    newkeys_addr = newkeys_var.GetValueAsUnsigned()
    if newkeys_addr == 0:
        log_event("KEY_RECHECK_ERROR", "ses.newkeys is NULL")
        return

    # Get trans and recv structures
    trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
    recv_var = newkeys_var.Dereference().GetChildMemberWithName("recv")

    if not trans_var.IsValid() or not recv_var.IsValid():
        log_event("KEY_RECHECK_ERROR", "trans/recv structures not found")
        return

    # Get MAC keys
    trans_mackey = trans_var.GetChildMemberWithName("mackey")
    recv_mackey = recv_var.GetChildMemberWithName("mackey")

    if not trans_mackey.IsValid() or not recv_mackey.IsValid():
        log_event("KEY_RECHECK_ERROR", "mackey fields not found")
        return

    trans_mackey_addr = trans_mackey.GetLoadAddress()
    recv_mackey_addr = recv_mackey.GetLoadAddress()

    # Read actual key bytes
    trans_mackey_data = _read_bytes(process, trans_mackey_addr, 32)
    recv_mackey_data = _read_bytes(process, recv_mackey_addr, 32)

    if not trans_mackey_data or not recv_mackey_data:
        log_event("KEY_RECHECK_ERROR", "Failed to read MAC key data")
        return

    # Compare with previously extracted keys
    old_trans = active_keys[key_id].get('trans_mackey', '')
    old_recv = active_keys[key_id].get('recv_mackey', '')
    new_trans = trans_mackey_data.hex()
    new_recv = recv_mackey_data.hex()

    if old_trans != new_trans:
        log_event("KEY_RECHECK_CHANGED", f"trans_mackey CHANGED after switch_keys()")
        log_event("KEY_RECHECK_CHANGED", f"OLD: {old_trans[:64]}...")
        log_event("KEY_RECHECK_CHANGED", f"NEW: {new_trans[:64]}...")

        # Update stored key
        active_keys[key_id]['trans_mackey'] = new_trans
        active_keys[key_id]['trans_mackey_changed'] = True

        # Try to set watchpoint on new non-zero key (unless disabled)
        if not disable_watchpoints and new_trans != '00' * 32:
            log_event("KEY_RECHECK", "trans_mackey now has non-zero value, attempting watchpoint")
            _set_watchpoint("trans_mackey_post_switch", trans_mackey_addr, trans_mackey_data, key_id)
    else:
        log_event("KEY_RECHECK_UNCHANGED", f"trans_mackey unchanged (still {new_trans[:32]}...)")

    if old_recv != new_recv:
        log_event("KEY_RECHECK_CHANGED", f"recv_mackey CHANGED after switch_keys()")
        log_event("KEY_RECHECK_CHANGED", f"OLD: {old_recv[:64]}...")
        log_event("KEY_RECHECK_CHANGED", f"NEW: {new_recv[:64]}...")

        # Update stored key
        active_keys[key_id]['recv_mackey'] = new_recv
        active_keys[key_id]['recv_mackey_changed'] = True

        # Try to set watchpoint on new non-zero key (unless disabled)
        if not disable_watchpoints and new_recv != '00' * 32:
            log_event("KEY_RECHECK", "recv_mackey now has non-zero value, attempting watchpoint")
            _set_watchpoint("recv_mackey_post_switch", recv_mackey_addr, recv_mackey_data, key_id)
    else:
        log_event("KEY_RECHECK_UNCHANGED", f"recv_mackey unchanged (still {new_recv[:32]}...)")

def fork_callback(frame, bp_loc, internal_dict):
    """Callback when fork() is called - helps debug fork following"""
    thread = frame.GetThread()
    process = thread.GetProcess()

    print("\n" + "="*72)
    print(f"[FORK] fork() called in PID {process.GetProcessID()}")
    print(f"[FORK] Current thread: {thread.GetThreadID()}")
    print(f"[FORK] This means Dropbear is about to fork to handle SSH connection")
    print(f"[FORK] LLDB should now follow the child process (follow-fork-mode: child)")
    print("="*72 + "\n")

    # Return False to continue execution (don't stop)
    return False

def gen_new_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint for gen_new_keys()"""
    global _kex_counter

    # DIAGNOSTIC: Print immediately to verify callback fires
    thread = frame.GetThread()
    process = thread.GetProcess()
    print(f"\n{'='*72}")
    print(f"[CALLBACK_FIRED] gen_new_keys_entry() callback executing!")
    print(f"[CALLBACK_FIRED] Process PID: {process.GetProcessID()}")
    print(f"[CALLBACK_FIRED] Thread: {thread.GetThreadID()}")
    print(f"[CALLBACK_FIRED] KEX counter: {_kex_counter}")
    print(f"{'='*72}\n")

    timestamp = time.time()

    # Detect if this is a rekey (not first KEX)
    is_rekey = (_kex_counter > 0)
    event_type = "REKEY_ENTRY" if is_rekey else "KEX_ENTRY"
    event_msg = f"{'Rekey' if is_rekey else 'Initial KEX'} - Entered gen_new_keys() (call #{_kex_counter + 1})"

    log_event(event_type, event_msg, {'timestamp': timestamp, 'is_rekey': is_rekey, 'kex_number': _kex_counter + 1})

    # Dump memory before key generation
    thread = frame.GetThread()
    process = thread.GetProcess()
    dump_type = "rekey_entry" if is_rekey else "kex_entry"
    log_event("DUMP_START", f"Dumping memory before {'rekey' if is_rekey else 'key generation'}")
    dump_full_memory(process, dump_type)

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
            bp.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_exit")

    return False

def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys() - NOW WITH KEY EXTRACTION"""
    global next_key_id, _kex_counter
    timestamp = time.time()

    # Detect if this is a rekey
    is_rekey = (_kex_counter > 0)
    event_type = "REKEY_EXIT" if is_rekey else "KEX_EXIT"

    key_id = f"dropbear_key_{next_key_id}"
    next_key_id += 1

    # Increment KEX counter AFTER using it for detection
    _kex_counter += 1

    log_event(event_type, f"Key {key_id} {'rekeyed' if is_rekey else 'generated'} (KEX #{_kex_counter})", {
        'timestamp': timestamp,
        'is_rekey': is_rekey,
        'kex_number': _kex_counter
    })
    log_timing(key_id, "rekeyed" if is_rekey else "generated", timestamp)

    # Dump full memory after key generation
    thread = frame.GetThread()
    process = thread.GetProcess()
    dump_type = "rekey_exit" if is_rekey else "kex_exit"
    log_event("DUMP_START", f"Dumping memory after {'rekey' if is_rekey else 'key generation'} for {key_id}")
    dump_full_memory(process, dump_type, key_id)

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

        # Check if this m_burn range overlaps with any of our monitored key addresses
        burn_start = addr
        burn_end = addr + length
        cleared_any_key = False
        keys_to_dump = []

        for key_id, key_info in active_keys.items():
            # Check trans_mackey
            if 'trans_mackey_addr' in key_info:
                key_addr = key_info['trans_mackey_addr']
                if burn_start <= key_addr < burn_end:
                    key_name = f"{key_id}_trans_mac"
                    log_event("KEY_CLEARED", f"Key {key_id} trans_mackey cleared with m_burn at {addr:#x}")
                    log_timing(key_id, "cleared_trans_mac", timestamp)
                    cleared_any_key = True
                    if key_name not in _dumped_mburn_keys:
                        keys_to_dump.append(key_name)

            # Check recv_mackey
            if 'recv_mackey_addr' in key_info:
                key_addr = key_info['recv_mackey_addr']
                if burn_start <= key_addr < burn_end:
                    key_name = f"{key_id}_recv_mac"
                    log_event("KEY_CLEARED", f"Key {key_id} recv_mackey cleared with m_burn at {addr:#x}")
                    log_timing(key_id, "cleared_recv_mac", timestamp)
                    cleared_any_key = True
                    if key_name not in _dumped_mburn_keys:
                        keys_to_dump.append(key_name)

            # Check trans_cipher_key
            if 'trans_cipher_key_addr' in key_info:
                key_addr = key_info['trans_cipher_key_addr']
                if burn_start <= key_addr < burn_end:
                    key_name = f"{key_id}_trans_cipher"
                    log_event("KEY_CLEARED", f"Key {key_id} trans_cipher_key cleared with m_burn at {addr:#x}")
                    log_timing(key_id, "cleared_trans_cipher", timestamp)
                    cleared_any_key = True
                    if key_name not in _dumped_mburn_keys:
                        keys_to_dump.append(key_name)

            # Check recv_cipher_key
            if 'recv_cipher_key_addr' in key_info:
                key_addr = key_info['recv_cipher_key_addr']
                if burn_start <= key_addr < burn_end:
                    key_name = f"{key_id}_recv_cipher"
                    log_event("KEY_CLEARED", f"Key {key_id} recv_cipher_key cleared with m_burn at {addr:#x}")
                    log_timing(key_id, "cleared_recv_cipher", timestamp)
                    cleared_any_key = True
                    if key_name not in _dumped_mburn_keys:
                        keys_to_dump.append(key_name)

        # Dump strategy: Only dump if:
        # 1. Size >= 64 bytes (ChaCha20-Poly1305 key size), OR
        # 2. This m_burn is clearing a tracked key AND we haven't dumped it before
        should_dump = (length >= 64) or (cleared_any_key and keys_to_dump)

        if should_dump:
            if keys_to_dump:
                log_event("DUMP_START", f"Dumping FIRST m_burn for keys: {', '.join(keys_to_dump)} at {addr:#x} ({length} bytes)")
                # Mark these keys as dumped
                _dumped_mburn_keys.update(keys_to_dump)
            else:
                log_event("DUMP_START", f"Dumping large m_burn at {addr:#x} ({length} bytes)")

            dump_memory(process, addr, length, "m_burn_key_clear")
        elif cleared_any_key:
            log_event("DUMP_SKIP", f"Skipping duplicate m_burn dump at {addr:#x} (already dumped for these keys)")

    return False

def switch_keys_callback(frame, bp_loc, internal_dict):
    """Breakpoint for switch_keys() - RE-CHECK KEYS AND DUMP MEMORY"""
    timestamp = time.time()

    log_event("KEYS_ACTIVATED", "Keys activated via switch_keys()", {
        'timestamp': timestamp
    })

    if active_keys:
        latest_key = max(active_keys.keys(), key=lambda k: active_keys[k].get('generated_at', 0))
        log_timing(latest_key, "activated", timestamp)

        # RE-EXTRACT KEYS to see if they have values now
        log_event("KEY_RECHECK", f"Re-extracting keys for {latest_key} after switch_keys()")
        _recheck_keys(frame, latest_key)

        # Dump memory AFTER NEWKEYS activation (keys are now active)
        thread = frame.GetThread()
        process = thread.GetProcess()
        log_event("DUMP_START", f"Dumping memory after NEWKEYS activation (keys active for {latest_key})")
        dump_full_memory(process, "after_newkeys_activate", latest_key)

    return False

def kex_init_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint for KEX initialization functions
    Detects initial KEX vs rekey based on function name or KEX counter
    """
    global _kex_counter

    timestamp = time.time()
    func_name = frame.GetFunctionName() or "unknown"

    # Determine if this is initial KEX or rekey
    if "first" in func_name.lower():
        # Definitely initial KEX (kexfirstinitialise)
        is_rekey = False
        kex_type = "INITIAL_KEX"
    elif "recv_msg_kexinit" in func_name:
        # recv_msg_kexinit is called for both initial and rekey
        # If counter > 0, this is a rekey
        is_rekey = (_kex_counter > 0)
        kex_type = "REKEY_INIT" if is_rekey else "KEX_INIT"
        if is_rekey:
            _kex_counter += 1
    elif "kexinitialise" in func_name:
        # kexinitialise is only called for rekey (not first)
        is_rekey = True
        kex_type = "REKEY_KEX"
        _kex_counter += 1
    else:
        # send_msg_kexinit or other functions
        is_rekey = (_kex_counter > 0)
        kex_type = "KEX_MESSAGE"

    log_event(kex_type, f"Entered {func_name}() - {'Rekey' if is_rekey else 'Initial KEX'}", {
        'timestamp': timestamp,
        'function': func_name,
        'is_rekey': is_rekey,
        'kex_number': _kex_counter + 1
    })

    return False

def abort_callback(frame, bp_loc, internal_dict):
    """Breakpoint for connection abort/termination (dropbear_exit, send_msg_disconnect, etc.)"""
    timestamp = time.time()

    # Get function name that triggered this callback
    func_name = frame.GetFunctionName() or "unknown"

    log_event("CONNECTION_ABORT", f"Connection aborted via {func_name}", {
        'timestamp': timestamp,
        'function': func_name
    })

    # Dump memory before abort
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", f"Dumping memory before abort ({func_name})")
    dump_full_memory(process, "abort")

    # Log timing for any active keys
    for key_id in list(active_keys.keys()):
        log_timing(key_id, "aborted", timestamp)
        log_event("KEY_ABORTED", f"Key {key_id} aborted at {func_name}", {
            'key_id': key_id,
            'function': func_name
        })

    return False

def recv_msg_kexdh_init_callback(frame, bp_loc, internal_dict):
    """KEX DH init callback - BEFORE shared secret computation"""
    timestamp = time.time()
    log_event("KEX_DH_INIT", "Received KEX DH init message (before shared secret)", {'timestamp': timestamp})

    # Dump memory BEFORE shared secret K is computed
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory before shared secret computation")
    dump_full_memory(process, "before_kexdh_reply")

    return False

def send_msg_kexdh_reply_callback(frame, bp_loc, internal_dict):
    """KEX DH reply callback - AFTER shared secret computation"""
    timestamp = time.time()
    log_event("KEX_DH_REPLY", "Sending KEX DH reply message (after shared secret)", {'timestamp': timestamp})

    # Dump memory AFTER shared secret K is computed (but before it's cleared)
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory after shared secret computation")
    dump_full_memory(process, "after_kexdh_reply")

    return False

def send_msg_newkeys_callback(frame, bp_loc, internal_dict):
    """SSH NEWKEYS send callback - BEFORE keys are activated

    At this point:
    - Session keys have been derived (gen_new_keys just ran)
    - Shared secret K still exists in memory
    - Keys are about to be activated
    """
    timestamp = time.time()
    log_event("SSH_NEWKEYS_SEND", "Sending NEWKEYS message (keys derived, about to activate)", {'timestamp': timestamp})

    # Dump memory BEFORE keys are activated (K still exists)
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory before NEWKEYS activation (K still present)")
    dump_full_memory(process, "before_newkeys_activate")

    return False

def recv_msg_newkeys_callback(frame, bp_loc, internal_dict):
    """SSH NEWKEYS receive callback - AFTER keys are activated

    At this point:
    - Session keys are now ACTIVE
    - Client has confirmed key activation
    - Keys are in active use for encryption/decryption
    - Shared secret K should be cleared soon
    """
    timestamp = time.time()
    log_event("SSH_NEWKEYS_RECV", "Received NEWKEYS message (keys NOW ACTIVE)", {'timestamp': timestamp})

    # Dump memory AFTER keys are activated (active session keys)
    thread = frame.GetThread()
    process = thread.GetProcess()
    log_event("DUMP_START", "Dumping memory after NEWKEYS activation (keys ACTIVE)")
    dump_full_memory(process, "after_newkeys_activate")

    return False

def kex_comb_key_callback(frame, bp_loc, internal_dict):
    """
    Callback for kex*_comb_key functions that compute shared secret K.
    This captures the DH/ECDH/Curve25519 shared secret before it's cleared.
    Functions: kexdh_comb_key, kexecdh_comb_key, kexcurve25519_comb_key
    """
    timestamp = time.time()
    func_name = frame.GetFunctionName() or "unknown"

    log_event("SHARED_SECRET_COMPUTE", f"Computing shared secret in {func_name}", {
        'timestamp': timestamp,
        'function': func_name
    })

    # The shared secret K is computed and stored in ses.kexhashbuf
    # After the function returns, we'll need an exit breakpoint to capture it
    return False

def kex_comb_key_exit_callback(frame, bp_loc, internal_dict):
    """
    Exit callback for kex*_comb_key functions.
    Extracts shared_secret K from ses.kexhashbuf after computation.
    """
    timestamp = time.time()
    func_name = frame.GetFunctionName() or "unknown"

    try:
        # Get ses pointer (global variable in Dropbear)
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()

        # Find ses variable address
        ses_var = frame.FindVariable("ses")
        if not ses_var.IsValid():
            log_event("SHARED_SECRET_ERROR", f"Could not find 'ses' variable in {func_name}")
            return False

        ses_addr = ses_var.GetLoadAddress()
        if ses_addr == lldb.LLDB_INVALID_ADDRESS:
            log_event("SHARED_SECRET_ERROR", f"Invalid ses address in {func_name}")
            return False

        # In Dropbear, the shared secret K is stored as ses.dh_K (mp_int*)
        # LibTomMath mp_int structure:
        # typedef struct {
        #     int used, alloc;
        #     mp_sign sign;      (enum, typically 4 bytes)
        #     mp_digit *dp;      (pointer to digit array)
        # } mp_int;

        # Try to access ses.dh_K directly using LLDB
        dh_K_child = ses_var.GetChildMemberWithName("dh_K")

        if not dh_K_child.IsValid():
            log_event("SHARED_SECRET_ERROR", f"Could not find ses.dh_K field in {func_name}")
            log_timing("shared_secret_k", "created", timestamp)
            return False

        dh_K_ptr = dh_K_child.GetValueAsUnsigned(0)
        if dh_K_ptr == 0:
            log_event("SHARED_SECRET_ERROR", f"ses.dh_K is NULL in {func_name}")
            log_timing("shared_secret_k", "created", timestamp)
            return False

        # Read mp_int structure fields
        # Assuming: int (4 bytes), mp_sign (4 bytes), pointer (8 bytes on x64)
        error = lldb.SBError()

        # Read used (int at offset 0)
        used = process.ReadUnsignedFromMemory(dh_K_ptr, 4, error)
        if error.Fail():
            log_event("SHARED_SECRET_ERROR", f"Failed to read mp_int.used: {error}")
            log_timing("shared_secret_k", "created", timestamp)
            return False

        # Read alloc (int at offset 4)
        alloc = process.ReadUnsignedFromMemory(dh_K_ptr + 4, 4, error)
        if error.Fail():
            alloc = 0  # Not critical

        # Read sign (mp_sign at offset 8, assuming 4 bytes)
        sign = process.ReadUnsignedFromMemory(dh_K_ptr + 8, 4, error)
        if error.Fail():
            sign = 0  # Assume positive

        # Read dp pointer (at offset 12 on x86-64, assuming 8-byte alignment)
        # Structure packing may vary, try offset 16 (after padding)
        dp_ptr = process.ReadPointerFromMemory(dh_K_ptr + 16, error)
        if error.Fail() or dp_ptr == 0:
            # Try without padding at offset 12
            error.Clear()
            dp_ptr = process.ReadPointerFromMemory(dh_K_ptr + 12, error)
            if error.Fail() or dp_ptr == 0:
                log_event("SHARED_SECRET_ERROR", f"Failed to read mp_int.dp pointer: {error}")
                log_timing("shared_secret_k", "created", timestamp)
                return False

        # Read digits from dp array
        # mp_digit is typically uint32_t (4 bytes) or uint64_t (8 bytes)
        # Try 4 bytes first (most common)
        digit_size = 4  # Assume 32-bit digits
        max_digits = min(used, 128)  # Safety limit (up to 512 bytes for 4-byte digits)

        digits = []
        for i in range(max_digits):
            digit = process.ReadUnsignedFromMemory(dp_ptr + i * digit_size, digit_size, error)
            if error.Fail():
                break
            digits.append(digit)

        if not digits:
            log_event("SHARED_SECRET_ERROR", f"Failed to read any mp_int digits")
            log_timing("shared_secret_k", "created", timestamp)
            return False

        # Convert digits to bytes (little-endian digit array to big-endian bytes)
        # LibTomMath stores digits in little-endian order (least significant first)
        # SSH expects big-endian representation
        k_bytes = bytearray()
        for digit in reversed(digits):  # Reverse to get big-endian
            # Extract bytes from digit (little-endian within digit)
            for j in range(digit_size):
                k_bytes.append((digit >> (j * 8)) & 0xFF)

        # Trim leading zeros
        while len(k_bytes) > 1 and k_bytes[0] == 0:
            k_bytes = k_bytes[1:]

        k_hex = k_bytes.hex()

        log_event("SHARED_SECRET_COMPUTED", f"Shared secret K computed in {func_name}", {
            'timestamp': timestamp,
            'function': func_name,
            'K_length_bytes': len(k_bytes),
            'K_digits': len(digits),
            'K_hex': k_hex[:64] + "..." if len(k_hex) > 64 else k_hex
        })

        # Write to keylog file
        keylog_file = os.environ.get('LLDB_KEYLOG', '/data/keylogs/ssh_keylog.log')
        try:
            with open(keylog_file, 'a') as f:
                f.write(f"{int(timestamp)} SHARED_SECRET {k_hex}\n")
            log_event("KEYLOG", f"Wrote SHARED_SECRET to {keylog_file}")
        except Exception as e:
            log_event("KEYLOG_ERROR", f"Failed to write SHARED_SECRET: {e}")

        log_timing("shared_secret_k", "created", timestamp)

    except Exception as e:
        log_event("SHARED_SECRET_ERROR", f"Error extracting shared secret: {e}", {
            'timestamp': timestamp,
            'function': func_name,
            'error': str(e)
        })

    return False

# Export callbacks
__all__ = [
    'fork_callback',
    'gen_new_keys_entry',
    'gen_new_keys_exit',
    'm_burn_entry',
    'switch_keys_callback',
    'kex_init_callback',
    'abort_callback',
    'recv_msg_kexdh_init_callback',
    'send_msg_kexdh_reply_callback',
    'send_msg_newkeys_callback',
    'recv_msg_newkeys_callback',
    'kex_comb_key_callback',
    'kex_comb_key_exit_callback',
]

def __lldb_init_module(debugger, internal_dict):
    """Initialize module when imported by LLDB"""

    # Display configuration
    import os
    _wp_env = os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')
    _wp_enabled = _wp_env.lower() in ('true', '1', 'yes')

    print("=" * 72)
    print("Loading Dropbear callbacks...")
    print(f"[DROPBEAR_CB_VERSION] {__version__}")
    print(f"[DROPBEAR_CB_LOADED ] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_load_time))} local")
    print(f"[DROPBEAR_CB_FILE   ] {__file__}")
    print(f"Environment: LLDB_ENABLE_WATCHPOINTS = '{_wp_env}'")
    print(f"Configuration: Watchpoints {'ENABLED' if _wp_enabled else 'DISABLED'}")
    if not _wp_enabled:
        print("Mode: Memory dumps and key extraction only (no watchpoints)")
    else:
        print("Mode: Full monitoring with hardware watchpoints")
    print("=" * 72)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("ERROR: No valid target available")
        return

    # Set breakpoints
    bp1 = target.BreakpointCreateByName("gen_new_keys")
    bp1.SetScriptCallbackFunction("dropbear_callbacks.gen_new_keys_entry")
    bp1.SetAutoContinue(True)
    print(f"✓ Set breakpoint on gen_new_keys (bp {bp1.GetID()})")

    # Add breakpoints for KEX initialization functions to detect rekey
    for kex_func in ["kexfirstinitialise", "kexinitialise"]:
        bp_kex = target.BreakpointCreateByName(kex_func)
        if bp_kex.IsValid() and bp_kex.GetNumLocations() > 0:
            bp_kex.SetScriptCallbackFunction("dropbear_callbacks.kex_init_callback")
            bp_kex.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {kex_func} (bp {bp_kex.GetID()}, {bp_kex.GetNumLocations()} locations)")
        else:
            print(f"⚠ Could not set breakpoint on {kex_func} (static symbol or not found)")

    # Add KEX message handlers (called during both initial KEX and rekey)
    for kex_msg in ["recv_msg_kexinit", "send_msg_kexinit"]:
        bp_msg = target.BreakpointCreateByName(kex_msg)
        if bp_msg.IsValid():
            bp_msg.SetScriptCallbackFunction("dropbear_callbacks.kex_init_callback")
            bp_msg.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {kex_msg} for rekey detection (bp {bp_msg.GetID()})")

    for alt_name in ["recv_msg_kexdh_init", "send_msg_kexdh_reply", "send_msg_newkeys", "recv_msg_newkeys", "switch_keys"]:
        bp_alt = target.BreakpointCreateByName(alt_name)
        if bp_alt.IsValid():
            if alt_name == "switch_keys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.switch_keys_callback")
            elif alt_name == "recv_msg_kexdh_init":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.recv_msg_kexdh_init_callback")
            elif alt_name == "send_msg_kexdh_reply":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.send_msg_kexdh_reply_callback")
            elif alt_name == "send_msg_newkeys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.send_msg_newkeys_callback")
            elif alt_name == "recv_msg_newkeys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks.recv_msg_newkeys_callback")
            bp_alt.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {alt_name} (bp {bp_alt.GetID()})")

    # Add shared secret extraction breakpoints (for handshake secret K)
    for kex_func in ["kexdh_comb_key", "kexecdh_comb_key", "kexcurve25519_comb_key"]:
        bp_kex = target.BreakpointCreateByName(kex_func)
        if bp_kex.IsValid() and bp_kex.GetNumLocations() > 0:
            bp_kex.SetScriptCallbackFunction("dropbear_callbacks.kex_comb_key_exit_callback")
            bp_kex.SetOneShot(False)  # Should fire on every call (initial + rekey)
            bp_kex.SetAutoContinue(True)
            print(f"✓ Set shared secret breakpoint on {kex_func} (bp {bp_kex.GetID()})")
        else:
            print(f"⚠ Could not set breakpoint on {kex_func} (static symbol or not found)")

    bp2 = target.BreakpointCreateByName("m_burn")
    bp2.SetScriptCallbackFunction("dropbear_callbacks.m_burn_entry")
    bp2.SetAutoContinue(True)
    print(f"✓ Set breakpoint on m_burn (bp {bp2.GetID()})")

    for func_name in ["session_cleanup", "cleanup_keys"]:
        bp = target.BreakpointCreateByName(func_name)
        if bp.IsValid():
            bp.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {func_name} (bp {bp.GetID()})")

    # Abort/termination breakpoints (default: dropbear_exit)
    # Note: Use environment variable DROPBEAR_ABORT_HOOKS to enable additional hooks
    # Example: DROPBEAR_ABORT_HOOKS="send_msg_disconnect,dropbear_close"
    abort_hooks = os.environ.get('DROPBEAR_ABORT_HOOKS', 'dropbear_exit').split(',')
    for func_name in abort_hooks:
        func_name = func_name.strip()
        if func_name:
            bp_abort = target.BreakpointCreateByName(func_name)
            if bp_abort.IsValid():
                bp_abort.SetScriptCallbackFunction("dropbear_callbacks.abort_callback")
                bp_abort.SetAutoContinue(True)
                print(f"✓ Set abort breakpoint on {func_name} (bp {bp_abort.GetID()})")
            else:
                print(f"⚠ Warning: Abort function '{func_name}' not found in binary")

    # Verify module-level configuration matches what we read
    global ENABLE_WATCHPOINTS
    print(f"\nVerification: Module-level ENABLE_WATCHPOINTS = {ENABLE_WATCHPOINTS}")
    if ENABLE_WATCHPOINTS != _wp_enabled:
        print(f"WARNING: Mismatch detected! Module={ENABLE_WATCHPOINTS}, Local={_wp_enabled}")
        # Override the module-level variable to match the current environment
        ENABLE_WATCHPOINTS = _wp_enabled
        print(f"Corrected: ENABLE_WATCHPOINTS now set to {ENABLE_WATCHPOINTS}")

    # Success messages based on configuration
    if ENABLE_WATCHPOINTS:
        print("\n✓ Dropbear callbacks loaded successfully (hardware watchpoints ENABLED)")
        print("  Hardware watchpoints will be set when keys are generated")
    else:
        print("\n✓ Dropbear callbacks loaded successfully (hardware watchpoints DISABLED)")
        print("  Memory dumps and key extraction will proceed without watchpoints")

    print(f"  Abort hooks: {', '.join(abort_hooks)}")

    # Add a breakpoint on fork() itself to detect when Dropbear forks
    print("\n" + "="*72)
    print("Setting up fork detection...")
    bp_fork = target.BreakpointCreateByName("fork")
    if bp_fork.IsValid() and bp_fork.GetNumLocations() > 0:
        bp_fork.SetScriptCallbackFunction("dropbear_callbacks.fork_callback")
        bp_fork.SetAutoContinue(False)  # Stop on fork to verify it's happening
        print(f"✓ Set breakpoint on fork() (bp {bp_fork.GetID()}, {bp_fork.GetNumLocations()} locations)")
        print("  This will fire when Dropbear forks to handle SSH connection")
    else:
        print("⚠ Could not set breakpoint on fork() - will rely on follow-fork-mode")

    print("="*72)
