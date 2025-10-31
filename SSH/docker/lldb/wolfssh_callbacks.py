#!/usr/bin/env python3
"""
wolfSSH LLDB callbacks with hardware watchpoints for precise key lifecycle tracking.
Based on successful Dropbear implementation

wolfSSH Key Management:
- GenerateKeys() generates encryption/MAC keys after KEX
- Keys stored in ssh->handshake->keys and ssh->handshake->peerKeys
- Key structure: Keys { encKey[AES_256_KEY_SIZE], macKey[MAX_HMAC_SZ] }
- Keys cleared with ForceZero() (wolfSSL's secure memory clearing)

Automated Testing Support:
- Microsecond-precision timestamps
- Rekey detection via KEX counter
- Full memory dumps at 8+ checkpoints
- Environment variable configuration
"""

import lldb
import json
import time
import os
import struct
from datetime import datetime

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

# Configuration from environment variables
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/ssh_keylog_wolfssh.log')
ENABLE_MEMORY_DUMPS = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'true').lower() == 'true'
# Watchpoints: Check per-client variable first, then fall back to generic (default: enabled)
ENABLE_WATCHPOINTS = os.environ.get('LLDB_ENABLE_WATCHPOINTS_WOLFSSH',
                                    os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')).lower() == 'true'

# Log configuration at startup
print(f"[WOLFSSH_CONFIG] Watchpoints: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
print(f"[WOLFSSH_CONFIG] Memory dumps: {'ENABLED' if ENABLE_MEMORY_DUMPS else 'DISABLED'}")

# Global state for KEX tracking (rekey detection)
_kex_counter = 0
_session_started = False

def get_microsecond_timestamp():
    """Get high-precision timestamp with microseconds"""
    now = datetime.now()
    return now.timestamp()  # Returns float with microsecond precision

def format_timestamp_us(ts):
    """Format timestamp with microseconds for logging"""
    dt = datetime.fromtimestamp(ts)
    return dt.strftime('%Y%m%d_%H%M%S_%f')

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
_watchpoints = {}
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
    """Set hardware watchpoint using the proven IPsec pattern"""
    global _watchpoints, _target, _debugger

    # Check if watchpoints are enabled
    if not ENABLE_WATCHPOINTS:
        print(f"[WATCHPOINT] Disabled by configuration (LLDB_ENABLE_WATCHPOINTS=false)")
        return

    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    if not _debugger or not _target:
        print(f"[WATCHPOINT] ERROR: No debugger/target for {key_name}")
        return

    try:
        print(f"[WATCHPOINT] Attempting to set watchpoint on {key_name} at 0x{address:x}")
        print(f"[WATCHPOINT] Key data length: {len(key_data)} bytes")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

        error = lldb.SBError()
        watchpoint = _target.WatchAddress(address, 4, False, True, error)

        print(f"[WATCHPOINT] error.Success(): {error.Success()}")
        print(f"[WATCHPOINT] watchpoint.IsValid(): {watchpoint.IsValid() if watchpoint else 'None'}")

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] FAILED to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()
        print(f"[WATCHPOINT] Successfully created watchpoint ID {wp_id} for {key_name}")

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name.replace('-', '_')}"

        # Fixed values for f-string
        fixed_addr = address
        fixed_key_name = key_name
        fixed_key_id = key_id
        fixed_key_hex = key_data.hex() if key_data else "unknown"

        # Generate callback code (IPsec pattern with microsecond timestamps)
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    """Watchpoint callback for {fixed_key_name} at 0x{fixed_addr:x}"""
    from datetime import datetime
    timestamp = datetime.now().timestamp()  # Microsecond precision

    print(f"[KEY_OVERWRITE] {fixed_key_name} overwritten at {{timestamp}}")
    print(f"[KEY_OVERWRITE] Address: 0x{fixed_addr:x}")
    print(f"[KEY_OVERWRITE] Original key: {fixed_key_hex[:64]}...")

    try:
        from ssh_monitor import log_timing
        log_timing("{fixed_key_id}", "overwritten", timestamp)
    except:
        pass

    # Return False for one-shot watchpoint (project-wide standard)
    return False
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
    """Extract keys from ssh->handshake->keys and set hardware watchpoints"""
    global _target, _debugger, _process

    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    _target = target
    _debugger = target.GetDebugger()
    _process = process

    ptr_size = target.GetAddressByteSize()
    log_event("KEY_EXTRACT", f"Extracting keys from wolfSSH for {key_id}")

    # Get 'ssh' parameter (first argument to GenerateKeys)
    arch = target.GetTriple().split('-')[0]
    if 'x86_64' in arch or 'amd64' in arch:
        ssh_reg = frame.FindRegister("rdi")
    elif 'aarch64' in arch or 'arm64' in arch:
        ssh_reg = frame.FindRegister("x0")
    else:
        log_event("KEY_EXTRACT_ERROR", f"Unsupported architecture: {arch}")
        return

    if not ssh_reg:
        log_event("KEY_EXTRACT_ERROR", "Could not read ssh parameter")
        return

    ssh_addr = ssh_reg.GetValueAsUnsigned()
    log_event("KEY_EXTRACT", f"WOLFSSH* ssh at 0x{ssh_addr:x}")

    # Try to use debug symbols to navigate structure
    ssh_value = target.CreateValueFromAddress("ssh", lldb.SBAddress(ssh_addr, target),
                                             target.FindFirstType("WOLFSSH"))

    if ssh_value.IsValid():
        handshake_var = ssh_value.GetChildMemberWithName("handshake")
        if handshake_var.IsValid():
            handshake_addr = handshake_var.GetValueAsUnsigned()
            if handshake_addr != 0:
                log_event("KEY_EXTRACT", f"HandshakeInfo* at 0x{handshake_addr:x}")

                # Get keys from handshake->keys
                handshake_value = handshake_var.Dereference()
                keys_var = handshake_value.GetChildMemberWithName("keys")
                peer_keys_var = handshake_value.GetChildMemberWithName("peerKeys")

                if keys_var.IsValid():
                    # Extract our keys (outgoing)
                    enc_key_var = keys_var.GetChildMemberWithName("encKey")
                    mac_key_var = keys_var.GetChildMemberWithName("macKey")

                    if enc_key_var.IsValid() and mac_key_var.IsValid():
                        enc_key_addr = enc_key_var.GetLoadAddress()
                        mac_key_addr = mac_key_var.GetLoadAddress()

                        enc_key_data = _read_bytes(process, enc_key_addr, 32)
                        mac_key_data = _read_bytes(process, mac_key_addr, 32)

                        if enc_key_data and mac_key_data:
                            log_event("KEY_EXTRACT_SUCCESS", f"Extracted OUT encKey: {_hex_dump(enc_key_data, 32)}")
                            log_event("KEY_EXTRACT_SUCCESS", f"Extracted OUT macKey: {_hex_dump(mac_key_data, 32)}")

                            # Set watchpoints
                            _set_watchpoint("keys_encKey", enc_key_addr, enc_key_data, key_id)
                            _set_watchpoint("keys_macKey", mac_key_addr, mac_key_data, key_id)

                            # Store in active_keys
                            active_keys[key_id]['out_encKey'] = enc_key_data.hex()
                            active_keys[key_id]['out_macKey'] = mac_key_data.hex()
                            active_keys[key_id]['out_encKey_addr'] = enc_key_addr
                            active_keys[key_id]['out_macKey_addr'] = mac_key_addr

                            # Write to keylog
                            timestamp = active_keys[key_id].get('generated_at', time.time())
                            out_full_key = enc_key_data.hex() + mac_key_data.hex()
                            write_keylog(timestamp, "OUT", "aes256-cbc", out_full_key, iv="unknown")

                if peer_keys_var.IsValid():
                    # Extract peer keys (incoming)
                    peer_enc_key_var = peer_keys_var.GetChildMemberWithName("encKey")
                    peer_mac_key_var = peer_keys_var.GetChildMemberWithName("macKey")

                    if peer_enc_key_var.IsValid() and peer_mac_key_var.IsValid():
                        peer_enc_key_addr = peer_enc_key_var.GetLoadAddress()
                        peer_mac_key_addr = peer_mac_key_var.GetLoadAddress()

                        peer_enc_key_data = _read_bytes(process, peer_enc_key_addr, 32)
                        peer_mac_key_data = _read_bytes(process, peer_mac_key_addr, 32)

                        if peer_enc_key_data and peer_mac_key_data:
                            log_event("KEY_EXTRACT_SUCCESS", f"Extracted IN encKey: {_hex_dump(peer_enc_key_data, 32)}")
                            log_event("KEY_EXTRACT_SUCCESS", f"Extracted IN macKey: {_hex_dump(peer_mac_key_data, 32)}")

                            # Set watchpoints (use remaining 2 of 4 hardware watchpoints)
                            _set_watchpoint("peerKeys_encKey", peer_enc_key_addr, peer_enc_key_data, key_id)
                            _set_watchpoint("peerKeys_macKey", peer_mac_key_addr, peer_mac_key_data, key_id)

                            # Store in active_keys
                            active_keys[key_id]['in_encKey'] = peer_enc_key_data.hex()
                            active_keys[key_id]['in_macKey'] = peer_mac_key_data.hex()
                            active_keys[key_id]['in_encKey_addr'] = peer_enc_key_addr
                            active_keys[key_id]['in_macKey_addr'] = peer_mac_key_addr

                            # Write to keylog
                            timestamp = active_keys[key_id].get('generated_at', time.time())
                            in_full_key = peer_enc_key_data.hex() + peer_mac_key_data.hex()
                            write_keylog(timestamp, "IN", "aes256-cbc", in_full_key, iv="unknown")
    else:
        log_event("KEY_EXTRACT_ERROR", "Could not resolve wolfSSH structure with debug symbols")

def generate_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint for GenerateKeys()"""
    global _kex_counter, _session_started

    timestamp = get_microsecond_timestamp()
    _kex_counter += 1

    # Detect rekey (KEX after initial connection)
    event_type = "REKEY_ENTRY" if _kex_counter > 1 else "KEX_ENTRY"
    is_rekey = _kex_counter > 1

    log_event(event_type, f"Entered GenerateKeys() (KEX #{_kex_counter})", {
        'timestamp': timestamp,
        'timestamp_formatted': format_timestamp_us(timestamp),
        'kex_number': _kex_counter,
        'is_rekey': is_rekey
    })

    thread = frame.GetThread()
    process = thread.GetProcess()

    # Memory dump before key generation (if enabled)
    if ENABLE_MEMORY_DUMPS:
        dump_tag = "rekey_entry" if is_rekey else "kex_entry"
        log_event("DUMP_START", f"Dumping memory before key generation (KEX #{_kex_counter})")
        dump_full_memory(process, dump_tag)
    else:
        log_event("DUMP_SKIP", "Memory dumps disabled by configuration")

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
            bp.SetScriptCallbackFunction("wolfssh_callbacks.generate_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("wolfssh_callbacks.generate_keys_exit")

    return False

def generate_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for GenerateKeys() - WITH KEY EXTRACTION"""
    global next_key_id, _kex_counter
    timestamp = get_microsecond_timestamp()

    key_id = f"wolfssh_key_{next_key_id}"
    next_key_id += 1

    # Detect rekey
    is_rekey = _kex_counter > 1
    event_type = "REKEY_EXIT" if is_rekey else "KEX_EXIT"

    log_event(event_type, f"Key {key_id} generated (KEX #{_kex_counter})", {
        'timestamp': timestamp,
        'timestamp_formatted': format_timestamp_us(timestamp),
        'key_id': key_id,
        'kex_number': _kex_counter,
        'is_rekey': is_rekey
    })
    log_timing(key_id, "generated", timestamp)

    thread = frame.GetThread()
    process = thread.GetProcess()

    # Memory dump after key generation (if enabled)
    if ENABLE_MEMORY_DUMPS:
        dump_tag = "rekey_exit" if is_rekey else "kex_exit"
        log_event("DUMP_START", f"Dumping memory after key generation for {key_id}")
        dump_full_memory(process, dump_tag, key_id)
    else:
        log_event("DUMP_SKIP", "Memory dumps disabled by configuration")

    # Initialize key tracking
    active_keys[key_id] = {
        'generated_at': timestamp,
        'timestamp_formatted': format_timestamp_us(timestamp),
        'status': 'active',
        'kex_number': _kex_counter,
        'is_rekey': is_rekey
    }

    # EXTRACT KEYS AND SET WATCHPOINTS (watchpoints respect ENABLE_WATCHPOINTS)
    _extract_and_watch_keys(frame, key_id)

    return False

def force_zero_entry(frame, bp_loc, internal_dict):
    """Breakpoint for ForceZero() - passive detection of key clearing"""
    timestamp = get_microsecond_timestamp()

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

        log_event("FORCE_ZERO_CALL", f"ForceZero called at {addr:#x}, size {length} bytes", {
            'timestamp': timestamp,
            'timestamp_formatted': format_timestamp_us(timestamp),
            'address': addr,
            'size': length
        })

        # Check if this range overlaps with any of our monitored key addresses
        burn_start = addr
        burn_end = addr + length

        for key_id, key_info in active_keys.items():
            # Check all key addresses
            for key_type in ['out_encKey_addr', 'out_macKey_addr', 'in_encKey_addr', 'in_macKey_addr']:
                if key_type in key_info:
                    key_addr = key_info[key_type]
                    if burn_start <= key_addr < burn_end:
                        log_event("KEY_CLEARED", f"Key {key_id} {key_type} cleared with ForceZero", {
                            'timestamp': timestamp,
                            'timestamp_formatted': format_timestamp_us(timestamp),
                            'address': addr,
                            'key_id': key_id,
                            'key_type': key_type
                        })
                        log_timing(key_id, f"cleared_{key_type}", timestamp)

                        # Update key status
                        if 'status' in key_info:
                            key_info['status'] = 'cleared'

        # Dump large clears (may contain keys) - if enabled
        if length >= 16 and ENABLE_MEMORY_DUMPS:
            log_event("DUMP_START", f"Dumping ForceZero at {addr:#x} ({length} bytes)")
            dump_memory(process, addr, length, "force_zero_large")
        elif length >= 16:
            log_event("DUMP_SKIP", "Memory dumps disabled by configuration")

    return False

# Export callbacks
__all__ = [
    'generate_keys_entry',
    'generate_keys_exit',
    'force_zero_entry',
    'do_new_keys_entry',
]

def do_new_keys_entry(frame, bp_loc, internal_dict):
    """
    Breakpoint for DoNewKeys() - where keys are activated after KEX.
    This is called after key derivation to activate the new encryption/MAC keys.
    *** This function fires successfully! ***
    """
    global _kex_counter, next_key_id

    timestamp = get_microsecond_timestamp()

    log_event("DO_NEW_KEYS", f"DoNewKeys() called (KEX #{_kex_counter})", {
        'timestamp': timestamp,
        'timestamp_formatted': format_timestamp_us(timestamp),
        'kex_number': _kex_counter
    })

    # Log to separate file for visibility (fix file path)
    log_dir = os.path.dirname(KEYLOG_PATH)
    try:
        with open(os.path.join(log_dir, 'do_new_keys.log'), 'a') as f:
            f.write(f"[{timestamp}] DO_NEW_KEYS: KEX #{_kex_counter}\n")
    except:
        pass

    # Try to extract keys here (DoNewKeys is where keys get activated)
    # This is our best chance since wc_SSH_KDF/wolfSSH_KDF aren't firing
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    key_id = next_key_id
    next_key_id += 1

    log_event("KEY_EXTRACT_DONEWKEYS", f"Attempting key extraction from DoNewKeys (key_id={key_id})")

    # Extract keys using same method as generate_keys_exit
    _extract_and_watch_keys(frame, key_id)

    return False

def wolfssh_accept_entry(frame, bp_loc, internal_dict):
    """
    Entry breakpoint for wolfSSH_accept() - for visibility into connection flow.
    This function is called early in the SSH connection lifecycle and may help
    identify when/where KEX actually occurs.
    """
    try:
        # Simple log message
        print("[ACCEPT_ENTRY] wolfSSH_accept() called")

        # Try to log to file if possible (fix file path)
        try:
            log_dir = os.path.dirname(KEYLOG_PATH)
            with open(os.path.join(log_dir, 'wolfssh_accept.log'), 'a') as f:
                import time
                f.write(f"[{time.time()}] ACCEPT_ENTRY: wolfSSH_accept() called\n")
        except:
            pass  # Ignore file errors

    except Exception as e:
        print(f"[ACCEPT_ENTRY_ERROR] Exception in callback: {e}")

    # No return statement - let function complete naturally (auto-continue is set on breakpoint)

def __lldb_init_module(debugger, internal_dict):
    """Initialize module when imported by LLDB"""
    print("Loading wolfSSH callbacks with hardware watchpoints...")

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("ERROR: No valid target available")
        return

    # OPTION 1: Add wolfSSH_accept breakpoint for visibility
    # Note: Symbol may not be resolved until library loads, but set callback anyway
    bp0 = target.BreakpointCreateByName("wolfSSH_accept")
    bp0.SetScriptCallbackFunction("wolfssh_callbacks.wolfssh_accept_entry")
    bp0.SetAutoContinue(True)
    print(f"✓ Set breakpoint on wolfSSH_accept (bp {bp0.GetID()}) - for visibility (may resolve after launch)")

    # Set breakpoints on wolfSSH_KDF (GenerateKeys is static, can't breakpoint by name)
    bp1 = target.BreakpointCreateByName("wolfSSH_KDF")
    bp1.SetScriptCallbackFunction("wolfssh_callbacks.generate_keys_entry")
    bp1.SetAutoContinue(True)
    print(f"✓ Set breakpoint on wolfSSH_KDF (bp {bp1.GetID()})")

    # OPTION 3: Add wc_SSH_KDF (wolfSSL backend - likely the real KDF being called)
    bp3 = target.BreakpointCreateByName("wc_SSH_KDF")
    bp3.SetScriptCallbackFunction("wolfssh_callbacks.generate_keys_entry")
    bp3.SetAutoContinue(True)
    print(f"✓ Set breakpoint on wc_SSH_KDF (wolfSSL backend KDF, bp {bp3.GetID()})")

    # OPTION 3: Add DoNewKeys (where keys are activated after KEX)
    bp4 = target.BreakpointCreateByName("DoNewKeys")
    bp4.SetScriptCallbackFunction("wolfssh_callbacks.do_new_keys_entry")
    bp4.SetAutoContinue(True)
    print(f"✓ Set breakpoint on DoNewKeys (key activation, bp {bp4.GetID()})")

    bp2 = target.BreakpointCreateByName("ForceZero")
    bp2.SetScriptCallbackFunction("wolfssh_callbacks.force_zero_entry")
    bp2.SetAutoContinue(True)
    print(f"✓ Set breakpoint on ForceZero (bp {bp2.GetID()})")

    print("wolfSSH callbacks with hardware watchpoints loaded successfully")
    print("Hardware watchpoints will be set when keys are generated")
    print("Note: Trying wc_SSH_KDF (wolfSSL backend) in addition to wolfSSH_KDF")
    print("Note: DoNewKeys added to track when keys are activated")
    print("Note: wolfSSH_accept added for connection flow visibility")
