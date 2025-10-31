#!/usr/bin/env python3
"""
Dropbear SSH Server v5.0 - LLDB Callbacks with Dual Key Extraction

Features:
- Fork tracking (follow first fork only - connection handler)
- Dual extraction strategy:
  1. gen_new_keys() - Extract 6 keys (A-F) from ses.newkeys structure
  2. hashkeys() - Validate KDF derivation by capturing parameters
- Manual dump commands (d, dump, manual_dump_now)
- Watchpoint runtime controls (disabled by default)
- Architecture-agnostic (ARM64/x86-64)

Usage:
  (lldb) command script import /opt/lldb/dropbear_server_callbacks.py
  (lldb) server_setup_monitoring
  (lldb) server_auto_continue

Author: TLS-Haze Research Framework
Date: 2025-10-31
"""

import lldb
import os
import sys
import time
import struct

# ============================================================================
#  GLOBAL STATE
# ============================================================================

_target = None
_process = None
_debugger = None
_thread = None

# Fork tracking
_fork_count = 0  # 0=parent, 1=connection (FOLLOW), 2=auth (STOP)

# KEX tracking
_kex_count = 0
_kex_session = 0

# Extraction mode
_extraction_mode = "dual"  # Extract from both gen_new_keys and hashkeys

# Key storage for validation
_gen_new_keys_data = {}  # Keys extracted from gen_new_keys
_hashkeys_data = {}      # Keys extracted from hashkeys

# Watchpoint storage
_watchpoints = {}
_watchpoints_enabled = True

# Manual dump integration
try:
    from ssh_memory_dump import SSHMemoryDump
    _dumper = None
except ImportError:
    _dumper = None
    print("[WARNING] ssh_memory_dump not available - manual dumps disabled")

# Environment configuration
_keylog_path = os.getenv('LLDB_KEYLOG', '/data/keylogs/dropbear_server_keylog.log')
_timing_csv_path = os.getenv('LLDB_RESULTS_DIR', '/data/lldb_results') + '/timing_dropbear_server.csv'
_dumps_dir = os.getenv('LLDB_DUMPS_DIR', '/data/dumps')

# Watchpoint control (disabled by default for server)
_watchpoints_enabled = os.getenv('LLDB_ENABLE_WATCHPOINTS', 'false').lower() == 'true'

# Auto-disable breakpoints after KEX (enabled by default for interactive sessions)
_auto_disable_breakpoints = os.getenv('LLDB_AUTO_DISABLE_BREAKPOINTS', 'true').lower() == 'true'

# Auto-search for extracted keys in memory (disabled by default - can be slow)
_auto_search_keys = os.getenv('LLDB_AUTO_SEARCH_KEYS', 'false').lower() == 'true'

# Key buffer addresses (for manual verification)
_key_buffer_addresses = {}  # letter -> (addr, length, kex_session)

print(f"[DROPBEAR_SERVER_v5.0] Callbacks loaded")
print(f"[CONFIG] Keylog: {_keylog_path}")
print(f"[CONFIG] Timing CSV: {_timing_csv_path}")
print(f"[CONFIG] Dumps: {_dumps_dir}")
print(f"[CONFIG] Watchpoints: {'ENABLED' if _watchpoints_enabled else 'DISABLED (default)'}")
print(f"[CONFIG] Auto-disable breakpoints: {'ENABLED (default)' if _auto_disable_breakpoints else 'DISABLED'}")
print(f"[CONFIG] Auto-search keys: {'ENABLED' if _auto_search_keys else 'DISABLED (default)'}")
print(f"[CONFIG] Extraction mode: {_extraction_mode.upper()}")

# ============================================================================
#  HELPER FUNCTIONS
# ============================================================================

def write_keylog(cookie_hex, key_type, key_hex, iv_hex=None, mac_hex=None):
    """Write key to SSH keylog file (Wireshark format)"""
    try:
        os.makedirs(os.path.dirname(_keylog_path), exist_ok=True)
        with open(_keylog_path, 'a') as f:
            # Format: cookie NEWKEYS MODE IN/OUT CIPHER name KEY key IV iv [MAC mac]
            # Simplified for validation: cookie NEWKEYS key_type key_hex
            line = f"{cookie_hex} NEWKEYS {key_type} KEY {key_hex}"
            if iv_hex:
                line += f" IV {iv_hex}"
            if mac_hex:
                line += f" MAC {mac_hex}"
            f.write(line + "\n")
            f.flush()
        print(f"[KEYLOG] {key_type}: {key_hex[:32]}...")
    except Exception as e:
        print(f"[ERROR] Failed to write keylog: {e}")

def write_timing_csv(key_id, event, details=""):
    """Write timing event to CSV"""
    try:
        timestamp = time.time()
        os.makedirs(os.path.dirname(_timing_csv_path), exist_ok=True)

        # Create header if file doesn't exist
        if not os.path.exists(_timing_csv_path):
            with open(_timing_csv_path, 'w') as f:
                f.write("timestamp,key_id,event,details\n")

        with open(_timing_csv_path, 'a') as f:
            f.write(f"{timestamp},{key_id},{event},{details}\n")
            f.flush()
        print(f"[TIMING] {key_id}: {event}")
    except Exception as e:
        print(f"[ERROR] Failed to write timing: {e}")

def get_architecture():
    """Detect CPU architecture"""
    triple = _target.GetTriple()
    if 'aarch64' in triple or 'arm64' in triple:
        return 'aarch64'
    elif 'x86_64' in triple:
        return 'x86_64'
    else:
        return 'unknown'

def get_return_address(frame):
    """Get return address (architecture-agnostic)"""
    arch = get_architecture()
    if arch == 'aarch64':
        lr = frame.FindRegister("lr")
        return lr.GetValueAsUnsigned() if lr.IsValid() else 0
    elif arch == 'x86_64':
        rsp = frame.FindRegister("rsp")
        if rsp.IsValid():
            error = lldb.SBError()
            ret_addr = _process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
            return ret_addr if error.Success() else 0
    return 0

# ============================================================================
#  FORK TRACKING
# ============================================================================

def fork_callback(frame, bp_loc, internal_dict):
    """
    Track fork() calls to follow first fork only

    Dropbear server fork pattern:
    - Fork #1: Connection handler (FOLLOW THIS)
    - Fork #2: Authentication/session process (DON'T FOLLOW)
    """
    global _fork_count
    _fork_count += 1

    print(f"\n[FORK] ==================== Fork #{_fork_count} Detected ====================")

    if _fork_count == 1:
        print("[FORK] ✓ First fork (connection handler) - continuing to follow")
        print("[FORK] This fork will handle the SSH connection and KEX")
        return False  # Continue following

    elif _fork_count == 2:
        print("[FORK] ✗ Second fork (auth/session process) detected")
        print("[FORK] NOTE: LLDB configured to NOT follow second fork")
        print("[FORK] (settings set target.process.follow-fork-mode child stops at first fork)")
        return False

    else:
        print(f"[FORK] Unexpected fork #{_fork_count} - check fork strategy")
        return False

# ============================================================================
#  GEN_NEW_KEYS EXTRACTION (Primary Method)
# ============================================================================

def gen_new_keys_entry(frame, bp_loc, internal_dict):
    """
    Entry breakpoint for gen_new_keys()

    Sets exit breakpoint at return address to capture derived keys
    """
    global _kex_session
    _kex_session += 1

    print(f"\n[SERVER_KEX_ENTRY] ==================== gen_new_keys() ENTRY (KEX #{_kex_session}) ====================")
    print(f"[SERVER_KEX_ENTRY] Fork count: {_fork_count} (should be 1 for connection handler)")

    # Get return address
    ret_addr = get_return_address(frame)
    if ret_addr == 0:
        print("[ERROR] Failed to get return address")
        return False

    print(f"[SERVER_KEX_ENTRY] Return address: 0x{ret_addr:x}")

    # Set one-shot exit breakpoint
    bp = _target.BreakpointCreateByAddress(ret_addr)
    bp.SetOneShot(True)
    bp.SetScriptCallbackFunction("dropbear_server_callbacks.gen_new_keys_exit")

    print(f"[SERVER_KEX_ENTRY] Exit breakpoint set at 0x{ret_addr:x}")
    return False

def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """
    Exit breakpoint for gen_new_keys()

    Extract 6 keys (A-F) from ses.newkeys structure:
    - Key A/B: IV client→server, IV server→client
    - Key C/D: Encryption client→server, Encryption server→client
    - Key E/F: MAC client→server, MAC server→client

    Keys stored in ses.newkeys->trans/recv->cipher_state (ChaCha20-Poly1305)
    """
    global _gen_new_keys_data

    print(f"\n[SERVER_KEX_EXIT] ==================== gen_new_keys() EXIT (KEX #{_kex_session}) ====================")

    try:
        # Navigate: ses (global) -> newkeys -> trans/recv -> cipher_state
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print("[ERROR] Could not find 'ses' global variable")
            return False

        ses_var = ses_list.GetValueAtIndex(0)
        print(f"[SERVER_KEX_EXIT] Found ses at: {ses_var.GetAddress()}")

        # Get newkeys pointer
        newkeys = ses_var.GetChildMemberWithName("newkeys")
        if not newkeys.IsValid():
            print("[ERROR] Could not access ses.newkeys")
            return False

        # Dereference newkeys pointer
        newkeys_addr = newkeys.GetValueAsUnsigned()
        print(f"[SERVER_KEX_EXIT] newkeys pointer: 0x{newkeys_addr:x}")

        error = lldb.SBError()
        newkeys_deref = _target.CreateValueFromAddress("newkeys_deref",
                                                        lldb.SBAddress(newkeys_addr, _target),
                                                        newkeys.GetType().GetPointeeType())

        # Extract trans (transmit) keys - server→client (D, F)
        trans = newkeys_deref.GetChildMemberWithName("trans")
        cipher_state_trans = trans.GetChildMemberWithName("cipher_state")
        trans_cipher_addr = cipher_state_trans.GetAddress().GetLoadAddress(_target)

        print(f"[SERVER_KEX_EXIT] trans.cipher_state at: 0x{trans_cipher_addr:x}")

        # Read ChaCha20-Poly1305 state (80 bytes total)
        trans_cipher_data = _process.ReadMemory(trans_cipher_addr, 80, error)
        if not error.Success():
            print(f"[ERROR] Failed to read trans cipher_state: {error}")
            return False

        # Validate ChaCha20 constant (bytes 0-15: "expand 32-byte k")
        chacha_constant = trans_cipher_data[:16]
        if chacha_constant != b'expand 32-byte k':
            print(f"[WARNING] Unexpected ChaCha20 constant: {chacha_constant.hex()}")

        # Extract keys from trans (server→client)
        key_d_enc = trans_cipher_data[16:48]  # Encryption key (bytes 16-47)
        key_f_mac = trans_cipher_data[48:80]  # Poly1305 key (bytes 48-79)

        print(f"[SERVER_KEX_EXIT] ✓ Key D (server→client ENC): {key_d_enc.hex()}")
        print(f"[SERVER_KEX_EXIT] ✓ Key F (server→client MAC): {key_f_mac.hex()}")

        # Extract recv (receive) keys - client→server (C, E)
        recv = newkeys_deref.GetChildMemberWithName("recv")
        cipher_state_recv = recv.GetChildMemberWithName("cipher_state")
        recv_cipher_addr = cipher_state_recv.GetAddress().GetLoadAddress(_target)

        print(f"[SERVER_KEX_EXIT] recv.cipher_state at: 0x{recv_cipher_addr:x}")

        recv_cipher_data = _process.ReadMemory(recv_cipher_addr, 80, error)
        if not error.Success():
            print(f"[ERROR] Failed to read recv cipher_state: {error}")
            return False

        # Extract keys from recv (client→server)
        key_c_enc = recv_cipher_data[16:48]  # Encryption key
        key_e_mac = recv_cipher_data[48:80]  # Poly1305 key

        print(f"[SERVER_KEX_EXIT] ✓ Key C (client→server ENC): {key_c_enc.hex()}")
        print(f"[SERVER_KEX_EXIT] ✓ Key E (client→server MAC): {key_e_mac.hex()}")

        # Store for validation against hashkeys
        _gen_new_keys_data[_kex_session] = {
            'C': key_c_enc,
            'D': key_d_enc,
            'E': key_e_mac,
            'F': key_f_mac
        }

        # Write to keylog
        cookie = f"SERVER_KEX{_kex_session:02d}"
        write_keylog(cookie, "KEY_C_CLIENT_TO_SERVER_ENC", key_c_enc.hex())
        write_keylog(cookie, "KEY_D_SERVER_TO_CLIENT_ENC", key_d_enc.hex())
        write_keylog(cookie, "KEY_E_CLIENT_TO_SERVER_MAC", key_e_mac.hex())
        write_keylog(cookie, "KEY_F_SERVER_TO_CLIENT_MAC", key_f_mac.hex())

        # Write timing events
        write_timing_csv(f"KEY_C_KEX{_kex_session}", "created", "gen_new_keys extraction")
        write_timing_csv(f"KEY_D_KEX{_kex_session}", "created", "gen_new_keys extraction")

        # Set watchpoints if enabled
        if _watchpoints_enabled:
            _set_watchpoint_for_key("KEY_C", recv_cipher_addr + 16, key_c_enc, _kex_session)
            _set_watchpoint_for_key("KEY_D", trans_cipher_addr + 16, key_d_enc, _kex_session)

        print(f"[SERVER_KEX_EXIT] ==================== gen_new_keys() Complete ====================\n")

        # After KEX extraction, optionally disable all breakpoints to allow normal operation
        # This is critical for Dropbear's two-fork architecture:
        # - Fork #1 (connection handler) - LLDB follows this, KEX extraction completed ✓
        # - Fork #2 (session handler) - Must proceed without LLDB intervention
        if _auto_disable_breakpoints:
            print("[SERVER_KEX_EXIT] Auto-disabling all breakpoints to allow session fork...")
            for i in range(_target.GetNumBreakpoints()):
                bp = _target.GetBreakpointAtIndex(i)
                if bp.IsValid():
                    bp.SetEnabled(False)
                    print(f"[SERVER_KEX_EXIT]   ✓ Disabled breakpoint #{bp.GetID()}")

            print("[SERVER_KEX_EXIT] ✓ All breakpoints disabled - Dropbear can now fork normally")
            print("[SERVER_KEX_EXIT] Session will proceed: auth → fork #2 → shell")
        else:
            print("[SERVER_KEX_EXIT] Auto-disable breakpoints: DISABLED")
            print("[SERVER_KEX_EXIT] ⚠ Breakpoints remain active - may interfere with fork #2")
            print("[SERVER_KEX_EXIT] Tip: Use 'breakpoint disable' manually if needed")

    except Exception as e:
        print(f"[ERROR] Exception in gen_new_keys_exit: {e}")
        import traceback
        traceback.print_exc()

    return False

def _set_watchpoint_for_key(key_name, addr, key_value, kex_session):
    """Set one-shot hardware watchpoint on key"""
    try:
        error = lldb.SBError()
        wp = _target.WatchAddress(addr, 32, False, True, error)  # 32 bytes, read=False, write=True

        if not error.Success():
            print(f"[WATCHPOINT] ✗ Failed to set watchpoint for {key_name}: {error}")
            return

        wp_id = wp.GetID()

        # Create callback function
        callback_name = f"_wp_callback_{key_name}_KEX{kex_session}"
        callback_code = f"""
def {callback_name}(frame, wp, internal_dict):
    print(f"[WATCHPOINT] ✓ {key_name} overwritten at KEX{kex_session} (address: 0x{addr:x})")
    import time
    from dropbear_server_callbacks import write_timing_csv
    write_timing_csv(f"{key_name}_KEX{kex_session}", "overwritten", f"Watchpoint at 0x{addr:x}")
    return False  # One-shot: disable after first hit
"""

        # Inject callback into namespace
        _debugger.HandleCommand(f"script {callback_code}")

        # Attach callback to watchpoint
        _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")

        _watchpoints[f"{key_name}_KEX{kex_session}"] = {'id': wp_id, 'addr': addr, 'enabled': True}
        print(f"[WATCHPOINT] ✓ Set for {key_name} at 0x{addr:x} (wp#{wp_id})")

    except Exception as e:
        print(f"[WATCHPOINT] ✗ Exception setting watchpoint for {key_name}: {e}")

# ============================================================================
#  HASHKEYS EXTRACTION (Validation Method)
# ============================================================================

def hashkeys_entry(frame, bp_loc, internal_dict):
    """
    Entry breakpoint for hashkeys()

    Signature: static void hashkeys(unsigned char *keybuf, unsigned int keylen,
                                     struct kex_hash_state *hs, unsigned char letter)

    Captures parameters to validate against gen_new_keys extraction
    """
    print(f"\n[HASHKEYS_ENTRY] hashkeys() called")

    arch = get_architecture()

    try:
        # Try to read from function parameters first (more reliable than registers after prologue)
        outlen_var = frame.FindVariable("outlen")
        out_var = frame.FindVariable("out")
        letter_var = frame.FindVariable("X")
        hs_var = frame.FindVariable("hs")

        if outlen_var.IsValid() and out_var.IsValid() and letter_var.IsValid():
            # Read from local variables (most reliable)
            keylen = outlen_var.GetValueAsUnsigned()
            keybuf_addr = out_var.GetValueAsUnsigned()
            letter = letter_var.GetValueAsUnsigned()
            hs_addr = hs_var.GetValueAsUnsigned() if hs_var.IsValid() else 0
            print(f"[HASHKEYS_ENTRY] Read from variables: outlen={keylen}, out=0x{keybuf_addr:x}")
        elif arch == 'aarch64':
            # ARM64 calling convention: x0-x3 (fallback to registers)
            keybuf_addr = frame.FindRegister("x0").GetValueAsUnsigned()
            keylen = frame.FindRegister("w1").GetValueAsUnsigned()
            hs_addr = frame.FindRegister("x2").GetValueAsUnsigned()
            letter = frame.FindRegister("w3").GetValueAsUnsigned()
            print(f"[HASHKEYS_ENTRY] Read from ARM64 registers")
        elif arch == 'x86_64':
            # x86-64 calling convention: rdi, esi, rdx, ecx
            keybuf_addr = frame.FindRegister("rdi").GetValueAsUnsigned()
            keylen = frame.FindRegister("esi").GetValueAsUnsigned()
            hs_addr = frame.FindRegister("rdx").GetValueAsUnsigned()
            letter = frame.FindRegister("ecx").GetValueAsUnsigned()
            print(f"[HASHKEYS_ENTRY] Read from x86_64 registers")
        else:
            print(f"[ERROR] Unsupported architecture: {arch}")
            return False

        letter_char = chr(letter) if 65 <= letter <= 70 else '?'

        # Validate keylen
        if keylen == 0:
            print(f"[WARNING] keylen is 0 for key '{letter_char}' - skipping hashkeys extraction")
            return False

        print(f"[HASHKEYS_ENTRY] Parameters:")
        print(f"  keybuf:  0x{keybuf_addr:x}")
        print(f"  keylen:  {keylen} bytes")
        print(f"  hs:      0x{hs_addr:x}")
        print(f"  letter:  '{letter_char}' (0x{letter:02x})")

        # Set exit breakpoint to capture derived key
        ret_addr = get_return_address(frame)
        if ret_addr == 0:
            print("[ERROR] Failed to get return address for hashkeys")
            return False

        # Store parameters for exit callback
        if not hasattr(hashkeys_exit, '_pending_calls'):
            hashkeys_exit._pending_calls = []

        hashkeys_exit._pending_calls.append({
            'keybuf_addr': keybuf_addr,
            'keylen': keylen,
            'letter': letter_char,
            'kex_session': _kex_session
        })

        # Set exit breakpoint
        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetScriptCallbackFunction("dropbear_server_callbacks.hashkeys_exit")

        print(f"[HASHKEYS_ENTRY] Exit breakpoint set at 0x{ret_addr:x}")

    except Exception as e:
        print(f"[ERROR] Exception in hashkeys_entry: {e}")
        import traceback
        traceback.print_exc()

    return False

def _search_key_in_memory(key_data, ignore_size_limit=False, verbose=False):
    """
    Helper function to search for a key in all process memory regions

    Args:
        key_data: bytes object containing the key to search for
        ignore_size_limit: If True, search all regions regardless of size (default: False)
        verbose: If True, print debug information about searched regions

    Returns:
        List of dicts with 'address', 'module', 'section' for each match
    """
    matches = []
    error = lldb.SBError()
    regions_searched = 0
    regions_skipped = 0

    if verbose:
        print(f"[SEARCH_DEBUG] Starting memory search for {len(key_data)} byte pattern")
        print(f"[SEARCH_DEBUG] Ignore size limit: {ignore_size_limit}")

    # First, check if we have stored buffer addresses (most efficient)
    if verbose and _key_buffer_addresses:
        print(f"[SEARCH_DEBUG] Known key buffer addresses: {len(_key_buffer_addresses)}")
        for letter, (addr, length, kex_session) in _key_buffer_addresses.items():
            print(f"[SEARCH_DEBUG]   Key '{letter}': 0x{addr:x} ({length} bytes, KEX {kex_session})")

    # Search in loaded modules (code sections, data sections)
    if verbose:
        print(f"[SEARCH_DEBUG] Searching loaded module sections...")

    for module in _target.module_iter():
        for section in module.section_iter():
            if not section.IsValid():
                continue

            addr = section.GetLoadAddress(_target)
            size = section.GetByteSize()

            if addr == lldb.LLDB_INVALID_ADDRESS or size == 0:
                continue

            # Read section memory
            data = _process.ReadMemory(addr, size, error)
            if not error.Success():
                if verbose:
                    print(f"[SEARCH_DEBUG]   ✗ Failed to read {module.GetFileSpec().GetFilename()}/{section.GetName()} (0x{addr:x})")
                continue

            regions_searched += 1
            if verbose:
                print(f"[SEARCH_DEBUG]   ✓ Searched {module.GetFileSpec().GetFilename()}/{section.GetName()} (0x{addr:x}, {size} bytes)")

            # Search for pattern
            offset = 0
            while True:
                pos = data.find(key_data, offset)
                if pos == -1:
                    break

                match_addr = addr + pos
                matches.append({
                    'address': match_addr,
                    'module': module.GetFileSpec().GetFilename(),
                    'section': section.GetName()
                })
                if verbose:
                    print(f"[SEARCH_DEBUG]     → FOUND at 0x{match_addr:x}")
                offset = pos + 1

    # Also search ALL memory regions (includes heap, stack, anonymous mappings)
    if verbose:
        print(f"[SEARCH_DEBUG] Searching memory regions via GetMemoryRegions()...")

    try:
        regions = _process.GetMemoryRegions()
        total_regions = regions.GetSize()
        if verbose:
            print(f"[SEARCH_DEBUG]   Total memory regions: {total_regions}")

        # Create SBMemoryRegionInfo object for API compatibility
        region_info = lldb.SBMemoryRegionInfo()

        for i in range(total_regions):
            # New API: pass region_info as argument (it gets populated)
            if not regions.GetMemoryRegionAtIndex(i, region_info):
                regions_skipped += 1
                if verbose:
                    print(f"[SEARCH_DEBUG]   ✗ Region {i}: Failed to get region info")
                continue

            addr = region_info.GetRegionBase()
            size = region_info.GetRegionEnd() - addr

            # Get region permissions for debugging
            is_readable = region_info.IsReadable()
            is_writable = region_info.IsWritable()
            is_executable = region_info.IsExecutable()
            perms = ('r' if is_readable else '-') + ('w' if is_writable else '-') + ('x' if is_executable else '-')

            # Skip unreadable regions
            if not is_readable:
                regions_skipped += 1
                if verbose:
                    print(f"[SEARCH_DEBUG]   - Region {i}: 0x{addr:x}-0x{region_info.GetRegionEnd():x} ({size} bytes, {perms}) - SKIPPED (not readable)")
                continue

            # Skip very large regions unless override is specified
            if not ignore_size_limit and size > 100 * 1024 * 1024:  # Skip >100MB regions
                regions_skipped += 1
                if verbose:
                    print(f"[SEARCH_DEBUG]   - Region {i}: 0x{addr:x}-0x{region_info.GetRegionEnd():x} ({size} bytes, {perms}) - SKIPPED (too large)")
                continue

            data = _process.ReadMemory(addr, size, error)
            if not error.Success():
                regions_skipped += 1
                if verbose:
                    print(f"[SEARCH_DEBUG]   ✗ Region {i}: 0x{addr:x}-0x{region_info.GetRegionEnd():x} ({size} bytes, {perms}) - READ FAILED")
                continue

            regions_searched += 1
            if verbose:
                print(f"[SEARCH_DEBUG]   ✓ Region {i}: 0x{addr:x}-0x{region_info.GetRegionEnd():x} ({size} bytes, {perms})")

            offset = 0
            while True:
                pos = data.find(key_data, offset)
                if pos == -1:
                    break

                match_addr = addr + pos
                # Avoid duplicates
                if not any(m['address'] == match_addr for m in matches):
                    matches.append({
                        'address': match_addr,
                        'module': 'memory',
                        'section': f'region_{i}_0x{addr:x}'
                    })
                    if verbose:
                        print(f"[SEARCH_DEBUG]     → FOUND at 0x{match_addr:x}")
                offset = pos + 1
    except Exception as e:
        if verbose:
            print(f"[SEARCH_DEBUG] Exception during memory region search: {e}")
        import traceback
        if verbose:
            traceback.print_exc()

    if verbose:
        print(f"[SEARCH_DEBUG] Search complete: {regions_searched} regions searched, {regions_skipped} skipped, {len(matches)} matches")

    return matches

def hashkeys_exit(frame, bp_loc, internal_dict):
    """
    Exit breakpoint for hashkeys()

    Reads derived key from keybuf and validates against gen_new_keys
    """
    print(f"\n[HASHKEYS_EXIT] hashkeys() returned")

    try:
        if not hasattr(hashkeys_exit, '_pending_calls') or not hashkeys_exit._pending_calls:
            print("[WARNING] No pending hashkeys call data")
            return False

        params = hashkeys_exit._pending_calls.pop(0)

        keybuf_addr = params['keybuf_addr']
        keylen = params['keylen']
        letter = params['letter']
        kex_session = params['kex_session']

        # Validate keylen before reading
        if keylen == 0 or keylen > 1024:
            print(f"[WARNING] Invalid keylen ({keylen}) for key '{letter}' - skipping")
            return False

        # Read derived key from keybuf
        error = lldb.SBError()
        key_data = _process.ReadMemory(keybuf_addr, keylen, error)

        if not error.Success():
            print(f"[ERROR] Failed to read keybuf: {error}")
            return False

        print(f"[HASHKEYS_EXIT] Key '{letter}' derived: {key_data.hex()}")
        print(f"[HASHKEYS_EXIT] Memory location: 0x{keybuf_addr:x} ({keylen} bytes)")
        print(f"[HASHKEYS_EXIT] KEX session: {kex_session}")

        # Store buffer address for manual verification
        _key_buffer_addresses[letter] = (keybuf_addr, keylen, kex_session)

        # Optional auto-search for key in all memory regions
        if _auto_search_keys:
            print(f"[AUTO_SEARCH] Searching for key '{letter}' in memory...")
            matches = _search_key_in_memory(key_data)

            if matches:
                print(f"[AUTO_SEARCH] ✓ Found {len(matches)} match(es):")
                for i, match in enumerate(matches, 1):
                    addr_hex = f"0x{match['address']:x}"
                    if match['address'] == keybuf_addr:
                        print(f"[AUTO_SEARCH]   {i}. {addr_hex} (expected location)")
                    else:
                        print(f"[AUTO_SEARCH]   {i}. {addr_hex} ({match['module']}/{match['section']})")
            else:
                print(f"[AUTO_SEARCH] ✗ Key not found in memory (unexpected!)")

        # Store for validation
        if kex_session not in _hashkeys_data:
            _hashkeys_data[kex_session] = {}
        _hashkeys_data[kex_session][letter] = key_data

        # Validate against gen_new_keys if available
        if kex_session in _gen_new_keys_data:
            gen_key = _gen_new_keys_data[kex_session].get(letter)
            if gen_key:
                if gen_key == key_data:
                    print(f"[VALIDATION] ✓ Key '{letter}' matches gen_new_keys extraction")
                else:
                    print(f"[VALIDATION] ✗ Key '{letter}' MISMATCH!")
                    print(f"  gen_new_keys: {gen_key.hex()}")
                    print(f"  hashkeys:     {key_data.hex()}")
            else:
                print(f"[VALIDATION] Key '{letter}' not in gen_new_keys data")
        else:
            print(f"[VALIDATION] KEX session {kex_session} not yet processed by gen_new_keys")

    except Exception as e:
        print(f"[ERROR] Exception in hashkeys_exit: {e}")
        import traceback
        traceback.print_exc()

    return False

# Initialize pending calls list
hashkeys_exit._pending_calls = []

# ============================================================================
#  MANUAL DUMP COMMANDS
# ============================================================================

def manual_dump_now(debugger, command, result, internal_dict):
    """Manual memory dump command"""
    global _dumper

    if _dumper is None:
        try:
            from ssh_memory_dump import SSHMemoryDump
            _dumper = SSHMemoryDump(_target, _process, _dumps_dir)
        except Exception as e:
            result.AppendMessage(f"[ERROR] Failed to initialize dumper: {e}")
            return

    label = command.strip() if command.strip() else "manual"
    try:
        dump_file = _dumper.dump_heap(label)
        result.AppendMessage(f"[DUMP] Created: {dump_file}")
    except Exception as e:
        result.AppendMessage(f"[ERROR] Dump failed: {e}")

def quick_dump(debugger, command, result, internal_dict):
    """Quick dump command (alias for 'd')"""
    manual_dump_now(debugger, command, result, internal_dict)

def findkey(debugger, command, result, internal_dict):
    """
    Search for a key in process memory

    Usage:
        findkey <hex_string>              # Normal search (skip regions >100MB)
        findkey --full <hex_string>       # Full search (all memory regions)
        findkey 1a2b3c4d5e6f...

    Searches the entire heap for the specified hex pattern.
    """
    command = command.strip()

    # Parse flags: --full and --verbose
    full_search = False
    verbose = False

    while command.startswith('--'):
        if command.startswith('--full'):
            full_search = True
            command = command[6:].strip()
        elif command.startswith('--verbose'):
            verbose = True
            command = command[9:].strip()
        else:
            break

    hex_string = command

    if not hex_string:
        result.AppendMessage("[FINDKEY] Usage: findkey [--full] [--verbose] <hex_string>")
        result.AppendMessage("[FINDKEY] Example: findkey 1a2b3c4d5e6f70819293a4b5c6d7e8f9")
        result.AppendMessage("[FINDKEY] Example: findkey --full 1a2b3c4d5e6f70819293a4b5c6d7e8f9")
        result.AppendMessage("[FINDKEY] Example: findkey --verbose d77f8b958dc1fec97a70368199e04cb3")
        result.AppendMessage("[FINDKEY] Example: findkey --full --verbose <hex>")
        result.AppendMessage("[FINDKEY] ")
        result.AppendMessage("[FINDKEY] Flags:")
        result.AppendMessage("[FINDKEY]   --full      Search ALL memory regions (may be slow)")
        result.AppendMessage("[FINDKEY]   --verbose   Show debug output (regions searched, permissions, etc.)")
        return

    # Remove spaces and validate hex
    hex_string = hex_string.replace(" ", "").replace(":", "")

    try:
        search_bytes = bytes.fromhex(hex_string)
    except ValueError:
        result.AppendMessage(f"[FINDKEY] ✗ Invalid hex string: {hex_string}")
        return

    result.AppendMessage(f"[FINDKEY] Searching for key: {hex_string}")
    result.AppendMessage(f"[FINDKEY] Length: {len(search_bytes)} bytes")
    if full_search:
        result.AppendMessage(f"[FINDKEY] Mode: FULL (searching all memory regions)")
        result.AppendMessage(f"[FINDKEY] Warning: This may take 30-60 seconds...")

    # Search in process memory
    matches = []
    error = lldb.SBError()

    # Get memory regions
    for module in _target.module_iter():
        for section in module.section_iter():
            if not section.IsValid():
                continue

            addr = section.GetLoadAddress(_target)
            size = section.GetByteSize()

            if addr == lldb.LLDB_INVALID_ADDRESS or size == 0:
                continue

            # Read section memory
            data = _process.ReadMemory(addr, size, error)
            if not error.Success():
                continue

            # Search for pattern
            offset = 0
            while True:
                pos = data.find(search_bytes, offset)
                if pos == -1:
                    break

                match_addr = addr + pos
                matches.append({
                    'address': match_addr,
                    'module': module.GetFileSpec().GetFilename(),
                    'section': section.GetName()
                })
                offset = pos + 1

    # Also search heap (using /proc/self/maps on Linux)
    try:
        maps = _process.GetMemoryRegions()
        for i in range(maps.GetSize()):
            region = maps.GetMemoryRegionAtIndex(i)
            addr = region.GetRegionBase()
            size = region.GetRegionEnd() - addr

            # Skip very large regions unless --full is specified
            if not full_search and size > 100 * 1024 * 1024:  # Skip >100MB in normal mode
                continue

            data = _process.ReadMemory(addr, size, error)
            if not error.Success():
                continue

            offset = 0
            while True:
                pos = data.find(search_bytes, offset)
                if pos == -1:
                    break

                match_addr = addr + pos
                # Avoid duplicates
                if not any(m['address'] == match_addr for m in matches):
                    matches.append({
                        'address': match_addr,
                        'module': 'heap',
                        'section': f'region_{i}'
                    })
                offset = pos + 1
    except:
        pass  # Heap search optional

    # Use enhanced search (with verbose support)
    # Note: This duplicates some logic above but will be refactored
    matches_enhanced = _search_key_in_memory(search_bytes, ignore_size_limit=full_search, verbose=verbose)

    # Merge with existing matches (avoid duplicates)
    for m in matches_enhanced:
        if not any(existing['address'] == m['address'] for existing in matches):
            matches.append(m)

    # Display results
    if matches:
        result.AppendMessage(f"\n[FINDKEY] ✓ Found {len(matches)} match(es):\n")
        for i, match in enumerate(matches, 1):
            result.AppendMessage(f"  {i}. Address: 0x{match['address']:x}")
            result.AppendMessage(f"     Module: {match['module']}")
            result.AppendMessage(f"     Section: {match['section']}")
            result.AppendMessage("")
    else:
        result.AppendMessage("[FINDKEY] ✗ Key not found in memory")

    result.AppendMessage(f"[FINDKEY] Search complete ({len(matches)} matches)")

# ============================================================================
#  WATCHPOINT RUNTIME CONTROLS
# ============================================================================

def watchpoints_toggle(debugger, command, result, internal_dict):
    """Toggle all watchpoints on/off"""
    global _watchpoints_enabled

    _watchpoints_enabled = not _watchpoints_enabled

    for name, wp_info in _watchpoints.items():
        wp = _target.FindWatchpointByID(wp_info['id'])
        if wp.IsValid():
            wp.SetEnabled(_watchpoints_enabled)

    status = "ENABLED" if _watchpoints_enabled else "DISABLED"
    result.AppendMessage(f"[WATCHPOINTS] {status} (count: {len(_watchpoints)})")

def watchpoints_status(debugger, command, result, internal_dict):
    """Show watchpoint status"""
    status = "ENABLED" if _watchpoints_enabled else "DISABLED"
    result.AppendMessage(f"[WATCHPOINTS] Status: {status}")
    result.AppendMessage(f"[WATCHPOINTS] Count: {len(_watchpoints)}")

    if _watchpoints:
        result.AppendMessage("\nActive watchpoints:")
        for name, wp_info in _watchpoints.items():
            wp = _target.FindWatchpointByID(wp_info['id'])
            if wp.IsValid():
                enabled = "✓" if wp.IsEnabled() else "✗"
                result.AppendMessage(f"  {enabled} {name} (wp#{wp_info['id']}) at 0x{wp_info['addr']:x}")

def watchpoints_list(debugger, command, result, internal_dict):
    """Detailed watchpoint list"""
    if not _watchpoints:
        result.AppendMessage("[WATCHPOINTS] No watchpoints set")
        return

    result.AppendMessage(f"[WATCHPOINTS] Total: {len(_watchpoints)}\n")
    for name, wp_info in _watchpoints.items():
        wp = _target.FindWatchpointByID(wp_info['id'])
        if wp.IsValid():
            result.AppendMessage(f"Watchpoint #{wp_info['id']}: {name}")
            result.AppendMessage(f"  Address: 0x{wp_info['addr']:x}")
            result.AppendMessage(f"  Enabled: {wp.IsEnabled()}")
            result.AppendMessage(f"  Hit count: {wp.GetHitCount()}")
            result.AppendMessage("")

# ============================================================================
#  SETUP COMMANDS
# ============================================================================

def server_setup_monitoring(debugger, command, result, internal_dict):
    """Setup all server monitoring breakpoints"""
    global _target, _process, _debugger, _dumper

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*80)
    print("  Dropbear Server Monitoring Setup (v5.0 - Dual Extraction)")
    print("="*80)

    # Initialize dumper
    if _dumper is None:
        try:
            from ssh_memory_dump import SSHMemoryDump
            _dumper = SSHMemoryDump(_target, _process, _dumps_dir)
            print("[SETUP] ✓ Memory dumper initialized")
        except:
            print("[SETUP] ⚠️  Memory dumper not available")

    # Set breakpoints
    breakpoints = [
        ('fork', 'dropbear_server_callbacks.fork_callback', 'Fork tracking'),
        ('gen_new_keys', 'dropbear_server_callbacks.gen_new_keys_entry', 'Primary key extraction'),
        ('hashkeys', 'dropbear_server_callbacks.hashkeys_entry', 'KDF validation')
    ]

    for func_name, callback, description in breakpoints:
        bp = _target.BreakpointCreateByName(func_name)
        if bp.GetNumLocations() > 0:
            bp.SetScriptCallbackFunction(callback)
            print(f"[SETUP] ✓ Breakpoint set: {func_name} ({description})")
        else:
            print(f"[SETUP] ✗ Failed to set breakpoint: {func_name}")

    # Register commands
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_toggle watchpoints_toggle')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_status watchpoints_status')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_list watchpoints_list')

    print("\n[SETUP] ✓ Server monitoring configured")
    print("\nAvailable commands:")
    print("  server_auto_continue     - Run with automatic breakpoint continuation")
    print("  d                        - Quick manual dump")
    print("  dump <label>             - Manual dump with label")
    print("  findkey <hex>            - Search for key in memory")
    print("  watchpoints_toggle       - Enable/disable all watchpoints")
    print("  watchpoints_status       - Show watchpoint status")
    print("  watchpoints_list         - Detailed watchpoint list")
    print("\n" + "="*80 + "\n")

def server_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue through breakpoints"""
    print("[AUTO_CONTINUE] Starting automatic continuation...")
    print("[AUTO_CONTINUE] Press Ctrl+C to stop")
    print("[AUTO_CONTINUE] Server will process client connections and extract keys")
    debugger.HandleCommand('continue')

# Register setup commands
def __lldb_init_module(debugger, internal_dict):
    """Module initialization"""
    global _debugger
    _debugger = debugger

    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.server_setup_monitoring server_setup_monitoring')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.server_auto_continue server_auto_continue')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.manual_dump_now dump')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.quick_dump d')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.findkey findkey')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_toggle watchpoints_toggle')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_status watchpoints_status')
    debugger.HandleCommand('command script add --overwrite -f dropbear_server_callbacks.watchpoints_list watchpoints_list')

    print("[DROPBEAR_SERVER_v5.0] Module initialized")
    print("[DROPBEAR_SERVER_v5.0] Use 'server_setup_monitoring' to configure breakpoints")
