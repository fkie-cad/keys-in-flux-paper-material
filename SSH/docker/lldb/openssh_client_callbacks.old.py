#!/usr/bin/env python3
"""
OpenSSH Client-Side Callbacks

Client-side monitoring for OpenSSH - simpler than server-side because:
- No forking (single process)
- Client initiates KEX
- Straightforward LLDB flow

Hooks kex_derive_keys() to extract session keys from client perspective.
"""

import lldb
import time
import os
import datetime

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_key_extracted = False
_keys_extracted_count = 0

# LLDB objects
_target = None
_debugger = None
_process = None

# Keylog path from environment
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/openssh_client_keylog.log')

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_microsecond_timestamp():
    """Get current timestamp with microsecond precision"""
    return datetime.datetime.now().timestamp()

def format_timestamp_us(ts):
    """Format timestamp with microsecond precision"""
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')

def write_keylog(key_type, key_hex):
    """Write extracted key to keylog file"""
    try:
        timestamp = get_microsecond_timestamp()
        with open(KEYLOG_PATH, 'a') as f:
            f.write(f"[{format_timestamp_us(timestamp)}] CLIENT {key_type}: {key_hex}\n")
        print(f"[OPENSSH_CLIENT] ✓ {key_type} logged to {KEYLOG_PATH}")
    except Exception as e:
        print(f"[OPENSSH_CLIENT] ERROR writing keylog: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def __lldb_init_module(debugger, internal_dict):
    """Called when script is imported by LLDB"""
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.openssh_setup_monitoring openssh_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.openssh_auto_continue openssh_auto_continue'
    )
    print("[OPENSSH_CLIENT] Commands registered: openssh_setup_monitoring, openssh_auto_continue")

# ═══════════════════════════════════════════════════════════════════════════
# KEY DERIVATION CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════

def kex_derive_keys_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint on kex_derive_keys() - OpenSSH's main key derivation function

    This function is called after KEX completes to derive all session keys.
    We extract keys from the ssh struct which contains kex, newkeys, etc.
    """
    global _keys_extracted_count, _target, _debugger

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    _keys_extracted_count += 1

    print(f"\n[OPENSSH_KEX] kex_derive_keys() called in PID {pid} (KEX #{_keys_extracted_count})")

    try:
        # OpenSSH passes 'ssh' struct as first argument
        # On ARM64: x0, on x86-64: rdi

        # Try ARM64 first
        ssh_arg = frame.FindRegister("x0")
        if not ssh_arg or ssh_arg.GetValueAsUnsigned() == 0:
            # Try x86-64
            ssh_arg = frame.FindRegister("rdi")

        if not ssh_arg or ssh_arg.GetValueAsUnsigned() == 0:
            print(f"[OPENSSH_KEX] ERROR: Could not find ssh struct argument")
            return False

        ssh_ptr = ssh_arg.GetValueAsUnsigned()
        print(f"[OPENSSH_KEX] ssh struct at 0x{ssh_ptr:x}")

        # The ssh struct contains pointers to kex and newkeys structures
        # We'll read them after this function completes (keys are derived inside)

        # Set exit breakpoint to extract keys after derivation
        # On ARM64, return address is in LR register
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            print(f"[OPENSSH_KEX] Setting exit breakpoint at 0x{ret_addr:x} (LR)")
        else:
            # x86-64: return address is on stack at RSP
            rsp = frame.FindRegister("rsp")
            if rsp:
                error = lldb.SBError()
                ret_addr = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
                if error.Success():
                    print(f"[OPENSSH_KEX] Setting exit breakpoint at 0x{ret_addr:x} (stack)")
                else:
                    print(f"[OPENSSH_KEX] ERROR: Could not read return address from stack")
                    return False
            else:
                print(f"[OPENSSH_KEX] ERROR: Could not find LR or RSP register")
                return False

        # Create one-shot exit breakpoint
        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetScriptCallbackFunction("openssh_client_callbacks.kex_derive_keys_exit")
        bp.SetAutoContinue(False)

        # Store ssh pointer for exit callback
        internal_dict['ssh_ptr'] = ssh_ptr

        print(f"[OPENSSH_KEX] ✓ Exit breakpoint set (bp {bp.GetID()})")

    except Exception as e:
        print(f"[OPENSSH_KEX] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def kex_derive_keys_exit(frame, bp_loc, internal_dict):
    """
    Exit breakpoint after kex_derive_keys() - keys are now derived

    Strategy: Rather than navigating complex struct pointers, we scan the process heap
    for sshenc structures by looking for known cipher name strings. This is inspired
    by Fox-IT's approach but optimized for LLDB.

    When we find a cipher name string, we check nearby memory for valid sshenc structure.
    """
    global _target

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[OPENSSH_KEX_EXIT] kex_derive_keys() returned in PID {pid}")
    print(f"[OPENSSH_KEX_EXIT] Keys should now be derived - extracting...")

    try:
        error = lldb.SBError()

        # Common SSH ciphers to search for
        CIPHER_NAMES = [
            b'chacha20-poly1305@openssh.com',
            b'aes128-ctr',
            b'aes256-ctr',
            b'aes128-gcm@openssh.com',
            b'aes256-gcm@openssh.com',
        ]

        # Get all memory regions (focus on heap)
        found_structures = []

        print(f"[OPENSSH_KEX_EXIT] Scanning process memory for cipher name strings...")

        # Get memory regions - iterate through them using index-based iteration
        # LLDB doesn't provide a direct way to get count, so we iterate until invalid
        region_idx = 0
        regions_scanned = 0

        while True:
            region = lldb.SBMemoryRegionInfo()
            # Query memory region at specific address - start from 0 and increment
            # This is a workaround since GetMemoryRegions() API is version-specific
            if region_idx >= 1000:  # Safety limit
                break

            # Try to get region info at current index
            # We'll use a different approach: scan known memory areas directly
            # Since LLDB API varies by version, let's use a simpler direct memory scan
            break  # Exit loop, will use alternative approach below

        # Alternative approach: Direct memory search in heap area
        # Get heap address range from process
        print(f"[OPENSSH_KEX_EXIT] Using direct memory scan approach...")

        # On Linux, heap typically starts after code segment
        # We'll search in reasonable heap range
        # Get process executable base address
        module = _target.GetModuleAtIndex(0)
        if not module:
            print(f"[OPENSSH_KEX_EXIT] ERROR: Could not get main module")
            return False

        # Search in a reasonable memory range (we'll use a more targeted approach)
        # Instead of scanning all memory, search near stack and heap areas
        # Get current stack pointer to estimate memory layout
        frame = thread.GetFrameAtIndex(0)
        sp = frame.FindRegister("sp")
        if not sp:
            sp = frame.FindRegister("rsp")

        if sp:
            sp_value = sp.GetValueAsUnsigned()
            print(f"[OPENSSH_KEX_EXIT] Stack pointer: 0x{sp_value:x}")

            # Search in memory regions around current execution context
            # Typical heap is below stack on Linux
            search_ranges = [
                (sp_value - 100 * 1024 * 1024, 50 * 1024 * 1024),  # Below stack
            ]

            for search_start, search_size in search_ranges:
                print(f"[OPENSSH_KEX_EXIT] Scanning region 0x{search_start:x}-0x{search_start + search_size:x}")
                regions_scanned += 1

                # Read memory in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                for offset in range(0, search_size, chunk_size):
                    region_start = search_start + offset
                    region_size = min(chunk_size, search_size - offset)

            # Skip regions that are too small or too large (likely not heap)
            if region_size < 1024 or region_size > 100 * 1024 * 1024:
                continue

            # Only scan readable+writable regions (heap characteristics)
            if not region.IsReadable() or not region.IsWritable():
                continue

            print(f"[OPENSSH_KEX_EXIT] Scanning region 0x{region_start:x}-0x{region_end:x} ({region_size} bytes)")

            # Read the entire region (limit to 1MB chunks)
            region_data = process.ReadMemory(region_start, min(region_size, 1024 * 1024), error)
            if not error.Success() or not region_data:
                continue

            # Search for cipher names in this region
            for cipher_name in CIPHER_NAMES:
                offset = 0
                while True:
                    pos = region_data.find(cipher_name, offset)
                    if pos == -1:
                        break

                    cipher_addr = region_start + pos
                    print(f"[OPENSSH_KEX_EXIT] Found '{cipher_name.decode()}' at 0x{cipher_addr:x}")

                    # Try to find sshenc structure near this cipher name
                    # The name pointer should point to this address
                    # Look backwards for a pointer to this address (max 512 bytes)
                    for back_offset in range(8, 512, 8):
                        candidate_ptr_addr = cipher_addr - back_offset
                        if candidate_ptr_addr < region_start:
                            break

                        # Read potential name pointer
                        name_ptr = process.ReadPointerFromMemory(candidate_ptr_addr, error)
                        if error.Success() and name_ptr == cipher_addr:
                            # Found potential sshenc struct at candidate_ptr_addr
                            print(f"[OPENSSH_KEX_EXIT] Found sshenc candidate at 0x{candidate_ptr_addr:x} (offset -{back_offset})")

                            # This is likely the start of sshenc struct
                            # Try extracting keys from this structure
                            if extract_keys_from_sshenc(process, candidate_ptr_addr, cipher_name.decode()):
                                found_structures.append(candidate_ptr_addr)

                    offset = pos + 1

        if len(found_structures) >= 2:
            print(f"[OPENSSH_KEX_EXIT] ✓ Successfully extracted keys from {len(found_structures)} sshenc structures!")
            return False
        else:
            print(f"[OPENSSH_KEX_EXIT] ⚠️  Only found {len(found_structures)} valid sshenc structures (expected 2: IN+OUT)")
            return False

    except Exception as e:
        print(f"[OPENSSH_KEX_EXIT] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def extract_keys_from_sshenc(process, sshenc_addr, cipher_name):
    """
    Extract keys from a single sshenc structure

    struct sshenc (v6.2+): name(8), cipher(8), enabled(4), key_len(4), iv_len(4), block_size(4), key(8), iv(8)
    struct sshenc (v6.1):  name(8), cipher(8), enabled(4), key_len(4), block_size(4), key(8), iv(8)

    Args:
        process: LLDB process
        sshenc_addr: Address of sshenc structure
        cipher_name: Expected cipher name (for validation)

    Returns:
        True if keys extracted successfully, False otherwise
    """
    try:
        error = lldb.SBError()

        # Expected key sizes
        CIPHER_KEY_SIZES = {
            'chacha20-poly1305@openssh.com': 64,
            'aes128-ctr': 16,
            'aes192-ctr': 24,
            'aes256-ctr': 32,
            'aes128-gcm@openssh.com': 16,
            'aes256-gcm@openssh.com': 32,
        }

        expected_key_len = CIPHER_KEY_SIZES.get(cipher_name)
        if not expected_key_len:
            return False

        # Read key_len at offset 20 (same in both versions)
        key_len = process.ReadUnsignedFromMemory(sshenc_addr + 20, 4, error)
        if not error.Success():
            return False

        # Validate key length matches expected
        if key_len != expected_key_len:
            print(f"[OPENSSH_KEX]   key_len mismatch: got {key_len}, expected {expected_key_len}")
            return False

        # Try v6.2+ layout first: key pointer at offset 32
        key_ptr = process.ReadPointerFromMemory(sshenc_addr + 32, error)
        if not error.Success() or key_ptr == 0:
            # Try v6.1 layout: key pointer at offset 28
            key_ptr = process.ReadPointerFromMemory(sshenc_addr + 28, error)

        if not error.Success() or key_ptr == 0:
            print(f"[OPENSSH_KEX]   Could not read key pointer")
            return False

        # Read actual key bytes
        key_data = process.ReadMemory(key_ptr, key_len, error)
        if not error.Success() or not key_data or key_data == b'\x00' * key_len:
            return False

        # Success!
        key_hex = key_data.hex()
        print(f"[OPENSSH_KEX]   ✓ Extracted {cipher_name} key ({key_len} bytes)")
        print(f"[OPENSSH_KEX]     Key: {key_hex[:64]}...")
        write_keylog(f"KEY_{cipher_name}", key_hex)

        return True

    except Exception as e:
        print(f"[OPENSSH_KEX] Exception in extract_keys_from_sshenc: {e}")
        return False

def extract_keys_from_newkeys(process, newkeys_in_ptr, newkeys_out_ptr):
    """
    Extract session keys from OpenSSH newkeys structures

    OpenSSH struct hierarchy:
    - struct newkeys contains enc (struct sshenc) at offset 0
    - struct sshenc (v6.2+): name, cipher, enabled, key_len, iv_len, block_size, key, iv
    - struct sshenc (v6.1): name, cipher, enabled, key_len, block_size, key, iv

    We probe both structures and validate cipher names and key lengths.
    Returns True if successful, False otherwise.
    """
    try:
        error = lldb.SBError()
        extracted_count = 0

        # Common SSH cipher algorithms with expected key sizes
        CIPHER_KEY_SIZES = {
            'chacha20-poly1305@openssh.com': 64,  # 32 bytes ChaCha20 + 32 bytes Poly1305
            'aes128-ctr': 16,
            'aes192-ctr': 24,
            'aes256-ctr': 32,
            'aes128-cbc': 16,
            'aes192-cbc': 24,
            'aes256-cbc': 32,
            'aes128-gcm@openssh.com': 16,
            'aes256-gcm@openssh.com': 32,
        }

        for direction, nk_ptr in [("MODE_IN", newkeys_in_ptr), ("MODE_OUT", newkeys_out_ptr)]:
            # struct newkeys has enc at offset 0
            # struct sshenc has name (char*) at offset 0

            enc_name_ptr = process.ReadPointerFromMemory(nk_ptr, error)
            if not error.Success() or enc_name_ptr == 0:
                print(f"[OPENSSH_KEX]   {direction}: Could not read enc.name pointer")
                continue

            # Read cipher name string (max 64 bytes)
            enc_name_data = process.ReadMemory(enc_name_ptr, 64, error)
            if not error.Success():
                print(f"[OPENSSH_KEX]   {direction}: Could not read cipher name")
                continue

            # Parse null-terminated string
            null_pos = enc_name_data.find(b'\x00')
            if null_pos > 0:
                cipher_name = enc_name_data[:null_pos].decode('utf-8', errors='ignore')
            else:
                cipher_name = enc_name_data[:32].decode('utf-8', errors='ignore')

            print(f"[OPENSSH_KEX]   {direction}: Cipher name = '{cipher_name}'")

            # Validate cipher name
            if cipher_name not in CIPHER_KEY_SIZES:
                print(f"[OPENSSH_KEX]   {direction}: Unknown cipher, skipping")
                continue

            expected_key_len = CIPHER_KEY_SIZES[cipher_name]

            # Try both struct layouts
            # v6.2+: name(8), cipher(8), enabled(4), key_len(4), iv_len(4), block_size(4), key(8), iv(8)
            # v6.1:  name(8), cipher(8), enabled(4), key_len(4), block_size(4), key(8), iv(8)

            # Offset of key_len in both versions: 8 + 8 + 4 = 20 bytes
            key_len = process.ReadUnsignedFromMemory(nk_ptr + 20, 4, error)
            if not error.Success():
                continue

            print(f"[OPENSSH_KEX]   {direction}: key_len = {key_len}")

            # Validate key length
            if key_len != expected_key_len:
                print(f"[OPENSSH_KEX]   {direction}: key_len mismatch (expected {expected_key_len})")
                continue

            # Try v6.2+ layout first: key pointer at offset 8+8+4+4+4+4 = 32
            key_ptr_offset_v62 = 32
            key_ptr = process.ReadPointerFromMemory(nk_ptr + key_ptr_offset_v62, error)

            if not error.Success() or key_ptr == 0:
                # Try v6.1 layout: key pointer at offset 8+8+4+4+4 = 28
                key_ptr_offset_v61 = 28
                key_ptr = process.ReadPointerFromMemory(nk_ptr + key_ptr_offset_v61, error)

            if not error.Success() or key_ptr == 0:
                print(f"[OPENSSH_KEX]   {direction}: Could not read key pointer")
                continue

            print(f"[OPENSSH_KEX]   {direction}: key pointer = 0x{key_ptr:x}")

            # Read actual key bytes
            key_data = process.ReadMemory(key_ptr, key_len, error)
            if not error.Success() or not key_data:
                print(f"[OPENSSH_KEX]   {direction}: Could not read key data")
                continue

            # Check if key is not all zeros (would indicate uninitialized)
            if key_data == b'\x00' * key_len:
                print(f"[OPENSSH_KEX]   {direction}: Key is all zeros (not initialized)")
                continue

            # Success! Write to keylog
            key_hex = key_data.hex()
            print(f"[OPENSSH_KEX]   {direction}: ✓ Extracted {cipher_name} key ({key_len} bytes)")
            print(f"[OPENSSH_KEX]   {direction}:   Key: {key_hex[:32]}...")
            write_keylog(f"{direction}_KEY_{cipher_name}", key_hex)
            extracted_count += 1

        return extracted_count >= 2  # Success if we extracted both directions

    except Exception as e:
        print(f"[OPENSSH_KEX] Exception in extract_keys_from_newkeys: {e}")
        import traceback
        traceback.print_exc()
        return False

# ═══════════════════════════════════════════════════════════════════════════
# EVP_KDF APPROACH (Alternative Method)
# ═══════════════════════════════════════════════════════════════════════════

def evp_kdf_derive_callback(frame, bp_loc, internal_dict):
    """
    Alternative approach: Hook EVP_KDF_derive from OpenSSL library

    int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[])

    This captures derived key material at the OpenSSL library level.
    More reliable than struct navigation but requires OpenSSL 3.0+
    """
    global _keys_extracted_count, _target, _debugger

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    _keys_extracted_count += 1

    print(f"\n[OPENSSH_EVP_KDF] EVP_KDF_derive() called in PID {pid} (call #{_keys_extracted_count})")

    try:
        # EVP_KDF_derive arguments on ARM64: ctx=x0, key=x1, keylen=x2, params=x3
        # On x86-64: ctx=rdi, key=rsi, keylen=rdx, params=rcx

        # Try ARM64 first
        key_ptr_reg = frame.FindRegister("x1")
        keylen_reg = frame.FindRegister("x2")

        if not key_ptr_reg or key_ptr_reg.GetValueAsUnsigned() == 0:
            # Try x86-64
            key_ptr_reg = frame.FindRegister("rsi")
            keylen_reg = frame.FindRegister("rdx")

        if not key_ptr_reg or key_ptr_reg.GetValueAsUnsigned() == 0:
            print(f"[OPENSSH_EVP_KDF] ERROR: Could not find key pointer register")
            return False

        key_ptr = key_ptr_reg.GetValueAsUnsigned()
        keylen = keylen_reg.GetValueAsUnsigned()

        print(f"[OPENSSH_EVP_KDF] key_ptr=0x{key_ptr:x}, keylen={keylen}")

        # Set exit breakpoint to capture derived key
        # On ARM64, return address is in LR register
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            print(f"[OPENSSH_EVP_KDF] Setting exit breakpoint at 0x{ret_addr:x} (LR)")
        else:
            # x86-64: return address is on stack
            rsp = frame.FindRegister("rsp")
            if rsp:
                error = lldb.SBError()
                ret_addr = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
                if not error.Success():
                    print(f"[OPENSSH_EVP_KDF] ERROR: Could not read return address")
                    return False
                print(f"[OPENSSH_EVP_KDF] Setting exit breakpoint at 0x{ret_addr:x} (stack)")
            else:
                print(f"[OPENSSH_EVP_KDF] ERROR: Could not find LR or RSP register")
                return False

        # Create one-shot exit breakpoint
        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetScriptCallbackFunction("openssh_client_callbacks.evp_kdf_derive_exit")
        bp.SetAutoContinue(False)

        # Store key info for exit callback
        internal_dict['evp_key_ptr'] = key_ptr
        internal_dict['evp_keylen'] = keylen

        print(f"[OPENSSH_EVP_KDF] ✓ Exit breakpoint set (bp {bp.GetID()})")

    except Exception as e:
        print(f"[OPENSSH_EVP_KDF] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def evp_kdf_derive_exit(frame, bp_loc, internal_dict):
    """Exit callback for EVP_KDF_derive - key has been derived"""
    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[OPENSSH_EVP_KDF_EXIT] EVP_KDF_derive() returned in PID {pid}")

    try:
        key_ptr = internal_dict.get('evp_key_ptr')
        keylen = internal_dict.get('evp_keylen')

        if not key_ptr or not keylen:
            print(f"[OPENSSH_EVP_KDF_EXIT] ERROR: key_ptr or keylen not in internal_dict")
            return False

        # Read derived key
        error = lldb.SBError()
        key_data = process.ReadMemory(key_ptr, keylen, error)

        if not error.Success() or not key_data or key_data == b'\x00' * keylen:
            print(f"[OPENSSH_EVP_KDF_EXIT] ERROR: Could not read key or key is all zeros")
            return False

        # Success!
        key_hex = key_data.hex()
        print(f"[OPENSSH_EVP_KDF_EXIT] ✓ Extracted key ({keylen} bytes)")
        print(f"[OPENSSH_EVP_KDF_EXIT]   Key: {key_hex[:64]}...")
        write_keylog(f"EVP_KDF_KEY_{keylen}bytes", key_hex)

    except Exception as e:
        print(f"[OPENSSH_EVP_KDF_EXIT] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def openssh_setup_monitoring(debugger, command, result, internal_dict):
    """Setup OpenSSH client-side monitoring"""
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[OPENSSH_CLIENT] OpenSSH Client-Side Monitoring")
    print("[OPENSSH_CLIENT] Version 2.0 - OpenSSH 9.8p1")
    print("[OPENSSH_CLIENT] Dual approach: kex_derive_keys + EVP_KDF_derive")
    print("="*70)

    # Approach 1: Breakpoint on kex_derive_keys (struct-based extraction)
    kex_bp = _target.BreakpointCreateByName("kex_derive_keys")
    if kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("openssh_client_callbacks.kex_derive_keys_callback")
        kex_bp.SetAutoContinue(False)
        print(f"[OPENSSH_CLIENT] ✓ Approach 1: kex_derive_keys() breakpoint (ID {kex_bp.GetID()})")
    else:
        print(f"[OPENSSH_CLIENT] ⚠️  Approach 1: kex_derive_keys() symbol not found")

    # Approach 2: Breakpoint on EVP_KDF_derive (OpenSSL library hook)
    evp_bp = _target.BreakpointCreateByName("EVP_KDF_derive")
    if evp_bp.IsValid():
        evp_bp.SetScriptCallbackFunction("openssh_client_callbacks.evp_kdf_derive_callback")
        evp_bp.SetAutoContinue(False)
        print(f"[OPENSSH_CLIENT] ✓ Approach 2: EVP_KDF_derive() breakpoint (ID {evp_bp.GetID()})")
    else:
        print(f"[OPENSSH_CLIENT] ⚠️  Approach 2: EVP_KDF_derive() not available (OpenSSL 3.0+ required)")

    print("[OPENSSH_CLIENT] Setup complete - ready for openssh_auto_continue")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def openssh_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop for OpenSSH client monitoring"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[OPENSSH_AUTO] Starting auto-continue loop")
    print("[OPENSSH_AUTO] Will continue until process exits")

    # Initial continue
    process.Continue()
    print("[OPENSSH_AUTO] Initial continue...")

    iteration = 0
    while process.GetState() != lldb.eStateExited:
        current_state = process.GetState()

        if current_state == lldb.eStateStopped:
            iteration += 1

            # Continue on all stops
            process.Continue()
            print(f"[OPENSSH_AUTO] Continued (iteration {iteration})")

        time.sleep(0.05)  # Brief sleep to avoid busy-waiting

    print(f"\n[OPENSSH_AUTO] Process exited after {iteration} stops")
    print(f"[OPENSSH_AUTO] Keys extracted: {_keys_extracted_count} KEX cycles")
    print(f"[OPENSSH_AUTO] Keylog path: {KEYLOG_PATH}")
