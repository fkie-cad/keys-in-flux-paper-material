#!/usr/bin/env python3
"""
OpenSSH Client-Side Callbacks - derive_key() Extraction v8.0

Cross-platform hybrid key extraction for OpenSSH client using derive_key():
- Direct key extraction from derive_key() function (6 calls per KEX: A-F)
- Symbol-aware extraction (requires debug symbols)
- Register-based fallback (works without symbols)
- Fallback approach: EVP_KDF_derive (OpenSSL 3.0+)
- Architecture support: ARM64 (aarch64) and x86-64 (amd64)

**v8.0 NEW FEATURES** (2025-10-30):
- Two-breakpoint pattern for lifecycle functions (entry + exit dumps)
- 7 lifecycle functions monitored: client_channel_closed, ssh_packet_free, chan_send_close2,
  ssh_packet_close_internal, ssh_packet_is_rekeying, ssh_packet_need_rekeying, kex_send_newkeys
- Generic entry/exit callback pattern for before/after memory dumps
- Pending breakpoint support (symbols resolve when libraries load)
- Configurable via LLDB_ENABLE_ENTRY_DUMPS and LLDB_ENTRY_DUMP_FUNCTIONS

**v5.0 FEATURES**:
- SSH protocol state machine integration (PRE_CONNECT → KEX_COMPLETE → ACTIVE → REKEY → SESSION_CLOSED)
- Automatic memory dumps at protocol state transitions (pre/post)
- Full lifecycle experiment support (handshake, active, rekey, close)
- Configurable dump modes: full, heap, or targeted key dumps

Uses shared utilities from ssh_extraction_utils.py for cross-platform parameter extraction.

RFC 4253 Key Mapping:
- id 65 (A): Initial IV client to server
- id 66 (B): Initial IV server to client
- id 67 (C): Encryption key client to server
- id 68 (D): Encryption key server to client
- id 69 (E): Integrity key client to server
- id 70 (F): Integrity key server to client
"""

import lldb
import time
import os
import datetime
import sys

# Import shared SSH extraction utilities
sys.path.insert(0, '/opt/lldb')
from ssh_extraction_utils import (
    detect_architecture,
    extract_derive_key_params_hybrid_aarch64,
    extract_derive_key_params_hybrid_x86_64,
    extract_evp_kdf_params_hybrid_aarch64,
    extract_evp_kdf_params_hybrid_x86_64,
    get_return_address_aarch64,
    get_return_address_x86_64,
    read_sshbuf_data
)

# Import lifecycle experiment infrastructure
import ssh_state_machine
import ssh_memory_dump

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

# Architecture (detected once)
_arch = None

# Global state dictionaries keyed by return address
# (internal_dict doesn't work for dynamically created exit breakpoints)
_derive_key_state = {}   # {ret_addr: {'keyp_addr': int, 'id': int, 'need': int, ...}}
_evp_state = {}          # {ret_addr: {'key_ptr': int, 'keylen': int, ...}}

# Counters
_derive_key_counter = 0
_evp_counter = 0
_kex_session = 0  # KEX session counter (increments every 6 derive_key calls)

# LLDB objects
_target = None
_debugger = None
_process = None

# State machine for lifecycle tracking (v5.0)
_state_machine = None

# Lifecycle function entry/exit state (v8.0 - two-breakpoint pattern)
_function_exit_state = {}  # {ret_addr: {'func_name': str, 'event_type': str}}

# Keylog paths from environment
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/openssh_client_keylog.log')
KEYLOG_DEBUG_PATH = os.environ.get('LLDB_KEYLOG_DEBUG', '/data/keylogs/openssh_client_keylog_debug.log')

# v5.0: Memory dump configuration
ENABLE_MEMORY_DUMPS = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'false').lower() == 'true'
DUMP_TYPE = os.environ.get('LLDB_DUMP_TYPE', 'heap')  # 'full', 'heap', or 'keys'
DUMPS_DIR = os.environ.get('LLDB_DUMPS_DIR', '/data/dumps')

# Watchpoint configuration: Check per-client variable first, then fall back to generic (default: enabled)
ENABLE_WATCHPOINTS = os.environ.get('LLDB_ENABLE_WATCHPOINTS_OPENSSH',
                                    os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')).lower() == 'true'

# Watchpoint tracking
_watchpoints = {}  # Dict[key_name: str, tuple(wp_id, address, key_data)]

# v7.0: Function entry monitoring configuration
ENABLE_ENTRY_DUMPS = os.environ.get('LLDB_ENABLE_ENTRY_DUMPS', 'false').lower() == 'true'
ENTRY_DUMP_FUNCTIONS = os.environ.get('LLDB_ENTRY_DUMP_FUNCTIONS', 'all')  # 'all' or comma-separated list

# Log configuration at startup
print(f"[OPENSSH_CLIENT_CONFIG] Watchpoints: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
print(f"[OPENSSH_CLIENT_CONFIG] Memory dumps: {'ENABLED' if ENABLE_MEMORY_DUMPS else 'DISABLED'}")
print(f"[OPENSSH_CLIENT_CONFIG] Function entry dumps: {'ENABLED' if ENABLE_ENTRY_DUMPS else 'DISABLED'}")

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_microsecond_timestamp():
    """Get current timestamp with microsecond precision"""
    return datetime.datetime.now().timestamp()

def format_timestamp_us(ts):
    """Format timestamp with microsecond precision"""
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Millisecond precision

def write_keylog(key_type, value_hex, keylog_path=KEYLOG_PATH):
    """Write extracted key to keylog file"""
    try:
        timestamp = get_microsecond_timestamp()
        with open(keylog_path, 'a') as f:
            f.write(f"{format_timestamp_us(timestamp)} {key_type} {value_hex}\n")
        print(f"[OPENSSH_KEYLOG] ✓ {key_type} logged")
    except Exception as e:
        print(f"[OPENSSH_KEYLOG] ERROR writing keylog: {e}")

def write_debug_keylog(key_type, value_hex):
    """Write to debug keylog (includes all intermediate values)"""
    write_keylog(key_type, value_hex, KEYLOG_DEBUG_PATH)

def _set_watchpoint(key_name, address, key_data, key_id):
    """
    Set hardware watchpoint using the proven IPsec pattern

    Tracks when encryption keys (C & D) are first overwritten in memory.
    Uses one-shot watchpoint pattern (project-wide standard).
    """
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
        print(f"[WATCHPOINT] Key preview: {key_data[:16].hex()}...")

        error = lldb.SBError()
        watchpoint = _target.WatchAddress(address, 4, False, True, error)

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
        import sys
        sys.path.insert(0, '/opt/lldb')
        from ssh_monitor import log_timing
        log_timing("{fixed_key_id}", "overwritten", timestamp)
    except Exception as e:
        print(f"[KEY_OVERWRITE] WARNING: Could not log timing: {{e}}")

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
        print(f"[WATCHPOINT] Key preview: {key_data[:16].hex()}...")

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# WATCHPOINT MANAGEMENT COMMANDS (Interactive debugging utility)
# ═══════════════════════════════════════════════════════════════════════════

def watchpoints_toggle(debugger, command, result, internal_dict):
    """
    Toggle watchpoints on/off globally during interactive LLDB session.

    Usage:
        (lldb) watchpoints_toggle

    When disabled, deletes all active watchpoints and prevents new ones from being created.
    When enabled, allows new watchpoints to be set on next key derivation.
    """
    global ENABLE_WATCHPOINTS, _watchpoints, _target

    # Toggle the flag
    ENABLE_WATCHPOINTS = not ENABLE_WATCHPOINTS

    if not ENABLE_WATCHPOINTS:
        # Delete all active watchpoints
        if _target and _watchpoints:
            for key_name, (wp_id, _, _) in list(_watchpoints.items()):
                _target.DeleteWatchpoint(wp_id)
                print(f"[WATCHPOINT_TOGGLE] Deleted watchpoint: {key_name} (ID {wp_id})")
            _watchpoints.clear()
            print(f"[WATCHPOINT_TOGGLE] ✓ ALL watchpoints DISABLED and deleted")
        else:
            print(f"[WATCHPOINT_TOGGLE] ✓ ALL watchpoints DISABLED (no active watchpoints)")
    else:
        print(f"[WATCHPOINT_TOGGLE] ✓ ALL watchpoints ENABLED")
        print(f"[WATCHPOINT_TOGGLE] New watchpoints will be set on next key derivation")


def watchpoints_status(debugger, command, result, internal_dict):
    """
    Show current watchpoint status.

    Usage:
        (lldb) watchpoints_status

    Displays:
    - Global enable/disable state
    - Number of active watchpoints
    - Derive key counter
    """
    global ENABLE_WATCHPOINTS, _watchpoints, _derive_key_counter

    print(f"\n[WATCHPOINT_STATUS] === Watchpoint Status ===")
    print(f"[WATCHPOINT_STATUS] Global state: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
    print(f"[WATCHPOINT_STATUS] Active watchpoints: {len(_watchpoints)}")
    print(f"[WATCHPOINT_STATUS] Derive key counter: {_derive_key_counter}")

    if _watchpoints:
        print(f"[WATCHPOINT_STATUS] Keys being monitored:")
        for key_name in _watchpoints.keys():
            print(f"[WATCHPOINT_STATUS]   - {key_name}")
    else:
        print(f"[WATCHPOINT_STATUS] No active watchpoints")
    print(f"[WATCHPOINT_STATUS] ========================\n")


def watchpoints_list(debugger, command, result, internal_dict):
    """
    List all active watchpoints with detailed information.

    Usage:
        (lldb) watchpoints_list

    Shows:
    - Watchpoint ID
    - Key name
    - Memory address being watched
    - Key data (hex preview)
    """
    global _watchpoints, _target

    if not _watchpoints:
        print(f"[WATCHPOINT_LIST] No active watchpoints")
        return

    print(f"\n[WATCHPOINT_LIST] === Active Watchpoints ({len(_watchpoints)}) ===")

    for key_name, (wp_id, address, key_data) in _watchpoints.items():
        # Get watchpoint details from LLDB
        wp = None
        if _target:
            wp = _target.FindWatchpointByID(wp_id)

        print(f"[WATCHPOINT_LIST] {key_name}:")
        print(f"[WATCHPOINT_LIST]   ID:      {wp_id}")
        print(f"[WATCHPOINT_LIST]   Address: 0x{address:016x}")
        print(f"[WATCHPOINT_LIST]   Size:    {len(key_data)} bytes")
        print(f"[WATCHPOINT_LIST]   Data:    {key_data[:32].hex()}{'...' if len(key_data) > 32 else ''}")

        if wp and wp.IsValid():
            print(f"[WATCHPOINT_LIST]   Enabled: {wp.IsEnabled()}")
            print(f"[WATCHPOINT_LIST]   Hit count: {wp.GetHitCount()}")
        else:
            print(f"[WATCHPOINT_LIST]   Status:  INVALID (may have been deleted)")
        print()

    print(f"[WATCHPOINT_LIST] ====================================\n")


def __lldb_init_module(debugger, internal_dict):
    """Called when script is imported by LLDB"""
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.openssh_setup_monitoring openssh_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.openssh_auto_continue openssh_auto_continue'
    )
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.watchpoints_toggle watchpoints_toggle'
    )
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.watchpoints_status watchpoints_status'
    )
    debugger.HandleCommand(
        'command script add -f openssh_client_callbacks.watchpoints_list watchpoints_list'
    )
    print("[OPENSSH_CLIENT] Commands registered: openssh_setup_monitoring, openssh_auto_continue")
    print("[OPENSSH_CLIENT] Watchpoint management: watchpoints_toggle, watchpoints_status, watchpoints_list")

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH 1: derive_key() - Direct Key Extraction (Primary)
# ═══════════════════════════════════════════════════════════════════════════

# RFC 4253 key type mapping
KEY_TYPE_MAP = {
    65: 'IV_CLIENT_TO_SERVER',      # A
    66: 'IV_SERVER_TO_CLIENT',      # B
    67: 'ENCRYPTION_KEY_CLIENT_TO_SERVER',  # C
    68: 'ENCRYPTION_KEY_SERVER_TO_CLIENT',  # D
    69: 'MAC_KEY_CLIENT_TO_SERVER',         # E
    70: 'MAC_KEY_SERVER_TO_CLIENT'          # F
}

def derive_key_entry(frame, bp_loc, internal_dict):
    """
    Entry callback for OpenSSH derive_key()

    Called 6 times per KEX with id = 65-70 (A-F keys)

    Strategy:
    1. Extract parameters using hybrid approach (symbol-aware + register fallback)
    2. Get return address (LR on ARM64, RSP on x86-64)
    3. Set one-shot exit breakpoint
    4. Store state in global dict keyed by return address
    """
    global _derive_key_state, _derive_key_counter, _target, _arch, _process, _kex_session

    thread = frame.GetThread()
    process = thread.GetProcess()
    _derive_key_counter += 1

    try:
        # Detect architecture if not already done
        if _arch is None:
            _arch = detect_architecture(_target)

        # Extract parameters using hybrid approach
        params = None
        if _arch == 'aarch64':
            params = extract_derive_key_params_hybrid_aarch64(frame)
        elif _arch == 'x86_64':
            params = extract_derive_key_params_hybrid_x86_64(frame, process)
        else:
            print(f"[OPENSSH_DERIVE_ENTRY] ERROR: Unsupported architecture '{_arch}'")
            return False

        if not params:
            print(f"[OPENSSH_DERIVE_ENTRY] ⚠️  Failed to extract parameters")
            return False

        key_id = params['id']
        key_type = KEY_TYPE_MAP.get(key_id, f'UNKNOWN_ID_{key_id}')

        # Increment KEX session every 6 calls (full set of A-F keys)
        if _derive_key_counter % 6 == 1:
            _kex_session += 1

        print(f"[OPENSSH_DERIVE_ENTRY] #{_derive_key_counter} KEX{_kex_session} - {key_type} (id={key_id}) - {params['method']}")

        # Get return address
        ret_addr = None
        if _arch == 'aarch64':
            ret_addr = get_return_address_aarch64(frame)
        elif _arch == 'x86_64':
            ret_addr = get_return_address_x86_64(frame, process)

        if not ret_addr:
            print(f"[OPENSSH_DERIVE_ENTRY] ⚠️  Failed to get return address")
            return False

        # Create one-shot exit breakpoint
        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetScriptCallbackFunction("openssh_client_callbacks.derive_key_exit")

        # Store state in global dict
        _derive_key_state[ret_addr] = {
            'keyp_addr': params['keyp'],
            'id': key_id,
            'need': params['need'],
            'shared_secret_ptr': params['shared_secret'],
            'hashlen': params['hashlen'],
            'method': params['method'],
            'derive_num': _derive_key_counter,
            'kex_session': _kex_session,
            'key_type': key_type
        }

    except Exception as e:
        print(f"[OPENSSH_DERIVE_ENTRY] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def derive_key_exit(frame, bp_loc, internal_dict):
    """
    Exit callback for OpenSSH derive_key()

    Strategy:
    1. Retrieve state from global dict
    2. Dereference keyp: read pointer at keyp_addr to get key buffer address
    3. Read 'need' bytes from that address
    4. Extract shared_secret from sshbuf (optional)
    5. Write to keylogs
    """
    global _derive_key_state, _process

    pc = frame.GetPC()
    state = _derive_key_state.get(pc)

    if not state:
        print(f"[OPENSSH_DERIVE_EXIT] ⚠️  No state found for PC {hex(pc)}")
        return False

    try:
        thread = frame.GetThread()
        process = thread.GetProcess()

        derive_num = state['derive_num']
        kex_session = state['kex_session']
        key_type = state['key_type']
        key_id = state['id']
        need = state['need']
        keyp_addr = state['keyp_addr']

        # Dereference keyp to get key buffer address
        error = lldb.SBError()
        key_buffer_addr = process.ReadPointerFromMemory(keyp_addr, error)

        if not error.Success() or key_buffer_addr == 0:
            print(f"[OPENSSH_DERIVE_EXIT] ⚠️  Failed to dereference keyp at {hex(keyp_addr)}")
            del _derive_key_state[pc]
            return False

        # Read the actual key data
        key_data = process.ReadMemory(key_buffer_addr, need, error)

        if not error.Success() or not key_data:
            print(f"[OPENSSH_DERIVE_EXIT] ⚠️  Failed to read key from {hex(key_buffer_addr)}")
            del _derive_key_state[pc]
            return False

        key_hex = key_data.hex()
        print(f"[OPENSSH_DERIVE_EXIT] ✓ KEX{kex_session} - {key_type}: {key_hex[:32]}... ({need} bytes)")

        # Write to keylogs (with KEX suffix for key update tracking)
        write_keylog(f"DERIVE_KEY {key_type}_KEX{kex_session}", key_hex)
        write_debug_keylog(f"DERIVE_KEY_{key_id}_KEX{kex_session}_{''.join(key_type.split('_'))}", key_hex)

        # SET WATCHPOINTS for encryption keys C & D only (id 67 & 68)
        if key_id in [67, 68]:  # 67=ENCRYPTION_KEY_CLIENT_TO_SERVER (C), 68=ENCRYPTION_KEY_SERVER_TO_CLIENT (D)
            _target = process.GetTarget()
            _debugger = _target.GetDebugger()

            # Create descriptive watchpoint name
            key_letter = chr(key_id)  # 67='C', 68='D'
            direction = "CLIENT_TO_SERVER" if key_id == 67 else "SERVER_TO_CLIENT"
            wp_key_name = f"KEY_{key_letter}_KEX{kex_session}_{direction}"

            print(f"[OPENSSH_DERIVE_EXIT] Setting watchpoint for {wp_key_name} at 0x{key_buffer_addr:x}")
            _set_watchpoint(wp_key_name, key_buffer_addr, key_data, key_letter)

        # Extract shared_secret from sshbuf (if available)
        if state['shared_secret_ptr'] != 0:
            shared_secret_data = read_sshbuf_data(process, state['shared_secret_ptr'])
            if shared_secret_data:
                ss_hex = shared_secret_data.hex()

                # Parse SSH mpint format: first 4 bytes are length (big-endian uint32)
                # Format: 00 00 00 XX (length) followed by actual bignum data
                mpint_info = ""
                actual_secret_hex = ss_hex  # Default to full buffer
                if len(shared_secret_data) >= 4:
                    mpint_len = int.from_bytes(shared_secret_data[:4], 'big')
                    if mpint_len > 0 and mpint_len < len(shared_secret_data):
                        actual_secret = shared_secret_data[4:4+mpint_len]
                        actual_secret_hex = actual_secret.hex()
                        mpint_info = f" [SSH mpint: len={mpint_len}, data={actual_secret_hex[:32]}...]"

                print(f"[OPENSSH_DERIVE_EXIT] ✓ KEX{kex_session} - Shared secret (sshbuf): {ss_hex[:32]}... ({len(shared_secret_data)} bytes){mpint_info}")

                # Only log shared secret once per KEX (on first derive_key call)
                if key_id == 65:  # First key (IV_CLIENT_TO_SERVER)
                    # Standard keylog: just the actual secret (skip SSH mpint length prefix)
                    write_keylog(f"SHARED_SECRET_KEX{kex_session}", actual_secret_hex)
                    # Debug keylog: full sshbuf format (includes SSH mpint length prefix)
                    write_debug_keylog(f"SHARED_SECRET_KEX{kex_session}", ss_hex)

        # v5.0: STATE MACHINE TRANSITIONS
        global _state_machine
        if _state_machine and ENABLE_MEMORY_DUMPS:
            # Transition at KEY milestones
            if _derive_key_counter == 6 and _kex_session == 1:
                # Event 1: HANDSHAKE (KEX_COMPLETE) - creates pre/post dumps
                # First KEX complete (all 6 keys extracted)
                _state_machine.transition(
                    ssh_state_machine.SSHState.KEX_COMPLETE,
                    metadata={
                        'kex_session': _kex_session,
                        'keys_extracted': 6,
                        'method': 'derive_key'
                    }
                )
                # Event 2: TRAFFIC START (ACTIVE) - creates pre/post dumps
                # Changed from quick_transition() to transition() to ensure lifecycle dumps are created
                _state_machine.transition(
                    ssh_state_machine.SSHState.ACTIVE,
                    metadata={'ready_for_traffic': True, 'kex_session': _kex_session}
                )

            elif _derive_key_counter == 7 and _kex_session == 2:
                # Rekey started (first key of second KEX)
                _state_machine.transition(
                    ssh_state_machine.SSHState.REKEY_START,
                    metadata={
                        'kex_session': _kex_session,
                        'trigger': 'rekey_initiated'
                    }
                )

            elif _derive_key_counter == 12 and _kex_session == 2:
                # Rekey complete (all 6 keys of second KEX extracted)
                _state_machine.transition(
                    ssh_state_machine.SSHState.REKEY_COMPLETE,
                    metadata={
                        'kex_session': _kex_session,
                        'keys_extracted': 6,
                        'total_keys': 12
                    }
                )

        # Cleanup state
        del _derive_key_state[pc]

    except Exception as e:
        print(f"[OPENSSH_DERIVE_EXIT] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# APPROACH 2: EVP_KDF_derive() - OpenSSL Library Hook (Fallback)
# ═══════════════════════════════════════════════════════════════════════════

def evp_kdf_derive_entry(frame, bp_loc, internal_dict):
    """
    Entry callback for EVP_KDF_derive() (OpenSSL 3.0+)

    This is a fallback approach for systems using OpenSSL 3.0+
    """
    global _evp_state, _evp_counter, _target, _arch, _process

    thread = frame.GetThread()
    process = thread.GetProcess()
    _evp_counter += 1

    try:
        if _arch is None:
            _arch = detect_architecture(_target)

        # Extract parameters
        params = None
        if _arch == 'aarch64':
            params = extract_evp_kdf_params_hybrid_aarch64(frame)
        elif _arch == 'x86_64':
            params = extract_evp_kdf_params_hybrid_x86_64(frame)

        if not params:
            return False

        print(f"[OPENSSH_EVP_ENTRY] #{_evp_counter} - keylen={params['keylen']} - {params['method']}")

        # Get return address
        ret_addr = None
        if _arch == 'aarch64':
            ret_addr = get_return_address_aarch64(frame)
        elif _arch == 'x86_64':
            ret_addr = get_return_address_x86_64(frame, process)

        if not ret_addr:
            return False

        # Create one-shot exit breakpoint
        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)
        bp.SetScriptCallbackFunction("openssh_client_callbacks.evp_kdf_derive_exit")

        # Store state
        _evp_state[ret_addr] = {
            'key_ptr': params['key_ptr'],
            'keylen': params['keylen'],
            'method': params['method'],
            'evp_num': _evp_counter
        }

    except Exception as e:
        print(f"[OPENSSH_EVP_ENTRY] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def evp_kdf_derive_exit(frame, bp_loc, internal_dict):
    """Exit callback for EVP_KDF_derive()"""
    global _evp_state

    pc = frame.GetPC()
    state = _evp_state.get(pc)

    if not state:
        return False

    try:
        thread = frame.GetThread()
        process = thread.GetProcess()

        evp_num = state['evp_num']
        keylen = state['keylen']
        key_ptr = state['key_ptr']

        # Read key data
        error = lldb.SBError()
        key_data = process.ReadMemory(key_ptr, keylen, error)

        if not error.Success() or not key_data:
            del _evp_state[pc]
            return False

        key_hex = key_data.hex()
        print(f"[OPENSSH_EVP_EXIT] ✓ EVP #{evp_num} - Extracted key ({keylen} bytes): {key_hex[:32]}...")

        # Write to keylog
        write_keylog(f"EVP_KDF_KEY LENGTH {keylen}", key_hex)
        write_debug_keylog(f"EVP{evp_num}_KEY_{keylen}bytes", key_hex)

        # Cleanup state
        del _evp_state[pc]

    except Exception as e:
        print(f"[OPENSSH_EVP_EXIT] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def openssh_setup_monitoring(debugger, command, result, internal_dict):
    """Setup OpenSSH client-side monitoring with derive_key() extraction"""
    global _target, _debugger, _process, _arch, _state_machine

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    # Detect architecture
    _arch = detect_architecture(_target)

    print("\n" + "="*70)
    print("[OPENSSH_CLIENT] OpenSSH Client-Side Monitoring v8.0")
    print("[OPENSSH_CLIENT] derive_key() Extraction: 6 calls per KEX (A-F)")
    print("[OPENSSH_CLIENT] Function Entry+Exit Monitoring: 7 lifecycle functions")
    print("[OPENSSH_CLIENT] Hybrid Extraction: Symbol-Aware + Register Fallback")
    print(f"[OPENSSH_CLIENT] Architecture: {_arch}")
    print("="*70)

    # v5.0: Initialize state machine for lifecycle tracking
    # Initialize if EITHER dumps OR watchpoints are enabled (both need state machine)
    if ENABLE_MEMORY_DUMPS or ENABLE_WATCHPOINTS:
        _state_machine = ssh_state_machine.create_state_machine(
            _process, DUMPS_DIR, dump_type=DUMP_TYPE, enable_dumps=ENABLE_MEMORY_DUMPS
        )
        print(f"[OPENSSH_CLIENT] ✓ State machine initialized")
        if ENABLE_MEMORY_DUMPS:
            print(f"[OPENSSH_CLIENT]   → Memory dumps: ENABLED ({DUMP_TYPE} mode)")
            print(f"[OPENSSH_CLIENT]   → Output: {DUMPS_DIR}")
        else:
            print(f"[OPENSSH_CLIENT]   → Memory dumps: DISABLED")
        if ENABLE_WATCHPOINTS:
            print(f"[OPENSSH_CLIENT]   → Watchpoints: ENABLED (timing CSVs)")
        else:
            print(f"[OPENSSH_CLIENT]   → Watchpoints: DISABLED")
    else:
        print(f"[OPENSSH_CLIENT] State machine: Disabled (dumps and watchpoints both disabled)")
        print(f"[OPENSSH_CLIENT] Memory dumps: DISABLED")
        print(f"[OPENSSH_CLIENT] Watchpoints: DISABLED")

    # Approach 1: Breakpoint on derive_key (PRIMARY)
    derive_bp = _target.BreakpointCreateByName("derive_key")
    if derive_bp.IsValid():
        derive_bp.SetScriptCallbackFunction("openssh_client_callbacks.derive_key_entry")
        derive_bp.SetAutoContinue(False)
        num_locs = derive_bp.GetNumLocations()
        if num_locs > 0:
            print(f"[OPENSSH_CLIENT] ✓ Approach 1: derive_key() breakpoint (ID {derive_bp.GetID()}, {num_locs} locations)")
            print(f"[OPENSSH_CLIENT]   → Extracts A-F keys (IVs, ENC, MAC) directly")
        else:
            print(f"[OPENSSH_CLIENT] ✓ Approach 1: derive_key() breakpoint (ID {derive_bp.GetID()}, pending - will resolve when ssh binary loads)")
            print(f"[OPENSSH_CLIENT]   → Extracts A-F keys (IVs, ENC, MAC) directly")
    else:
        print(f"[OPENSSH_CLIENT] ✗ Approach 1: derive_key() breakpoint creation FAILED")

    # Approach 2: Breakpoint on EVP_KDF_derive (FALLBACK)
    evp_bp = _target.BreakpointCreateByName("EVP_KDF_derive")
    if evp_bp.IsValid():
        evp_bp.SetScriptCallbackFunction("openssh_client_callbacks.evp_kdf_derive_entry")
        evp_bp.SetAutoContinue(False)
        num_locs = evp_bp.GetNumLocations()
        if num_locs > 0:
            print(f"[OPENSSH_CLIENT] ✓ Approach 2: EVP_KDF_derive() breakpoint (ID {evp_bp.GetID()}, {num_locs} locations)")
            print(f"[OPENSSH_CLIENT]   → Fallback for OpenSSL 3.0+ systems")
        else:
            print(f"[OPENSSH_CLIENT] ✓ Approach 2: EVP_KDF_derive() breakpoint (ID {evp_bp.GetID()}, pending)")
            print(f"[OPENSSH_CLIENT]   → Fallback for OpenSSL 3.0+ systems")
    else:
        print(f"[OPENSSH_CLIENT] ⚠️  Approach 2: EVP_KDF_derive() not available (optional)")

    print(f"[OPENSSH_CLIENT] Keylog: {KEYLOG_PATH}")
    print(f"[OPENSSH_CLIENT] Debug keylog: {KEYLOG_DEBUG_PATH}")

    # ═══ NEW v6.0: Session close detection ═══
    print(f"[OPENSSH_CLIENT] Setting up session close detection...")

    close_bp = _target.BreakpointCreateByName("ssh_packet_close")
    if not close_bp.IsValid():
        # Try alternative function
        close_bp = _target.BreakpointCreateByName("sshpkt_disconnect")

    if close_bp.IsValid():
        close_bp.SetScriptCallbackFunction("openssh_client_callbacks.session_close_callback")
        close_bp.SetAutoContinue(False)
        num_locs = close_bp.GetNumLocations()
        if num_locs > 0:
            print(f"[OPENSSH_CLIENT] ✓ Session close breakpoint set (ID {close_bp.GetID()}, {num_locs} locations)")
        else:
            print(f"[OPENSSH_CLIENT] ✓ Session close breakpoint set (ID {close_bp.GetID()}, pending)")
    else:
        print(f"[OPENSSH_CLIENT] ⚠️  Could not set session close breakpoint (non-critical)")

    # ═══ NEW v8.0: Function Entry+Exit Monitoring (Two-Breakpoint Pattern) ═══
    if ENABLE_ENTRY_DUMPS:
        print(f"[OPENSSH_CLIENT] Setting up function entry+exit monitoring (v8.0)...")

        entry_functions = {
            'ssh_packet_free': 'ssh_packet_free_entry',
            'client_channel_closed': 'client_channel_closed_entry',
            'chan_send_close2': 'chan_send_close2_entry',
            'ssh_packet_close_internal': 'ssh_packet_close_internal_entry',
            'ssh_packet_is_rekeying': 'ssh_packet_is_rekeying_entry',
            'ssh_packet_need_rekeying': 'ssh_packet_need_rekeying_entry',
            'kex_send_newkeys': 'kex_send_newkeys_entry'
        }

        # Filter functions if ENTRY_DUMP_FUNCTIONS is not 'all'
        if ENTRY_DUMP_FUNCTIONS != 'all':
            filter_list = [f.strip() for f in ENTRY_DUMP_FUNCTIONS.split(',')]
            entry_functions = {k: v for k, v in entry_functions.items() if k in filter_list}

        entry_bp_count = 0
        pending_bp_count = 0
        for func_name, callback_name in entry_functions.items():
            bp = _target.BreakpointCreateByName(func_name)
            if bp.IsValid():
                # Attach callback to valid breakpoints (even if pending/0 locations)
                bp.SetScriptCallbackFunction(f"openssh_client_callbacks.{callback_name}")
                bp.SetAutoContinue(False)
                entry_bp_count += 1

                num_locs = bp.GetNumLocations()
                if num_locs > 0:
                    print(f"[OPENSSH_CLIENT] ✓ Entry+Exit breakpoint: {func_name}() (ID {bp.GetID()}, {num_locs} locations)")
                else:
                    pending_bp_count += 1
                    print(f"[OPENSSH_CLIENT] ✓ Entry+Exit breakpoint: {func_name}() (ID {bp.GetID()}, pending - will resolve when library loads)")
            else:
                print(f"[OPENSSH_CLIENT] ⚠️  Entry+Exit breakpoint: {func_name}() invalid")

        if pending_bp_count > 0:
            print(f"[OPENSSH_CLIENT] Entry+Exit monitoring: {entry_bp_count}/{len(entry_functions)} functions set ({pending_bp_count} pending, will resolve when library loads)")
        else:
            print(f"[OPENSSH_CLIENT] Entry+Exit monitoring: {entry_bp_count}/{len(entry_functions)} functions found")
    else:
        print(f"[OPENSSH_CLIENT] Function entry monitoring: DISABLED (set LLDB_ENABLE_ENTRY_DUMPS=true to enable)")

    print("[OPENSSH_CLIENT] Setup complete - ready for openssh_auto_continue")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# FUNCTION ENTRY MONITORING (v8.0 - Two-Breakpoint Pattern)
# ═══════════════════════════════════════════════════════════════════════════

def generic_function_exit_callback(frame, bp_loc, internal_dict):
    """
    Generic exit callback for lifecycle functions.
    Takes memory dump at function exit and logs the event.

    Retrieves metadata stored by entry callback from _function_exit_state.
    """
    global _function_exit_state, _state_machine, _arch

    try:
        # Get PC (return address) to match with stored state
        if _arch == 'aarch64':
            pc = frame.GetPC()
        elif _arch == 'x86_64':
            pc = frame.GetPC()
        else:
            pc = frame.GetPC()

        # Retrieve stored metadata
        if pc not in _function_exit_state:
            print(f"[FUNCTION_EXIT] WARNING: No stored state for PC=0x{pc:x}")
            return False

        metadata = _function_exit_state[pc]
        func_name = metadata['func_name']
        event_type = metadata['event_type']

        print(f"\n{'='*70}")
        print(f"[FUNCTION_EXIT] {func_name}() - EXIT")
        print(f"{'='*70}")

        # Take memory dump at function exit (if enabled)
        if _state_machine and ENABLE_MEMORY_DUMPS:
            label = f"{event_type}_exit"
            _state_machine.dump_now(
                label,
                metadata={
                    'function': func_name,
                    'event_type': event_type,
                    'phase': 'exit'
                }
            )
            print(f"[{func_name}] ✓ Memory dump created: {label}")

        # Log to state machine event log
        if _state_machine:
            _state_machine.log_event(f"FUNCTION_EXIT_{event_type.upper()}", {
                'function': func_name
            })

        print(f"[{func_name}] Exit callback complete")
        print(f"{'='*70}\n")

        # Cleanup: Remove processed entry from global state
        del _function_exit_state[pc]

    except Exception as e:
        print(f"[FUNCTION_EXIT] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

def generic_function_entry_exit_callback(frame, bp_loc, internal_dict, func_name, event_type):
    """
    Generic entry+exit callback for lifecycle functions.
    Takes memory dump at function entry, sets exit breakpoint for after-dump.

    Args:
        frame: LLDB stack frame
        bp_loc: Breakpoint location
        internal_dict: LLDB internal dictionary
        func_name: Function name (e.g., "client_channel_closed")
        event_type: Event type for dump label (e.g., "channel_closed")
    """
    global _function_exit_state, _state_machine, _target, _arch

    try:
        print(f"\n{'='*70}")
        print(f"[FUNCTION_ENTRY] {func_name}() - ENTRY (with exit dump)")
        print(f"{'='*70}")

        # Extract function arguments (best-effort)
        args_info = {}
        for i in range(5):  # Try first 5 args
            try:
                arg_var = frame.FindVariable(f"arg{i}")
                if arg_var.IsValid():
                    args_info[f"arg{i}"] = str(arg_var)
            except:
                pass

        # Take memory dump at function entry (if enabled)
        if _state_machine and ENABLE_MEMORY_DUMPS:
            label = f"{event_type}_entry"
            _state_machine.dump_now(
                label,
                metadata={
                    'function': func_name,
                    'event_type': event_type,
                    'arguments': args_info,
                    'phase': 'entry'
                }
            )
            print(f"[{func_name}] ✓ Memory dump created (entry): {label}")

        # Log to state machine event log
        if _state_machine:
            _state_machine.log_event(f"FUNCTION_ENTRY_{event_type.upper()}", {
                'function': func_name,
                'arguments': args_info
            })

        # Set exit breakpoint for "after" dump
        # Get return address based on architecture
        ret_addr = None
        if _arch == 'aarch64':
            ret_addr = get_return_address_aarch64(frame)
        elif _arch == 'x86_64':
            thread = frame.GetThread()
            process = thread.GetProcess()
            ret_addr = get_return_address_x86_64(frame, process)
        else:
            print(f"[{func_name}] WARNING: Unknown architecture '{_arch}', cannot set exit breakpoint")

        if ret_addr and ret_addr != 0:
            # Store metadata for exit callback
            _function_exit_state[ret_addr] = {
                'func_name': func_name,
                'event_type': event_type
            }

            # Create one-shot exit breakpoint
            exit_bp = _target.BreakpointCreateByAddress(ret_addr)
            if exit_bp.IsValid():
                exit_bp.SetOneShot(True)
                exit_bp.SetScriptCallbackFunction("openssh_client_callbacks.generic_function_exit_callback")
                print(f"[{func_name}] ✓ Exit breakpoint set at 0x{ret_addr:x} (ID {exit_bp.GetID()})")
            else:
                print(f"[{func_name}] ⚠️  Failed to create exit breakpoint at 0x{ret_addr:x}")
        else:
            print(f"[{func_name}] ⚠️  Failed to get return address, no exit dump will be created")

        print(f"[{func_name}] Entry callback complete")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[{func_name}] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

# Wrapper functions for each monitored function (v8.0 - Entry+Exit pattern)

def ssh_packet_free_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for ssh_packet_free()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="ssh_packet_free",
        event_type="packet_free"
    )

def client_channel_closed_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for client_channel_closed()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="client_channel_closed",
        event_type="channel_closed"
    )

def chan_send_close2_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for chan_send_close2()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="chan_send_close2",
        event_type="send_close"
    )

def ssh_packet_close_internal_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for ssh_packet_close_internal()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="ssh_packet_close_internal",
        event_type="close_internal"
    )

def ssh_packet_is_rekeying_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for ssh_packet_is_rekeying()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="ssh_packet_is_rekeying",
        event_type="is_rekeying"
    )

def ssh_packet_need_rekeying_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for ssh_packet_need_rekeying()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="ssh_packet_need_rekeying",
        event_type="need_rekeying"
    )

def kex_send_newkeys_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for kex_send_newkeys()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="kex_send_newkeys",
        event_type="send_newkeys"
    )

# ═══════════════════════════════════════════════════════════════════════════
# SESSION CLOSE CALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def session_close_callback(frame, bp_loc, internal_dict):
    """
    Callback triggered when ssh_packet_close() or sshpkt_disconnect() is called.
    Transitions to SESSION_CLOSED state (cleanup begins).

    This captures the moment when SSH session close is initiated, before
    keep-alive period and process exit.
    """
    global _state_machine

    func_name = frame.GetFunctionName()
    print(f"\n{'='*70}")
    print(f"[OPENSSH_CLOSE] Session Close Detected: {func_name}()")
    print(f"{'='*70}")

    if _state_machine:
        _state_machine.transition(
            ssh_state_machine.SSHState.SESSION_CLOSED,
            metadata={
                'trigger': 'ssh_packet_close',
                'function': func_name
            }
        )
        print(f"[OPENSSH_CLOSE] ✓ SESSION_CLOSED dump completed")
    else:
        print(f"[OPENSSH_CLOSE] ⚠️  State machine not available")

    print(f"{'='*70}\n")
    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def openssh_auto_continue(debugger, command, result, internal_dict):
    """
    Auto-continue loop for OpenSSH client monitoring

    Continuously monitors process state and resumes on stops until process exits.
    Includes timeout detection to prevent SIGPIPE from long stops.
    """
    global _state_machine

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[OPENSSH_AUTO] Starting auto-continue loop v6.0")
    print("[OPENSSH_AUTO] Will continue until process exits")
    print("[OPENSSH_AUTO] Monitoring for /tmp/lldb_dump_pre_exit trigger file")

    # Initial continue
    process.Continue()
    print("[OPENSSH_AUTO] Initial continue...")

    stop_count = 0
    max_iterations = 1000  # Safety limit to prevent infinite loops
    iteration = 0
    last_stop_time = time.time()
    pre_session_close_triggered = False  # Track if we've dumped pre-exit state

    while process.GetState() != lldb.eStateExited and iteration < max_iterations:
        iteration += 1
        current_state = process.GetState()

        # ═══ File-based trigger for PRE_SESSION_CLOSE ═══
        if not pre_session_close_triggered and os.path.exists('/tmp/lldb_dump_pre_exit'):
            print(f"\n[OPENSSH_AUTO] ⚡ Detected pre-exit trigger file at iteration {iteration}!")

            # Trigger PRE_SESSION_CLOSE dump
            if _state_machine:
                _state_machine.transition(
                    ssh_state_machine.SSHState.PRE_SESSION_CLOSE,
                    metadata={
                        'trigger': 'file_marker',
                        'iteration': iteration,
                        'stop_count': stop_count
                    }
                )
                print(f"[OPENSSH_AUTO] ✓ PRE_SESSION_CLOSE dump completed")

            # Clean up trigger file
            try:
                os.remove('/tmp/lldb_dump_pre_exit')
                print(f"[OPENSSH_AUTO] ✓ Trigger file removed")
            except Exception as e:
                print(f"[OPENSSH_AUTO] ⚠️  Failed to remove trigger file: {e}")

            pre_session_close_triggered = True

        if current_state == lldb.eStateStopped:
            stop_count += 1

            # Check if stopped for too long (potential connection timeout)
            stop_duration = time.time() - last_stop_time
            if stop_duration > 5.0:
                print(f"[OPENSSH_AUTO] ⚠️  Long stop detected ({stop_duration:.1f}s) - connection may timeout")

            # Get stop reason for debugging
            stop_reason = process.GetSelectedThread().GetStopReason()
            stop_desc = process.GetSelectedThread().GetStopDescription(100)

            # Continue on all stops
            last_stop_time = time.time()
            process.Continue()
            if stop_count % 100 == 0:  # Log every 100 stops to avoid spam
                print(f"[OPENSSH_AUTO] Continued (stop #{stop_count}, iteration {iteration}, reason: {stop_desc})")

        time.sleep(0.1)  # Brief sleep to avoid busy-waiting

    # Check if we hit the iteration limit
    if iteration >= max_iterations:
        print(f"\n[OPENSSH_AUTO] ⚠️  WARNING: Hit maximum iteration limit ({max_iterations})")
        print(f"[OPENSSH_AUTO] Process state: {current_state}")
        print(f"[OPENSSH_AUTO] Total stops: {stop_count}")
        print(f"[OPENSSH_AUTO] This suggests the process is stuck in a stop-continue loop")
        print(f"[OPENSSH_AUTO] Forcing exit...")
        process.Kill()  # Force kill the process to exit the loop

    # v6.0: Final CLEANUP transition when process exits
    # (SESSION_CLOSED is now handled by session_close_callback breakpoint)
    if _state_machine and ENABLE_MEMORY_DUMPS:
        # Final cleanup transition only
        _state_machine.transition(
            ssh_state_machine.SSHState.CLEANUP,
            metadata={
                'cleanup_complete': True,
                'total_iterations': iteration,
                'total_keys': _derive_key_counter
            }
        )

        # Print state machine summary
        _state_machine.summary()

    print(f"\n[OPENSSH_AUTO] Process exited after {iteration} stops")
    print(f"[OPENSSH_AUTO] derive_key extractions: {_derive_key_counter}")
    print(f"[OPENSSH_AUTO] KEX sessions: {_kex_session}")
    print(f"[OPENSSH_AUTO] EVP_KDF extractions: {_evp_counter}")
    print(f"[OPENSSH_AUTO] Keylog: {KEYLOG_PATH}")
    print(f"[OPENSSH_AUTO] Debug keylog: {KEYLOG_DEBUG_PATH}")

"""
═══════════════════════════════════════════════════════════════════════════
LIFECYCLE EVENT COVERAGE (v7.0):
═══════════════════════════════════════════════════════════════════════════

This callback implements proper state machine transitions with memory dumps:

BASE MODE:
- Event 1: HANDSHAKE (KEX_COMPLETE) ✓ - Captured when all 6 keys are derived (derive_key_counter == 6)
- Event 2: TRAFFIC (ACTIVE) ✓ - Captured immediately after KEX_COMPLETE via transition()
- Event 3: SESSION_CLOSE (SESSION_CLOSED) ✓ - Captured via ssh_packet_close() breakpoint
- Event 4: CLEANUP (CLEANUP) ✓ - Captured on process exit

KEY UPDATE MODE:
- Event 5: REKEY_START ✓ - Captured when 7th key is derived (kex_session == 2)
- Event 6: REKEY_COMPLETE ✓ - Captured when 12th key is derived (all rekey keys)

v7.0 FUNCTION ENTRY MONITORING (NEW):
Captures memory dumps at function ENTRY for detailed lifecycle analysis:
- ssh_packet_free() - Packet structure cleanup
- client_channel_closed() - Client-side channel close
- chan_send_close2() - Send channel close message
- ssh_packet_close_internal() - Internal close handler
- ssh_packet_is_rekeying() - Rekey detection
- ssh_packet_need_rekeying() - Rekey trigger logic
- kex_send_newkeys() - New keys message (NEWKEYS packet)

Configuration:
- LLDB_ENABLE_ENTRY_DUMPS=true: Enable function entry dumps
- LLDB_ENTRY_DUMP_FUNCTIONS=all|csv: Control which functions to monitor
- Entry dumps create timestamped files: <timestamp>_<event_type>_entry.dump

Modified from quick_transition() to transition() at lines 411-416 to ensure
pre/post memory dumps are created for the ACTIVE state.
"""
