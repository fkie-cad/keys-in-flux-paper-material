#!/usr/bin/env python3
"""
Dropbear Client-Side Callbacks v4.0

Client-side monitoring is SIMPLER than server-side because:
- No forking (single process)
- Client initiates KEX
- Straightforward LLDB flow

**v4.0 NEW FEATURES** (2025-10-30):
- Two-breakpoint pattern for lifecycle functions (entry + exit dumps)
- 12 lifecycle functions monitored: send_msg_channel_eof, send_msg_channel_close,
  dropbear_exit, dropbear_close, session_cleanup, cli_cleanup, common_session_cleanup,
  session_identification, session_loop, send_msg_channel_request, recv_msg_channel_close,
  recv_msg_newkeys
- Generic entry/exit callback pattern with automatic exit breakpoint creation
- Architecture-aware return address extraction (aarch64/x86_64)
- Pending breakpoint support (symbols resolve when libraries load)
- Configurable via LLDB_ENABLE_ENTRY_DUMPS and LLDB_ENTRY_DUMP_FUNCTIONS

**v3.0 FEATURES**:
- Function entry monitoring with memory dumps for lifecycle functions
- 5 initial breakpoints: send_msg_channel_eof, send_msg_channel_close, dropbear_exit,
  dropbear_close, session_cleanup_entry
- Generic callback pattern for reusable function entry handling

**v2.0 FEATURES**:
- SSH protocol state machine integration (PRE_CONNECT → KEX_COMPLETE → ACTIVE → SESSION_CLOSED)
- Automatic memory dumps at protocol state transitions (pre/post)
- Full lifecycle experiment support (handshake, active, session close)
- Configurable dump modes: full, heap, or targeted key dumps

Based on successful dropbear_callbacks_minimal.py pattern.
"""

import lldb
import time
import os
import datetime
import sys

# Import lifecycle experiment infrastructure (v2.0)
sys.path.insert(0, '/opt/lldb')
import ssh_state_machine
import ssh_memory_dump

# Import timing log function (for key lifecycle CSV)
try:
    from ssh_monitor import log_timing
except ImportError:
    # Fallback: define log_timing locally if ssh_monitor not available
    def log_timing(key_id, event, timestamp=None):
        """Log timing data to CSV (compatible with TLS timing format)"""
        import time
        if timestamp is None:
            timestamp = time.time()
        timing_csv = os.environ.get('LLDB_TIMING_CSV', '/data/lldb_results/timing_dropbear.csv')
        with open(timing_csv, 'a') as f:
            f.write(f"{timestamp},{key_id},{event},\n")

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_key_extracted = False
_key_address = None
_key_value = None

# KEX session tracking (for rekey lifecycle)
_kex_counter = 0     # Track total key extractions across all KEX sessions
_kex_session = 0     # Track KEX session number (1, 2, ...)

# LLDB objects
_target = None
_debugger = None
_process = None

# State machine for lifecycle tracking (v2.0)
_state_machine = None

# Architecture detection (v4.0 - for two-breakpoint pattern)
_arch = None

# Lifecycle function entry/exit state (v4.0 - two-breakpoint pattern)
_function_exit_state = {}  # {ret_addr: {'func_name': str, 'event_type': str}}

# Keylog path from environment
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/dropbear_client_keylog.log')

# Timing CSV path (for key lifecycle timing data)
# IMPORTANT: Must be in /data/lldb_results/ for collection by run_all_ssh_lifecycle_experiments.sh
TIMING_CSV = os.environ.get('LLDB_TIMING_CSV', '/data/lldb_results/timing_dropbear.csv')

# Initialize timing CSV with header if it doesn't exist
if not os.path.exists(TIMING_CSV):
    try:
        os.makedirs(os.path.dirname(TIMING_CSV), exist_ok=True)
        with open(TIMING_CSV, 'w') as f:
            f.write("timestamp,key_id,event,details\n")
        print(f"[DROPBEAR_CLIENT_CONFIG] Timing CSV initialized: {TIMING_CSV}")
    except Exception as e:
        print(f"[DROPBEAR_CLIENT_CONFIG] WARNING: Could not initialize timing CSV: {e}")

# v2.0: Memory dump configuration
ENABLE_MEMORY_DUMPS = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'false').lower() == 'true'
DUMP_TYPE = os.environ.get('LLDB_DUMP_TYPE', 'heap')  # 'full', 'heap', or 'keys'
DUMPS_DIR = os.environ.get('LLDB_DUMPS_DIR', '/data/dumps')

# Extended key extraction (extract all 6 RFC 4253 keys instead of just 1)
# Default: true (extract all keys A-F)
# Set to false for backward compatibility (extract only trans_cipher_key)
EXTRACT_ALL_KEYS = os.environ.get('LLDB_EXTRACT_ALL_KEYS', 'true').lower() == 'true'

# Watchpoint configuration: Check per-client variable first, then fall back to generic (default: enabled)
ENABLE_WATCHPOINTS = os.environ.get('LLDB_ENABLE_WATCHPOINTS_DROPBEAR',
                                    os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')).lower() == 'true'

# Watchpoint tracking
_watchpoints = {}  # Dict[key_name: str, tuple(wp_id, address, key_data)]

# v3.0: Function entry monitoring configuration
ENABLE_ENTRY_DUMPS = os.environ.get('LLDB_ENABLE_ENTRY_DUMPS', 'false').lower() == 'true'
ENTRY_DUMP_FUNCTIONS = os.environ.get('LLDB_ENTRY_DUMP_FUNCTIONS', 'all')  # 'all' or comma-separated list

# Log configuration at startup
print(f"[DROPBEAR_CLIENT_CONFIG] Watchpoints: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
print(f"[DROPBEAR_CLIENT_CONFIG] Memory dumps: {'ENABLED' if ENABLE_MEMORY_DUMPS else 'DISABLED'}")
print(f"[DROPBEAR_CLIENT_CONFIG] Function entry dumps: {'ENABLED' if ENABLE_ENTRY_DUMPS else 'DISABLED'}")

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

def write_keylog(key_hex, key_type="TRANS_CIPHER_KEY"):
    """Write extracted key to keylog file"""
    try:
        timestamp = get_microsecond_timestamp()
        with open(KEYLOG_PATH, 'a') as f:
            f.write(f"[{format_timestamp_us(timestamp)}] CLIENT {key_type}: {key_hex}\n")
        print(f"[CLIENT] ✓ Key logged to {KEYLOG_PATH}")
    except Exception as e:
        print(f"[CLIENT] ERROR writing keylog: {e}")

def get_return_address_aarch64(frame):
    """
    Extract return address from ARM64/aarch64 frame.
    On ARM64, return address is stored in LR (Link Register).

    Returns:
        int: Return address, or None if not found
    """
    try:
        lr = frame.FindRegister("lr")
        if lr and lr.IsValid():
            ret_addr = lr.GetValueAsUnsigned()
            if ret_addr > 0:
                return ret_addr
    except Exception as e:
        print(f"[RETURN_ADDR] ERROR reading LR (aarch64): {e}")
    return None

def get_return_address_x86_64(frame, process):
    """
    Extract return address from x86_64 frame.
    On x86-64, return address is on stack at RSP.

    Args:
        frame: LLDB stack frame
        process: LLDB process (for memory read)

    Returns:
        int: Return address, or None if not found
    """
    try:
        rsp = frame.FindRegister("rsp")
        if rsp and rsp.IsValid():
            error = lldb.SBError()
            ret_addr = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
            if error.Success() and ret_addr > 0:
                return ret_addr
    except Exception as e:
        print(f"[RETURN_ADDR] ERROR reading RSP (x86_64): {e}")
    return None

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
    - KEX session counter
    """
    global ENABLE_WATCHPOINTS, _watchpoints, _kex_session

    print(f"\n[WATCHPOINT_STATUS] === Watchpoint Status ===")
    print(f"[WATCHPOINT_STATUS] Global state: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
    print(f"[WATCHPOINT_STATUS] Active watchpoints: {len(_watchpoints)}")
    print(f"[WATCHPOINT_STATUS] KEX session: {_kex_session}")

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
        'command script add -f dropbear_client_callbacks.client_setup_monitoring client_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_client_callbacks.client_auto_continue client_auto_continue'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_client_callbacks.watchpoints_toggle watchpoints_toggle'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_client_callbacks.watchpoints_status watchpoints_status'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_client_callbacks.watchpoints_list watchpoints_list'
    )
    print("[CLIENT] Commands registered: client_setup_monitoring, client_auto_continue")
    print("[CLIENT] Watchpoint management: watchpoints_toggle, watchpoints_status, watchpoints_list")

# ═══════════════════════════════════════════════════════════════════════════
# SHARED SECRET K EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def kex_comb_key_entry(frame, bp_loc, internal_dict):
    """
    Entry callback for kex*_comb_key functions (DH/ECDH/Curve25519).
    Sets exit breakpoint to extract shared secret K after computation.
    """
    global _target

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()
    func_name = frame.GetFunctionName() or "kex_comb_key"

    print(f"\n[CLIENT_KEX_K_ENTRY] {func_name}() ENTRY in PID {pid}")
    print(f"[CLIENT_KEX_K_ENTRY] Setting exit breakpoint to extract shared secret K...")

    # Get return address (ARM64/x86-64 pattern)
    lr = frame.FindRegister("lr")
    if lr:
        ret_addr = lr.GetValueAsUnsigned()
        print(f"[CLIENT_KEX_K_ENTRY] Return address from LR (ARM64): 0x{ret_addr:x}")
    else:
        # x86-64: return address is on stack at RSP
        rsp = frame.FindRegister("rsp")
        if rsp:
            error = lldb.SBError()
            ret_addr = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
            if error.Success():
                print(f"[CLIENT_KEX_K_ENTRY] Return address from stack (x86-64): 0x{ret_addr:x}")
            else:
                print(f"[CLIENT_KEX_K_ENTRY] ERROR: Could not read return address from stack")
                return False
        else:
            print(f"[CLIENT_KEX_K_ENTRY] ERROR: Could not find LR or RSP register")
            return False

    # Create one-shot exit breakpoint
    bp = _target.BreakpointCreateByAddress(ret_addr)
    bp.SetOneShot(True)
    bp.SetScriptCallbackFunction("dropbear_client_callbacks.kex_comb_key_exit")
    bp.SetAutoContinue(False)
    print(f"[CLIENT_KEX_K_ENTRY] ✓ Exit breakpoint set (bp {bp.GetID()}, one-shot)")

    return False

def kex_comb_key_exit(frame, bp_loc, internal_dict):
    """
    Exit callback for kex*_comb_key functions.
    Extracts shared secret K from ses.dh_K (LibTomMath mp_int structure).
    """
    global _target, _kex_session

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()
    func_name = frame.GetFunctionName() or "kex_comb_key"

    print(f"\n[CLIENT_KEX_K_EXIT] {func_name}() EXIT in PID {pid}")
    print(f"[CLIENT_KEX_K_EXIT] Extracting shared secret K from ses.dh_K...")

    try:
        # Get ses variable (global in Dropbear)
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print(f"[CLIENT_KEX_K_EXIT] ERROR: 'ses' global variable not found")
            return False

        ses_var = ses_list.GetValueAtIndex(0)
        print(f"[CLIENT_KEX_K_EXIT] Found 'ses' at 0x{ses_var.GetLoadAddress():x}")

        # Navigate to ses.dh_K (pointer to mp_int)
        dh_K_child = ses_var.GetChildMemberWithName("dh_K")
        if not dh_K_child.IsValid():
            print(f"[CLIENT_KEX_K_EXIT] ERROR: Could not find ses.dh_K field")
            return False

        dh_K_ptr = dh_K_child.GetValueAsUnsigned(0)
        if dh_K_ptr == 0:
            print(f"[CLIENT_KEX_K_EXIT] ERROR: ses.dh_K is NULL")
            return False

        print(f"[CLIENT_KEX_K_EXIT] ses.dh_K pointer: 0x{dh_K_ptr:x}")

        # Read mp_int structure fields
        # LibTomMath mp_int: {int used, int alloc, mp_sign sign, mp_digit *dp}
        error = lldb.SBError()

        # Read used (int at offset 0)
        used = process.ReadUnsignedFromMemory(dh_K_ptr, 4, error)
        if error.Fail():
            print(f"[CLIENT_KEX_K_EXIT] ERROR reading mp_int.used: {error}")
            return False

        print(f"[CLIENT_KEX_K_EXIT] mp_int.used = {used} digits")

        # Read dp pointer (try offset 16 first for padding, fallback to 12)
        dp_ptr = process.ReadPointerFromMemory(dh_K_ptr + 16, error)
        if error.Fail() or dp_ptr == 0:
            print(f"[CLIENT_KEX_K_EXIT] Trying dp offset 12 (no padding)...")
            error.Clear()
            dp_ptr = process.ReadPointerFromMemory(dh_K_ptr + 12, error)
            if error.Fail() or dp_ptr == 0:
                print(f"[CLIENT_KEX_K_EXIT] ERROR reading mp_int.dp pointer: {error}")
                return False

        print(f"[CLIENT_KEX_K_EXIT] mp_int.dp pointer: 0x{dp_ptr:x}")

        # Read digits from dp array (uint32_t, 4 bytes each)
        digit_size = 4
        max_digits = min(used, 128)  # Safety limit

        digits = []
        for i in range(max_digits):
            digit = process.ReadUnsignedFromMemory(dp_ptr + i * digit_size, digit_size, error)
            if error.Fail():
                print(f"[CLIENT_KEX_K_EXIT] ERROR reading digit {i}: {error}")
                break
            digits.append(digit)

        if not digits:
            print(f"[CLIENT_KEX_K_EXIT] ERROR: Failed to read any mp_int digits")
            return False

        print(f"[CLIENT_KEX_K_EXIT] Read {len(digits)} digits")

        # Convert digits to bytes (little-endian digits -> big-endian bytes)
        # LibTomMath stores least significant digit first
        k_bytes = bytearray()
        for digit in reversed(digits):  # Reverse for big-endian
            for j in range(digit_size):
                k_bytes.append((digit >> (j * 8)) & 0xFF)

        # Trim leading zeros
        while len(k_bytes) > 1 and k_bytes[0] == 0:
            k_bytes = k_bytes[1:]

        k_hex = k_bytes.hex()
        print(f"[CLIENT_KEX_K_EXIT] ✓ Shared secret K ({len(k_bytes)} bytes): {k_hex[:64]}...")

        # Write to keylog (with KEX suffix for key update tracking)
        write_keylog(k_hex, f"SHARED_SECRET_KEX{_kex_session}")
        print(f"[CLIENT_KEX_K_EXIT] ✓ Shared secret K logged for KEX{_kex_session}")

    except Exception as e:
        print(f"[CLIENT_KEX_K_EXIT] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# KEY DERIVATION CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════

def kex_derive_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint on gen_new_keys - set exit breakpoint for key extraction"""
    global _target

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[CLIENT_KEX_ENTRY] gen_new_keys() ENTRY in PID {pid}")

    # Set one-shot breakpoint at function return address (ARM64/x86-64 pattern)
    print(f"[CLIENT_KEX_ENTRY] Setting exit breakpoint...")

    # Try ARM64 first (LR register), fallback to x86-64 (stack)
    lr = frame.FindRegister("lr")
    if lr:
        ret_addr = lr.GetValueAsUnsigned()
        print(f"[CLIENT_KEX_ENTRY] Return address from LR (ARM64): 0x{ret_addr:x}")
    else:
        # x86-64: return address is on stack at RSP
        rsp = frame.FindRegister("rsp")
        if rsp:
            error = lldb.SBError()
            ret_addr = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned(), error)
            if error.Success():
                print(f"[CLIENT_KEX_ENTRY] Return address from stack (x86-64): 0x{ret_addr:x}")
            else:
                print(f"[CLIENT_KEX_ENTRY] ERROR: Could not read return address from stack")
                return False
        else:
            print(f"[CLIENT_KEX_ENTRY] ERROR: Could not find LR or RSP register")
            return False

    bp = _target.BreakpointCreateByAddress(ret_addr)
    bp.SetOneShot(True)  # Fire once and auto-delete
    bp.SetScriptCallbackFunction("dropbear_client_callbacks.kex_derive_keys_exit")
    bp.SetAutoContinue(False)  # Don't auto-continue, let callback handle it
    print(f"[CLIENT_KEX_ENTRY] ✓ Exit breakpoint set (bp {bp.GetID()}, one-shot)")

    return False

def kex_derive_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys - extract keys after they're populated"""
    global _key_extracted, _key_address, _key_value, _target, _debugger
    global _state_machine, _kex_counter, _kex_session

    # Define log_timing locally to ensure it's accessible in this scope
    def log_timing(key_id, event, timestamp=None):
        """Log timing data to CSV (local definition for callback scope)"""
        import time
        import os
        try:
            if timestamp is None:
                timestamp = time.time()
            timing_csv = os.environ.get('LLDB_TIMING_CSV', '/data/lldb_results/timing_dropbear.csv')
            with open(timing_csv, 'a') as f:
                f.write(f"{timestamp},{key_id},{event},\n")
            print(f"[TIMING] Logged {key_id} {event} at {timestamp}")
        except Exception as e:
            print(f"[TIMING ERROR] Failed to log {key_id} {event}: {e}")

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[CLIENT_KEX_EXIT] gen_new_keys() EXIT in PID {pid}")

    if _key_extracted:
        print(f"[CLIENT_KEX_EXIT] Key already extracted, skipping")
        return False

    print(f"[CLIENT_KEX_EXIT] Extracting trans_cipher_key...")

    try:
        # Get ses global variable
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print(f"[CLIENT_KEX] ERROR: 'ses' global variable not found")
            return False

        ses_var = ses_list.GetValueAtIndex(0)
        print(f"[CLIENT_KEX] Found 'ses' at 0x{ses_var.GetLoadAddress():x}")

        # Navigate: ses.newkeys->trans.cipher_state
        newkeys = ses_var.GetChildMemberWithName("newkeys")
        if not newkeys.IsValid():
            print(f"[CLIENT_KEX] ERROR: ses.newkeys not found")
            return False

        newkeys_addr = newkeys.GetValueAsUnsigned()
        print(f"[CLIENT_KEX] ses.newkeys pointer: 0x{newkeys_addr:x}")

        # Dereference to get actual newkeys struct
        newkeys_type = newkeys.GetType().GetPointeeType()
        newkeys_deref = _target.CreateValueFromAddress("newkeys_deref",
                                                        lldb.SBAddress(newkeys_addr, _target),
                                                        newkeys_type)

        trans = newkeys_deref.GetChildMemberWithName("trans")
        if not trans.IsValid():
            print(f"[CLIENT_KEX] ERROR: newkeys->trans not found")
            return False

        # trans.cipher_state is a union containing ChaCha20-Poly1305 structure
        cipher_state = trans.GetChildMemberWithName("cipher_state")
        if not cipher_state.IsValid():
            print(f"[CLIENT_KEX] ERROR: trans.cipher_state not found")
            return False

        trans_cipher_addr = cipher_state.GetLoadAddress()
        print(f"[CLIENT_KEX] trans.cipher_state at 0x{trans_cipher_addr:x}")

        # Read cipher_state (80 bytes: 16 constant + 32 ChaCha20 + 32 Poly1305)
        error = lldb.SBError()
        trans_cipher_data = process.ReadMemory(trans_cipher_addr, 80, error)

        if not error.Success():
            print(f"[CLIENT_KEX] ERROR reading cipher_state: {error}")
            return False

        # ChaCha20-Poly1305 structure:
        # Bytes 0-15: constant (expan d32-byt ek)
        # Bytes 16-47: ChaCha20 key (32 bytes)
        # Bytes 48-79: Poly1305 key (32 bytes)

        chacha_constant = trans_cipher_data[:16]
        expected_constant = b'expand 32-byte k'

        if chacha_constant == expected_constant:
            # Extract ChaCha20 key (bytes 16-47)
            _key_value = trans_cipher_data[16:48]
            _key_address = trans_cipher_addr + 16
            print(f"[CLIENT_KEX] ✓ ChaCha20 key found at 0x{_key_address:x}")
            print(f"[CLIENT_KEX] Key: {_key_value.hex()}")

            # Write to keylog (with KEX suffix for key update tracking)
            write_keylog(_key_value.hex(), f"C_ENCRYPTION_KEY_CLIENT_TO_SERVER_KEX{_kex_session}")

            # Log timing (key derivation event)
            log_timing("C", "derived")

            _key_extracted = True
            print(f"[CLIENT_KEX] ✓ Key C (trans_cipher_key) extraction successful!")

            # SET WATCHPOINT for Key C (client-to-server encryption)
            _target = process.GetTarget()
            _debugger = _target.GetDebugger()
            key_name = "KEY_C_CLIENT_TO_SERVER"
            print(f"[CLIENT_KEX] Setting watchpoint for {key_name} at 0x{_key_address:x}")
            _set_watchpoint(key_name, _key_address, _key_value, "C")

            # EXTENDED KEY EXTRACTION (Keys A, B, D, E, F)
            if EXTRACT_ALL_KEYS:
                print(f"[CLIENT_KEX] Extended key extraction enabled - extracting remaining keys...")
                keys_extracted = 1  # Already have Key C

                # KEY D: RECV cipher key (server-to-client encryption)
                try:
                    recv = newkeys_deref.GetChildMemberWithName("recv")
                    if recv.IsValid():
                        recv_cipher_state = recv.GetChildMemberWithName("cipher_state")
                        if recv_cipher_state.IsValid():
                            recv_cipher_addr = recv_cipher_state.GetLoadAddress()
                            print(f"[CLIENT_KEX] recv.cipher_state at 0x{recv_cipher_addr:x}")

                            recv_cipher_data = process.ReadMemory(recv_cipher_addr, 80, error)
                            if error.Success():
                                # Verify ChaCha20 structure (same as trans)
                                recv_chacha_constant = recv_cipher_data[:16]
                                if recv_chacha_constant == expected_constant:
                                    recv_key = recv_cipher_data[16:48]  # ChaCha20 key
                                    recv_key_address = recv_cipher_addr + 16  # Offset to ChaCha20 key
                                    write_keylog(recv_key.hex(), f"D_ENCRYPTION_KEY_SERVER_TO_CLIENT_KEX{_kex_session}")

                                    # Log timing (key derivation event)
                                    log_timing("D", "derived")

                                    keys_extracted += 1
                                    print(f"[CLIENT_KEX] ✓ Key D (recv_cipher_key) extracted")

                                    # SET WATCHPOINT for Key D (server-to-client encryption)
                                    key_name = "KEY_D_SERVER_TO_CLIENT"
                                    print(f"[CLIENT_KEX] Setting watchpoint for {key_name} at 0x{recv_key_address:x}")
                                    _set_watchpoint(key_name, recv_key_address, recv_key, "D")
                                else:
                                    print(f"[CLIENT_KEX] ⚠️  recv.cipher_state doesn't match ChaCha20 pattern")
                            else:
                                print(f"[CLIENT_KEX] ⚠️  Could not read recv.cipher_state: {error}")
                        else:
                            print(f"[CLIENT_KEX] ⚠️  recv.cipher_state not found")
                    else:
                        print(f"[CLIENT_KEX] ⚠️  recv structure not found")
                except Exception as e:
                    print(f"[CLIENT_KEX] ⚠️  Key D extraction error: {e}")

                # KEYS A-B: IVs (Initial Vectors)
                # Dropbear may store IVs in separate fields or within cipher structures
                try:
                    # Try to find IV fields in trans and recv structures
                    trans_iv = trans.GetChildMemberWithName("iv")
                    recv_iv = recv.GetChildMemberWithName("iv")

                    if trans_iv.IsValid() and trans_iv.GetValueAsUnsigned() != 0:
                        # Extract trans IV (client-to-server)
                        trans_iv_addr = trans_iv.GetLoadAddress() if trans_iv.GetLoadAddress() > 0 else trans_iv.GetValueAsUnsigned()
                        if trans_iv_addr > 0:
                            # Typical IV size for ChaCha20 is 8 or 12 bytes
                            trans_iv_data = process.ReadMemory(trans_iv_addr, 12, error)
                            if error.Success() and trans_iv_data:
                                write_keylog(trans_iv_data.hex(), f"A_IV_CLIENT_TO_SERVER_KEX{_kex_session}")

                                # Log timing (key derivation event)
                                log_timing("A", "derived")

                                keys_extracted += 1
                                print(f"[CLIENT_KEX] ✓ Key A (trans IV) extracted ({len(trans_iv_data)} bytes)")
                    else:
                        print(f"[CLIENT_KEX] ℹ️  trans.iv not found (may be embedded in cipher_state)")

                    if recv_iv.IsValid() and recv_iv.GetValueAsUnsigned() != 0:
                        # Extract recv IV (server-to-client)
                        recv_iv_addr = recv_iv.GetLoadAddress() if recv_iv.GetLoadAddress() > 0 else recv_iv.GetValueAsUnsigned()
                        if recv_iv_addr > 0:
                            recv_iv_data = process.ReadMemory(recv_iv_addr, 12, error)
                            if error.Success() and recv_iv_data:
                                write_keylog(recv_iv_data.hex(), f"B_IV_SERVER_TO_CLIENT_KEX{_kex_session}")

                                # Log timing (key derivation event)
                                log_timing("B", "derived")

                                keys_extracted += 1
                                print(f"[CLIENT_KEX] ✓ Key B (recv IV) extracted ({len(recv_iv_data)} bytes)")
                    else:
                        print(f"[CLIENT_KEX] ℹ️  recv.iv not found (may be embedded in cipher_state)")

                except Exception as e:
                    print(f"[CLIENT_KEX] ℹ️  IV extraction skipped: {e}")

                # KEYS E-F: MAC keys (Integrity keys)
                # For AEAD ciphers (ChaCha20-Poly1305), these may not exist
                try:
                    trans_mackey = trans.GetChildMemberWithName("mackey")
                    recv_mackey = recv.GetChildMemberWithName("mackey")

                    if trans_mackey.IsValid() and trans_mackey.GetValueAsUnsigned() != 0:
                        # Extract trans MAC key (client-to-server)
                        trans_mac_addr = trans_mackey.GetLoadAddress() if trans_mackey.GetLoadAddress() > 0 else trans_mackey.GetValueAsUnsigned()
                        if trans_mac_addr > 0:
                            # Typical MAC key size is 32 bytes for Poly1305
                            trans_mac_data = process.ReadMemory(trans_mac_addr, 32, error)
                            if error.Success() and trans_mac_data and trans_mac_data != b'\x00' * 32:
                                write_keylog(trans_mac_data.hex(), f"E_INTEGRITY_KEY_CLIENT_TO_SERVER_KEX{_kex_session}")

                                # Log timing (key derivation event)
                                log_timing("E", "derived")

                                keys_extracted += 1
                                print(f"[CLIENT_KEX] ✓ Key E (trans MAC key) extracted")
                            else:
                                print(f"[CLIENT_KEX] ℹ️  trans.mackey is NULL (AEAD cipher)")
                    else:
                        print(f"[CLIENT_KEX] ℹ️  trans.mackey not found (AEAD cipher - no separate MAC)")

                    if recv_mackey.IsValid() and recv_mackey.GetValueAsUnsigned() != 0:
                        # Extract recv MAC key (server-to-client)
                        recv_mac_addr = recv_mackey.GetLoadAddress() if recv_mackey.GetLoadAddress() > 0 else recv_mackey.GetValueAsUnsigned()
                        if recv_mac_addr > 0:
                            recv_mac_data = process.ReadMemory(recv_mac_addr, 32, error)
                            if error.Success() and recv_mac_data and recv_mac_data != b'\x00' * 32:
                                write_keylog(recv_mac_data.hex(), f"F_INTEGRITY_KEY_SERVER_TO_CLIENT_KEX{_kex_session}")

                                # Log timing (key derivation event)
                                log_timing("F", "derived")

                                keys_extracted += 1
                                print(f"[CLIENT_KEX] ✓ Key F (recv MAC key) extracted")
                            else:
                                print(f"[CLIENT_KEX] ℹ️  recv.mackey is NULL (AEAD cipher)")
                    else:
                        print(f"[CLIENT_KEX] ℹ️  recv.mackey not found (AEAD cipher - no separate MAC)")

                except Exception as e:
                    print(f"[CLIENT_KEX] ℹ️  MAC key extraction skipped: {e}")

                print(f"[CLIENT_KEX] ✓ Extended extraction complete ({keys_extracted} keys total)")
            else:
                print(f"[CLIENT_KEX] Extended extraction disabled (LLDB_EXTRACT_ALL_KEYS=false)")
                print(f"[CLIENT_KEX] Only trans_cipher_key (Key C) extracted")

            # v2.0: STATE MACHINE TRANSITIONS
            # (global variables already declared at function start)
            if _state_machine and ENABLE_MEMORY_DUMPS:
                # Determine key count and type based on extraction mode
                if EXTRACT_ALL_KEYS:
                    key_count = keys_extracted
                    key_type = f'EXTENDED_MODE_{keys_extracted}_KEYS'
                else:
                    key_count = 1
                    key_type = 'SIMPLE_MODE_1_KEY'

                # Update KEX session tracking (for rekey lifecycle)
                # Dropbear extracts 6 keys per KEX session (A-F)
                prev_kex_counter = _kex_counter
                _kex_counter += key_count
                _kex_session = (_kex_counter + 5) // 6  # Session 1: 1-6 keys, Session 2: 7-12 keys

                print(f"[CLIENT_KEX] KEX tracking: counter={_kex_counter}, session={_kex_session} (prev={prev_kex_counter})")

                # REKEY_START: Trigger when entering session 2 (second KEX begins)
                # This happens when prev counter was 6 and current counter > 6
                if prev_kex_counter == 6 and _kex_counter > 6:
                    _state_machine.transition(
                        ssh_state_machine.SSHState.REKEY_START,
                        metadata={
                            'kex_session': _kex_session,
                            'trigger': 'rekey_initiated',
                            'total_keys': _kex_counter
                        }
                    )

                # KEX complete (key extracted)
                # Event 1: HANDSHAKE (KEX_COMPLETE) - creates pre/post dumps
                _state_machine.transition(
                    ssh_state_machine.SSHState.KEX_COMPLETE,
                    metadata={
                        'key_extracted': True,
                        'key_count': key_count,
                        'key_type': key_type,
                        'key_address': hex(_key_address),
                        'extract_all_keys': EXTRACT_ALL_KEYS,
                        'kex_session': _kex_session
                    }
                )
                # Event 2: TRAFFIC START (ACTIVE) - creates pre/post dumps
                # Changed from quick_transition() to transition() to ensure lifecycle dumps are created
                _state_machine.transition(
                    ssh_state_machine.SSHState.ACTIVE,
                    metadata={'ready_for_traffic': True, 'key_count': key_count, 'kex_session': _kex_session}
                )

                # REKEY_COMPLETE: Trigger when second KEX session completes (all 12 keys extracted)
                if _kex_counter == 12 and _kex_session == 2:
                    _state_machine.transition(
                        ssh_state_machine.SSHState.REKEY_COMPLETE,
                        metadata={
                            'kex_session': _kex_session,
                            'keys_extracted': key_count,
                            'total_keys': _kex_counter
                        }
                    )

            # Optional: Set hardware watchpoint to detect key clearing
            # (Disabled by default to avoid trace mode issues)
            # Uncomment to enable:
            # setup_watchpoint(_key_address, _debugger, _target)

        else:
            print(f"[CLIENT_KEX] ERROR: cipher_state doesn't match ChaCha20 pattern")
            print(f"[CLIENT_KEX] First 16 bytes: {trans_cipher_data[:16].hex()}")
            return False

    except Exception as e:
        print(f"[CLIENT_KEX] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

def setup_watchpoint(address, debugger, target):
    """Optional: Set hardware watchpoint on key memory"""
    global _key_address

    print(f"[CLIENT_KEX] Creating watchpoint on key at 0x{address:x}...")
    wp_error = lldb.SBError()
    watchpoint = target.WatchAddress(address, 1, False, True, wp_error)

    if not wp_error.Success():
        print(f"[CLIENT_KEX] ERROR: Watchpoint failed: {wp_error}")
        return

    wp_id = watchpoint.GetID()
    print(f"[CLIENT_KEX] ✓ Watchpoint {wp_id} created")

    # Inject one-shot callback
    callback_name = f"client_wp_cb_{wp_id}"
    callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    import datetime
    ts = datetime.datetime.now().timestamp()
    ts_str = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
    print(f"\\n[CLIENT_WP] 🎯 KEY OVERWRITE at {{ts_str}}")
    print(f"[CLIENT_WP] PID: {{frame.GetThread().GetProcess().GetProcessID()}}")
    print(f"[CLIENT_WP] PC: 0x{{frame.GetPC():x}}")
    print("[CLIENT_WP] One-shot: Returning False to disable")
    return False  # One-shot: disable after first hit
"""

    debugger.HandleCommand(f"script {callback_code}")
    debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")
    print(f"[CLIENT_KEX] ✓ One-shot watchpoint callback attached")

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def client_setup_monitoring(debugger, command, result, internal_dict):
    """Setup client-side monitoring v4.0 (single breakpoint on gen_new_keys + lifecycle monitoring)"""
    global _target, _debugger, _process, _state_machine, _arch

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[CLIENT] Dropbear Client-Side Monitoring v4.0")
    print("[CLIENT] No forking, simple flow")
    print("[CLIENT] Function Entry+Exit Monitoring: 11 lifecycle functions (two-breakpoint pattern)")
    print("="*70)

    # v4.0: Detect architecture for return address extraction
    triple = _target.GetTriple()
    if 'aarch64' in triple or 'arm64' in triple:
        _arch = 'aarch64'
    elif 'x86_64' in triple or 'x86-64' in triple:
        _arch = 'x86_64'
    else:
        # Fallback: try to detect from frame
        print(f"[CLIENT] WARNING: Unknown architecture from triple: {triple}")
        print(f"[CLIENT] Will attempt runtime detection from frame registers")
        _arch = 'unknown'

    print(f"[CLIENT] Architecture: {_arch}")

    # v2.0: Initialize state machine for lifecycle tracking
    # Initialize if EITHER dumps OR watchpoints are enabled (both need state machine)
    if ENABLE_MEMORY_DUMPS or ENABLE_WATCHPOINTS:
        _state_machine = ssh_state_machine.create_state_machine(
            _process, DUMPS_DIR, dump_type=DUMP_TYPE, enable_dumps=ENABLE_MEMORY_DUMPS
        )
        print(f"[CLIENT] ✓ State machine initialized")
        if ENABLE_MEMORY_DUMPS:
            print(f"[CLIENT]   → Memory dumps: ENABLED ({DUMP_TYPE} mode)")
            print(f"[CLIENT]   → Output: {DUMPS_DIR}")
        else:
            print(f"[CLIENT]   → Memory dumps: DISABLED")
        if ENABLE_WATCHPOINTS:
            print(f"[CLIENT]   → Watchpoints: ENABLED (timing CSVs)")
        else:
            print(f"[CLIENT]   → Watchpoints: DISABLED")
    else:
        print(f"[CLIENT] State machine: Disabled (dumps and watchpoints both disabled)")
        print(f"[CLIENT] Memory dumps: DISABLED")
        print(f"[CLIENT] Watchpoints: DISABLED")

    # Print key extraction mode
    if EXTRACT_ALL_KEYS:
        print(f"[CLIENT] Key extraction: EXTENDED MODE (extract all 6 RFC 4253 keys)")
    else:
        print(f"[CLIENT] Key extraction: SIMPLE MODE (extract only trans_cipher_key)")

    # Breakpoint 1: gen_new_keys ENTRY - sets exit breakpoint for key extraction
    kex_bp = _target.BreakpointCreateByName("gen_new_keys")
    if kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("dropbear_client_callbacks.kex_derive_keys_entry")
        kex_bp.SetAutoContinue(False)  # Stop to set exit breakpoint
        print(f"[CLIENT] ✓ Breakpoint on gen_new_keys() ENTRY (ID {kex_bp.GetID()})")
    else:
        print(f"[CLIENT] ⚠️  Could not set breakpoint on gen_new_keys()")

    # Breakpoint 2: kex*_comb_key functions - extract shared secret K
    kex_functions = ["kexdh_comb_key", "kexecdh_comb_key", "kexcurve25519_comb_key"]
    kex_k_bps_set = []
    for kex_func in kex_functions:
        kex_k_bp = _target.BreakpointCreateByName(kex_func)
        if kex_k_bp.IsValid() and kex_k_bp.GetNumLocations() > 0:
            kex_k_bp.SetScriptCallbackFunction("dropbear_client_callbacks.kex_comb_key_entry")
            kex_k_bp.SetAutoContinue(False)
            kex_k_bp.SetOneShot(False)  # Allow firing for both initial KEX and rekey
            kex_k_bps_set.append(kex_func)
            print(f"[CLIENT] ✓ Breakpoint on {kex_func}() ENTRY (ID {kex_k_bp.GetID()}) for shared secret K")

    if kex_k_bps_set:
        print(f"[CLIENT] ✓ Shared secret K extraction enabled for: {', '.join(kex_k_bps_set)}")
    else:
        print(f"[CLIENT] ⚠️  No KEX functions found - shared secret K extraction disabled")

    # ═══ NEW v3.0: Session close detection ═══
    print(f"[CLIENT] Setting up session close detection...")

    close_bp = _target.BreakpointCreateByName("session_cleanup")
    if not close_bp.IsValid() or close_bp.GetNumLocations() == 0:
        # Try alternative function
        close_bp = _target.BreakpointCreateByName("dropbear_exit")

    if close_bp.IsValid() and close_bp.GetNumLocations() > 0:
        close_bp.SetScriptCallbackFunction("dropbear_client_callbacks.session_close_callback")
        close_bp.SetAutoContinue(False)
        print(f"[CLIENT] ✓ Session close breakpoint set (ID {close_bp.GetID()}, {close_bp.GetNumLocations()} locations)")
    else:
        print(f"[CLIENT] ⚠️  Could not set session close breakpoint (non-critical)")

    # ═══ v4.0: Function Entry+Exit Monitoring (Two-Breakpoint Pattern) ═══
    if ENABLE_ENTRY_DUMPS:
        print(f"[CLIENT] Setting up function entry+exit monitoring (v4.0 two-breakpoint pattern)...")

        entry_functions = {
            'send_msg_channel_eof': 'send_msg_channel_eof_entry',
            'send_msg_channel_close': 'send_msg_channel_close_entry',
            'dropbear_exit': 'dropbear_exit_entry',
            'dropbear_close': 'dropbear_close_entry',
            'session_cleanup': 'session_cleanup_entry',
            # v4.0: Added 6 more lifecycle functions
            'cli_cleanup': 'cli_cleanup_entry',
            'common_session_cleanup': 'common_session_cleanup_entry',
            'session_identification': 'session_identification_entry',
            'session_loop': 'session_loop_entry',
            'send_msg_channel_request': 'send_msg_channel_request_entry',
            'recv_msg_channel_close': 'recv_msg_channel_close_entry',
            # KEX message function (added per user request)
            'recv_msg_newkeys': 'recv_msg_newkeys_entry'
        }

        # Filter functions if ENTRY_DUMP_FUNCTIONS is not 'all'
        if ENTRY_DUMP_FUNCTIONS != 'all':
            filter_list = [f.strip() for f in ENTRY_DUMP_FUNCTIONS.split(',')]
            entry_functions = {k: v for k, v in entry_functions.items() if k in filter_list}

        entry_bp_count = 0
        pending_bp_count = 0
        for func_name, callback_name in entry_functions.items():
            bp = _target.BreakpointCreateByName(func_name)
            if bp.IsValid():  # v4.0 FIX: Accept all valid breakpoints (including pending)
                # Attach callback to valid breakpoints (even if pending/0 locations)
                bp.SetScriptCallbackFunction(f"dropbear_client_callbacks.{callback_name}")
                bp.SetAutoContinue(False)
                entry_bp_count += 1

                num_locs = bp.GetNumLocations()
                if num_locs > 0:
                    print(f"[CLIENT] ✓ Entry+Exit breakpoint: {func_name}() (ID {bp.GetID()}, {num_locs} locations)")
                else:
                    pending_bp_count += 1
                    print(f"[CLIENT] ✓ Entry+Exit breakpoint: {func_name}() (ID {bp.GetID()}, pending - will resolve when library loads)")
            else:
                print(f"[CLIENT] ⚠️  Entry+Exit breakpoint: {func_name}() not found (non-critical)")

        if pending_bp_count > 0:
            print(f"[CLIENT] Entry+Exit monitoring: {entry_bp_count}/{len(entry_functions)} functions set ({pending_bp_count} pending, will resolve when library loads)")
        else:
            print(f"[CLIENT] Entry+Exit monitoring: {entry_bp_count}/{len(entry_functions)} functions set")
    else:
        print(f"[CLIENT] Function entry+exit monitoring: DISABLED (set LLDB_ENABLE_ENTRY_DUMPS=true to enable)")

    print("[CLIENT] Setup complete - ready for client_auto_continue")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# FUNCTION ENTRY MONITORING (v3.0)
# ═══════════════════════════════════════════════════════════════════════════

def generic_function_entry_callback(frame, bp_loc, internal_dict, func_name, event_type):
    """
    Generic entry callback for any Dropbear function.
    Takes memory dump at function entry and logs the event.

    Args:
        frame: LLDB stack frame
        bp_loc: Breakpoint location
        internal_dict: LLDB internal dictionary
        func_name: Function name (e.g., "send_msg_channel_eof")
        event_type: Event type for dump label (e.g., "channel_eof")
    """
    try:
        print(f"\n{'='*70}")
        print(f"[FUNCTION_ENTRY] {func_name}() - ENTRY")
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
        global _state_machine
        if _state_machine and ENABLE_MEMORY_DUMPS:
            label = f"{event_type}_entry"
            _state_machine.dump_now(
                label,
                metadata={
                    'function': func_name,
                    'event_type': event_type,
                    'arguments': args_info
                }
            )
            print(f"[{func_name}] ✓ Memory dump created: {label}")

        # Log to state machine event log
        if _state_machine:
            _state_machine.log_event(f"FUNCTION_ENTRY_{event_type.upper()}", {
                'function': func_name,
                'arguments': args_info
            })

        print(f"[{func_name}] Entry callback complete")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[{func_name}] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

def generic_function_exit_callback(frame, bp_loc, internal_dict):
    """
    Generic exit callback for lifecycle functions (v4.0 two-breakpoint pattern).
    Takes memory dump at function exit and logs the event.

    Retrieves metadata stored by entry callback from _function_exit_state.
    """
    global _function_exit_state, _state_machine, _arch

    try:
        # Get PC (return address) to match with stored state
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

        # Cleanup: Remove processed entry from global state
        del _function_exit_state[pc]

        print(f"[{func_name}] Exit callback complete")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[FUNCTION_EXIT] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

def generic_function_entry_exit_callback(frame, bp_loc, internal_dict, func_name, event_type):
    """
    Generic entry+exit callback for lifecycle functions (v4.0 two-breakpoint pattern).
    Takes memory dump at function entry, sets exit breakpoint for after-dump.

    Args:
        frame: LLDB stack frame
        bp_loc: Breakpoint location
        internal_dict: LLDB internal dictionary
        func_name: Function name (e.g., "send_msg_channel_eof")
        event_type: Event type for dump label (e.g., "channel_eof")
    """
    global _function_exit_state, _state_machine, _target, _arch

    try:
        print(f"\n{'='*70}")
        print(f"[FUNCTION_ENTRY] {func_name}() - ENTRY (with exit dump)")
        print(f"{'='*70}")

        # Take memory dump at function entry (if enabled)
        if _state_machine and ENABLE_MEMORY_DUMPS:
            label = f"{event_type}_entry"
            _state_machine.dump_now(
                label,
                metadata={
                    'function': func_name,
                    'event_type': event_type,
                    'phase': 'entry'
                }
            )
            print(f"[{func_name}] ✓ Memory dump created (entry): {label}")

        # Log to state machine event log
        if _state_machine:
            _state_machine.log_event(f"FUNCTION_ENTRY_{event_type.upper()}", {
                'function': func_name
            })

        # Set exit breakpoint for "after" dump
        # Get return address based on architecture
        thread = frame.GetThread()
        process = thread.GetProcess()

        if _arch == 'aarch64':
            ret_addr = get_return_address_aarch64(frame)
        elif _arch == 'x86_64':
            ret_addr = get_return_address_x86_64(frame, process)
        else:
            print(f"[{func_name}] WARNING: Unknown architecture '{_arch}', trying aarch64 first...")
            ret_addr = get_return_address_aarch64(frame)
            if not ret_addr:
                ret_addr = get_return_address_x86_64(frame, process)

        if ret_addr and ret_addr != 0:
            # Store metadata for exit callback
            _function_exit_state[ret_addr] = {
                'func_name': func_name,
                'event_type': event_type
            }

            # Create exit breakpoint
            exit_bp = _target.BreakpointCreateByAddress(ret_addr)
            if exit_bp.IsValid():
                exit_bp.SetOneShot(True)  # One-shot breakpoint
                exit_bp.SetScriptCallbackFunction("dropbear_client_callbacks.generic_function_exit_callback")
                exit_bp.SetAutoContinue(False)
                print(f"[{func_name}] ✓ Exit breakpoint set at 0x{ret_addr:x}")
            else:
                print(f"[{func_name}] WARNING: Could not create exit breakpoint at 0x{ret_addr:x}")
        else:
            print(f"[{func_name}] WARNING: Could not determine return address (arch={_arch})")

        print(f"[{func_name}] Entry callback complete")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[{func_name}] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

# Wrapper functions for each monitored function

def send_msg_channel_eof_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for send_msg_channel_eof() (v4.0 two-breakpoint pattern)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="send_msg_channel_eof",
        event_type="channel_eof"
    )

def send_msg_channel_close_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for send_msg_channel_close() (v4.0 two-breakpoint pattern)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="send_msg_channel_close",
        event_type="channel_close"
    )

def dropbear_exit_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for dropbear_exit() (v4.0 two-breakpoint pattern)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="dropbear_exit",
        event_type="exit"
    )

def dropbear_close_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for dropbear_close() (v4.0 two-breakpoint pattern)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="dropbear_close",
        event_type="close"
    )

def session_cleanup_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for session_cleanup() (v4.0 two-breakpoint pattern)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="session_cleanup",
        event_type="cleanup"
    )

# Additional lifecycle functions (v4.0 - expanding from 5 to 11 functions)

def cli_cleanup_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for cli_cleanup() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="cli_cleanup",
        event_type="cli_cleanup"
    )

def common_session_cleanup_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for common_session_cleanup() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="common_session_cleanup",
        event_type="common_cleanup"
    )

def session_identification_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for session_identification() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="session_identification",
        event_type="identification"
    )

def session_loop_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for session_loop() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="session_loop",
        event_type="session_loop"
    )

def send_msg_channel_request_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for send_msg_channel_request() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="send_msg_channel_request",
        event_type="channel_request"
    )

def recv_msg_channel_close_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for recv_msg_channel_close() (v4.0)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="recv_msg_channel_close",
        event_type="recv_channel_close"
    )

def recv_msg_newkeys_entry(frame, bp_loc, internal_dict):
    """Entry+Exit callback for recv_msg_newkeys() (KEX message - added per user request)"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="recv_msg_newkeys",
        event_type="recv_newkeys"
    )

# ═══════════════════════════════════════════════════════════════════════════
# SESSION CLOSE CALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def session_close_callback(frame, bp_loc, internal_dict):
    """
    Callback triggered when session_cleanup() or dropbear_exit() is called.
    Transitions to SESSION_CLOSED state (cleanup begins).

    This captures the moment when SSH session close is initiated, before
    keep-alive period and process exit.
    """
    global _state_machine

    func_name = frame.GetFunctionName()
    print(f"\n{'='*70}")
    print(f"[CLIENT_CLOSE] Session Close Detected: {func_name}()")
    print(f"{'='*70}")

    if _state_machine:
        _state_machine.transition(
            ssh_state_machine.SSHState.SESSION_CLOSED,
            metadata={
                'trigger': 'session_cleanup',
                'function': func_name
            }
        )
        print(f"[CLIENT_CLOSE] ✓ SESSION_CLOSED dump completed")
    else:
        print(f"[CLIENT_CLOSE] ⚠️  State machine not available")

    print(f"{'='*70}\n")
    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def client_auto_continue(debugger, command, result, internal_dict):
    """
    Auto-continue loop for client monitoring v2.0

    LIFECYCLE EVENT COVERAGE (BASE mode):
    - Event 1: HANDSHAKE (KEX_COMPLETE) ✓ - Captured when gen_new_keys() completes
    - Event 2: TRAFFIC (ACTIVE) ✓ - Captured immediately after KEX_COMPLETE
    - Event 3: SESSION_CLOSE (SESSION_CLOSED) ⚠️  - Currently only on process exit
    - Event 4: CLEANUP (CLEANUP) ⚠️  - Currently only on process exit

    NOTE: SESSION_CLOSED and CLEANUP currently trigger on process exit rather than during
    normal SSH session lifecycle. For proper lifecycle tracking, we would need to add breakpoints
    on Dropbear's session termination functions. This is acceptable for short-lived client
    connections but may miss early cleanup events in long-running sessions.
    """
    global _state_machine, _key_extracted

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[CLIENT_AUTO] Starting auto-continue loop v3.0")
    print("[CLIENT_AUTO] Will continue until process exits")
    print("[CLIENT_AUTO] Monitoring for /tmp/lldb_dump_pre_exit trigger file")

    # Initial continue
    process.Continue()
    print("[CLIENT_AUTO] Initial continue...")

    stop_count = 0
    max_iterations = 1000  # Safety limit to prevent infinite loops
    iteration = 0
    pre_session_close_triggered = False  # Track if we've dumped pre-exit state

    while process.GetState() != lldb.eStateExited and iteration < max_iterations:
        iteration += 1
        current_state = process.GetState()

        # ═══ File-based trigger for PRE_SESSION_CLOSE ═══
        if not pre_session_close_triggered and os.path.exists('/tmp/lldb_dump_pre_exit'):
            print(f"\n[CLIENT_AUTO] ⚡ Detected pre-exit trigger file at iteration {iteration}!")

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
                print(f"[CLIENT_AUTO] ✓ PRE_SESSION_CLOSE dump completed")

            # Clean up trigger file
            try:
                os.remove('/tmp/lldb_dump_pre_exit')
                print(f"[CLIENT_AUTO] ✓ Trigger file removed")
            except Exception as e:
                print(f"[CLIENT_AUTO] ⚠️  Failed to remove trigger file: {e}")

            pre_session_close_triggered = True

        if current_state == lldb.eStateStopped:
            stop_count += 1
            stop_reason = process.GetSelectedThread().GetStopReason()

            # Continue on all stops (breakpoints handle themselves)
            process.Continue()
            if stop_count % 100 == 0:  # Log every 100 stops to avoid spam
                print(f"[CLIENT_AUTO] Continued (stop #{stop_count}, iteration {iteration})")

        time.sleep(0.05)  # Brief sleep to avoid busy-waiting

    # Check if we hit the iteration limit
    if iteration >= max_iterations:
        print(f"\n[CLIENT_AUTO] ⚠️  WARNING: Hit maximum iteration limit ({max_iterations})")
        print(f"[CLIENT_AUTO] Process state: {current_state}")
        print(f"[CLIENT_AUTO] Total stops: {stop_count}")
        print(f"[CLIENT_AUTO] This suggests the process is stuck in a stop-continue loop")
        print(f"[CLIENT_AUTO] Forcing exit...")
        process.Kill()  # Force kill the process to exit the loop

    # v3.0: Final CLEANUP transition when process exits
    # (SESSION_CLOSED is now handled by session_close_callback breakpoint)
    if _state_machine and ENABLE_MEMORY_DUMPS:
        # Final cleanup transition only
        _state_machine.transition(
            ssh_state_machine.SSHState.CLEANUP,
            metadata={
                'cleanup_complete': True,
                'total_stops': stop_count,
                'total_iterations': iteration,
                'key_extracted': _key_extracted
            }
        )

        # Print state machine summary
        _state_machine.summary()

    print(f"\n[CLIENT_AUTO] Process exited after {iteration} stops")
    print(f"[CLIENT_AUTO] Key extracted: {_key_extracted}")
    print(f"[CLIENT_AUTO] Keylog path: {KEYLOG_PATH}")
