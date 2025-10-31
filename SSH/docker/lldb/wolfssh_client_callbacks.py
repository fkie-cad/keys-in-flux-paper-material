#!/usr/bin/env python3
"""
wolfSSH Client-Side Callbacks v3.1 - Cross-Platform (ARM64 + x86-64)

Hooks into wc_SSH_KDF() function in libwolfssl.so to extract SSH KEX keys.

Function signature:
    int wc_SSH_KDF(byte hashId, byte keyId,
                   byte* key, word32 keySz,
                   const byte* k, word32 kSz,
                   const byte* h, word32 hSz,
                   const byte* sessionId, word32 sessionIdSz);

Architecture Support:
    - ARM64 (aarch64): Parameters in x0-x7, then stack
    - x86-64 (amd64): Parameters in rdi, rsi, rdx, rcx, r8, r9, then stack

**v3.1 NEW FEATURES** (2025-10-30):
- Two-breakpoint pattern for lifecycle functions (before/after dumps)
- 10 new lifecycle function hooks with entry+exit dumps:
  * Cleanup: wolfSSH_Cleanup, wolfSSH_free, wolfSSH_shutdown
  * KEX protocol: DoKexInit, DoNewKeys, SendKexInit, SendKexDhInit,
    DoKexDhInit, SendKexDhReply, DoKexDhReply, wolfSSH_TriggerKeyExchange
- generic_function_entry_exit_callback() - sets exit breakpoint at return address
- generic_function_exit_callback() - handles exit dumps
- Uses _function_exit_state{} dict to pass metadata between entry/exit callbacks

**v3.0 FEATURES** (2025-10-28):
- Function entry monitoring with memory dumps for lifecycle functions
- Generic callback pattern for reusable function entry handling
- Configurable via LLDB_ENABLE_ENTRY_DUMPS and LLDB_ENTRY_DUMP_FUNCTIONS

**v2.0 FEATURES**:
- SSH protocol state machine integration (PRE_CONNECT → KEX_COMPLETE → ACTIVE → SESSION_CLOSED)
- Automatic memory dumps at protocol state transitions (pre/post)
- Full lifecycle experiment support (handshake, active, session close)
- Configurable dump modes: full, heap, or targeted key dumps

Pattern:
    - Entry callback: Extract pointers from registers/stack, store in internal_dict
    - Entry callback: Set exit breakpoint (LR for ARM64, return address for x86-64)
    - Exit callback: Read memory at stored pointers (values now populated)
    - Write dual keylogs: standard + debug format
    - v2.0: State transitions triggered at key milestones

Refactored to use shared SSH extraction utilities for architecture detection
and return address extraction (reduces code duplication).
"""

import lldb
import os
import datetime
import time
import sys

# Import shared SSH extraction utilities
sys.path.insert(0, '/opt/lldb')
try:
    from ssh_extraction_utils import (
        detect_architecture,
        get_return_address_aarch64,
        get_return_address_x86_64
    )
    EXTRACTION_UTILS_AVAILABLE = True
except ImportError:
    print("[WOLFSSH_CLIENT] WARNING: ssh_extraction_utils not available, using fallback")
    EXTRACTION_UTILS_AVAILABLE = False

    # Fallback implementations
    def detect_architecture(target):
        arch = target.GetTriple().split('-')[0]
        return 'aarch64' if 'aarch64' in arch or 'arm64' in arch else 'x86_64'

    def get_return_address_aarch64(frame):
        lr_reg = frame.FindRegister("lr")
        return lr_reg.GetValueAsUnsigned() if lr_reg else None

    def get_return_address_x86_64(frame):
        import struct
        sp = frame.GetSP()
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()
        ret_addr_data = process.ReadMemory(sp, 8, error)
        if not error.Fail():
            return struct.unpack('<Q', ret_addr_data)[0]
        return None

# Import lifecycle experiment infrastructure (v2.0)
try:
    import ssh_state_machine
    import ssh_memory_dump
    STATE_MACHINE_AVAILABLE = True
except ImportError:
    print("[WOLFSSH_CLIENT] WARNING: State machine modules not available, lifecycle features disabled")
    STATE_MACHINE_AVAILABLE = False
    ssh_state_machine = None
    ssh_memory_dump = None

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
        # IMPORTANT: Must be in /data/lldb_results/ for collection by run_all_ssh_lifecycle_experiments.sh
        timing_csv = os.environ.get('LLDB_TIMING_CSV', '/data/lldb_results/timing_wolfssh.csv')
        # Ensure directory exists
        os.makedirs(os.path.dirname(timing_csv), exist_ok=True)
        with open(timing_csv, 'a') as f:
            f.write(f"{timestamp},{key_id},{event},\n")

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_debugger = None
_target = None
_arch = None  # Auto-detected: 'aarch64' or 'x86_64'
_session_logged = False  # Track if shared secret/session_id logged once
_kdf_state = {}  # Shared state between entry and exit callbacks (keyed by return address)
_function_exit_state = {}  # Shared state for lifecycle function entry/exit callbacks

# State machine for lifecycle tracking (v2.0)
_state_machine = None
_kdf_counter = 0  # Track number of KDF calls (4 per KEX session for AEAD cipher)
_kex_session = 0  # Track KEX session number (1, 2, ...) for rekey lifecycle

# Watchpoint tracking
_watchpoints = {}  # Dict[key_name: str, tuple(wp_id, address, key_data)]
_process = None  # Will be set in setup

# Environment configuration
LLDB_KEYLOG = os.environ.get('LLDB_KEYLOG', '/data/keylogs/wolfssh_client_keylog.log')
LLDB_KEYLOG_DEBUG = LLDB_KEYLOG.replace('.log', '_debug.log')

# Timing CSV path (for key lifecycle timing data)
TIMING_CSV = os.environ.get('LLDB_TIMING_CSV', '/data/lldb_results/timing_wolfssh.csv')

# Initialize timing CSV with header if it doesn't exist
if not os.path.exists(TIMING_CSV):
    try:
        os.makedirs(os.path.dirname(TIMING_CSV), exist_ok=True)
        with open(TIMING_CSV, 'w') as f:
            f.write("timestamp,key_id,event,details\n")
        print(f"[WOLFSSH_CLIENT_CONFIG] Timing CSV initialized: {TIMING_CSV}")
    except Exception as e:
        print(f"[WOLFSSH_CLIENT_CONFIG] WARNING: Could not initialize timing CSV: {e}")

# v2.0: Memory dump configuration
ENABLE_MEMORY_DUMPS = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'false').lower() == 'true'
DUMP_TYPE = os.environ.get('LLDB_DUMP_TYPE', 'heap')  # 'full', 'heap', or 'keys'
DUMPS_DIR = os.environ.get('LLDB_DUMPS_DIR', '/data/dumps')

# Watchpoint configuration: Check per-client variable first, then fall back to generic (default: enabled)
ENABLE_WATCHPOINTS = os.environ.get('LLDB_ENABLE_WATCHPOINTS_WOLFSSH',
                                    os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')).lower() == 'true'

# v3.0: Function entry monitoring configuration
ENABLE_ENTRY_DUMPS = os.environ.get('LLDB_ENABLE_ENTRY_DUMPS', 'false').lower() == 'true'
ENTRY_DUMP_FUNCTIONS = os.environ.get('LLDB_ENTRY_DUMP_FUNCTIONS', 'all')  # 'all' or comma-separated list

# Log configuration at startup
print(f"[WOLFSSH_CLIENT_CONFIG] Watchpoints: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
print(f"[WOLFSSH_CLIENT_CONFIG] Memory dumps: {'ENABLED' if ENABLE_MEMORY_DUMPS else 'DISABLED'}")
print(f"[WOLFSSH_CLIENT_CONFIG] Function entry dumps: {'ENABLED' if ENABLE_ENTRY_DUMPS else 'DISABLED'}")
if ENABLE_ENTRY_DUMPS:
    if ENTRY_DUMP_FUNCTIONS == 'all':
        print(f"[WOLFSSH_CLIENT_CONFIG]   ├─ Lifecycle: shutdown, free, trigger_kex")
        print(f"[WOLFSSH_CLIENT_CONFIG]   └─ Rekey detection: 10 crypto functions (SendKexInit, GenerateKey, wc_*)")
    else:
        print(f"[WOLFSSH_CLIENT_CONFIG]   └─ Selective: {ENTRY_DUMP_FUNCTIONS}")

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_timestamp():
    """Get current timestamp with microsecond precision"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def write_keylog(message):
    """Write to standard keylog file"""
    try:
        timestamp = get_timestamp()
        with open(LLDB_KEYLOG, 'a') as f:
            f.write(f"{timestamp} {message}\n")
        print(f"[WOLFSSH_KEYLOG] {message}")
    except Exception as e:
        print(f"[WOLFSSH_KEYLOG] ERROR writing: {e}")

def write_keylog_debug(message):
    """Write to debug keylog file"""
    try:
        timestamp = get_timestamp()
        with open(LLDB_KEYLOG_DEBUG, 'a') as f:
            f.write(f"{timestamp} {message}\n")
        print(f"[WOLFSSH_DEBUG] {message}")
    except Exception as e:
        print(f"[WOLFSSH_DEBUG] ERROR writing: {e}")

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
        # Watch only 1 byte to minimize multiple triggers during memset
        watchpoint = _target.WatchAddress(address, 1, False, True, error)

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

    # Delete watchpoint BEFORE returning (one-shot pattern)
    # Returning False alone doesn't prevent re-triggering during same memory operation
    try:
        import lldb
        # bp_loc in a watchpoint callback is already an SBWatchpoint object
        watchpoint = bp_loc
        if watchpoint and watchpoint.IsValid():
            # Get target from frame context (watchpoint doesn't have GetTarget())
            wp_id = watchpoint.GetID()
            # Use frame.GetThread().GetProcess().GetTarget() to get target
            target = frame.GetThread().GetProcess().GetTarget()
            target.DeleteWatchpoint(wp_id)
            print(f"[KEY_OVERWRITE] Watchpoint {{wp_id}} deleted (one-shot)")
    except Exception as e:
        print(f"[KEY_OVERWRITE] Could not delete watchpoint: {{e}}")

    # Return False for good measure (watchpoint already deleted)
    return False
'''

        # Inject callback using Dropbear's proven pattern
        # Step 1: Inject callback into LLDB Python namespace
        _debugger.HandleCommand(f"script {callback_code}")

        # Step 2: Also inject into module globals as backup
        try:
            exec(callback_code, globals())
        except Exception as e:
            print(f"[WATCHPOINT] Warning: Could not exec into globals: {e}")
            pass  # Non-fatal

        # Step 3: Attach callback to watchpoint with -F flag
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # Store watchpoint info
        _watchpoints[key_name] = (wp_id, address, key_data)

        print(f"[WATCHPOINT] Set on {key_name} at 0x{address:x} (wp {wp_id})")
        print(f"[WATCHPOINT] Key preview: {key_data[:16].hex()}...")

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# ARCHITECTURE-AWARE PARAMETER EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def extract_wc_ssh_kdf_params_aarch64(frame, process):
    """
    Extract wc_SSH_KDF parameters on ARM64 (aarch64)

    Hybrid approach:
    1. Try symbol-aware extraction (FindVariable) - requires debug symbols
    2. Fall back to register reading - works without symbols (pattern mode)

    Parameters:
        byte hashId, byte keyId, byte* key, word32 keySz,
        const byte* k, word32 kSz, const byte* h, word32 hSz,
        const byte* sessionId, word32 sessionIdSz
    """
    error = lldb.SBError()

    # METHOD 1: Try symbol-aware extraction (requires debug symbols)
    var_hashId = frame.FindVariable("hashId")
    var_keyId = frame.FindVariable("keyId")

    # Check if debug symbols are available
    if var_hashId.IsValid() and var_keyId.IsValid():
        # Success: Debug symbols available, use symbol-aware extraction
        print("[WOLFSSH_ARM64] Using symbol-aware extraction (debug symbols present)")

        var_key = frame.FindVariable("key")
        var_keySz = frame.FindVariable("keySz")
        var_k = frame.FindVariable("k")
        var_kSz = frame.FindVariable("kSz")
        var_h = frame.FindVariable("h")
        var_hSz = frame.FindVariable("hSz")
        var_sessionId = frame.FindVariable("sessionId")
        var_sessionIdSz = frame.FindVariable("sessionIdSz")

        hashId = var_hashId.GetValueAsUnsigned() & 0xFF
        keyId = var_keyId.GetValueAsUnsigned() & 0xFF
        key_ptr = var_key.GetValueAsUnsigned()
        keySz = var_keySz.GetValueAsUnsigned()
        k_ptr = var_k.GetValueAsUnsigned()
        kSz = var_kSz.GetValueAsUnsigned()
        h_ptr = var_h.GetValueAsUnsigned()
        hSz = var_hSz.GetValueAsUnsigned()
        sessionId_ptr = var_sessionId.GetValueAsUnsigned()
        sessionIdSz = var_sessionIdSz.GetValueAsUnsigned()
    else:
        # METHOD 2: Fallback to register reading (no debug symbols)
        print("[WOLFSSH_ARM64] ⚠️  Falling back to register extraction (no debug symbols)")
        print("[WOLFSSH_ARM64]   This may fail if breakpoint is after function prologue")

        # Read from registers x0-x7 (ARM64 calling convention)
        hashId = frame.FindRegister("x0").GetValueAsUnsigned() & 0xFF
        keyId = frame.FindRegister("x1").GetValueAsUnsigned() & 0xFF
        key_ptr = frame.FindRegister("x2").GetValueAsUnsigned()
        keySz = frame.FindRegister("x3").GetValueAsUnsigned()
        k_ptr = frame.FindRegister("x4").GetValueAsUnsigned()
        kSz = frame.FindRegister("x5").GetValueAsUnsigned()
        h_ptr = frame.FindRegister("x6").GetValueAsUnsigned()
        hSz = frame.FindRegister("x7").GetValueAsUnsigned()

        # Read from stack
        sp = frame.FindRegister("sp").GetValueAsUnsigned()
        sessionId_ptr = process.ReadPointerFromMemory(sp, error)
        if error.Fail():
            print(f"[WOLFSSH_ARM64] ERROR reading sessionId ptr from stack: {error}")
            sessionId_ptr = 0

        sessionIdSz = process.ReadPointerFromMemory(sp + 8, error)
        if error.Fail():
            print(f"[WOLFSSH_ARM64] ERROR reading sessionIdSz from stack: {error}")
            sessionIdSz = 0

    # Get return address using shared utility (from ssh_extraction_utils)
    ret_addr = get_return_address_aarch64(frame)

    return {
        'hashId': hashId,
        'keyId': keyId,
        'key_ptr': key_ptr,
        'keySz': keySz,
        'k_ptr': k_ptr,
        'kSz': kSz,
        'h_ptr': h_ptr,
        'hSz': hSz,
        'sessionId_ptr': sessionId_ptr,
        'sessionIdSz': sessionIdSz,
        'ret_addr': ret_addr
    }

def extract_wc_ssh_kdf_params_x86_64(frame, process):
    """
    Extract wc_SSH_KDF parameters on x86-64 (amd64)

    Hybrid approach:
    1. Try symbol-aware extraction (FindVariable) - requires debug symbols
    2. Fall back to register reading - works without symbols (pattern mode)

    Parameters:
        byte hashId, byte keyId, byte* key, word32 keySz,
        const byte* k, word32 kSz, const byte* h, word32 hSz,
        const byte* sessionId, word32 sessionIdSz

    x86-64 calling convention: rdi, rsi, rdx, rcx, r8, r9, then stack
    """
    error = lldb.SBError()

    # METHOD 1: Try symbol-aware extraction (requires debug symbols)
    var_hashId = frame.FindVariable("hashId")
    var_keyId = frame.FindVariable("keyId")

    if var_hashId.IsValid() and var_keyId.IsValid():
        # Success: Debug symbols available, use symbol-aware extraction
        print("[WOLFSSH_x86_64] Using symbol-aware extraction (debug symbols present)")

        var_key = frame.FindVariable("key")
        var_keySz = frame.FindVariable("keySz")
        var_k = frame.FindVariable("k")
        var_kSz = frame.FindVariable("kSz")
        var_h = frame.FindVariable("h")
        var_hSz = frame.FindVariable("hSz")
        var_sessionId = frame.FindVariable("sessionId")
        var_sessionIdSz = frame.FindVariable("sessionIdSz")

        hashId = var_hashId.GetValueAsUnsigned() & 0xFF
        keyId = var_keyId.GetValueAsUnsigned() & 0xFF
        key_ptr = var_key.GetValueAsUnsigned()
        keySz = var_keySz.GetValueAsUnsigned()
        k_ptr = var_k.GetValueAsUnsigned()
        kSz = var_kSz.GetValueAsUnsigned()
        h_ptr = var_h.GetValueAsUnsigned()
        hSz = var_hSz.GetValueAsUnsigned()
        sessionId_ptr = var_sessionId.GetValueAsUnsigned()
        sessionIdSz = var_sessionIdSz.GetValueAsUnsigned()

    else:
        # METHOD 2: Fallback to register extraction (works without debug symbols)
        print("[WOLFSSH_x86_64] ⚠️  Falling back to register extraction (no debug symbols)")
        print("[WOLFSSH_x86_64]   This may fail if breakpoint is after function prologue")

        # x86-64 calling convention: rdi, rsi, rdx, rcx, r8, r9, then stack
        # Parameters: hashId(rdi), keyId(rsi), key(rdx), keySz(rcx), k(r8), kSz(r9), ...
        hashId = frame.FindRegister("rdi").GetValueAsUnsigned() & 0xFF
        keyId = frame.FindRegister("rsi").GetValueAsUnsigned() & 0xFF
        key_ptr = frame.FindRegister("rdx").GetValueAsUnsigned()
        keySz = frame.FindRegister("rcx").GetValueAsUnsigned()
        k_ptr = frame.FindRegister("r8").GetValueAsUnsigned()
        kSz = frame.FindRegister("r9").GetValueAsUnsigned()

        # Remaining parameters (h, hSz, sessionId, sessionIdSz) are on the stack
        rsp = frame.FindRegister("rsp").GetValueAsUnsigned()

        # Stack layout after return address: +8=h, +16=hSz, +24=sessionId, +32=sessionIdSz
        h_ptr = process.ReadPointerFromMemory(rsp + 8, error)
        if error.Fail():
            print(f"[WOLFSSH_x86_64] ERROR reading h ptr from stack: {error}")
            h_ptr = 0

        hSz = process.ReadPointerFromMemory(rsp + 16, error)
        if error.Fail():
            print(f"[WOLFSSH_x86_64] ERROR reading hSz from stack: {error}")
            hSz = 0

        sessionId_ptr = process.ReadPointerFromMemory(rsp + 24, error)
        if error.Fail():
            print(f"[WOLFSSH_x86_64] ERROR reading sessionId ptr from stack: {error}")
            sessionId_ptr = 0

        sessionIdSz = process.ReadPointerFromMemory(rsp + 32, error)
        if error.Fail():
            print(f"[WOLFSSH_x86_64] ERROR reading sessionIdSz from stack: {error}")
            sessionIdSz = 0

    # Get return address using shared utility (from ssh_extraction_utils)
    ret_addr = get_return_address_x86_64(frame, process)

    return {
        'hashId': hashId,
        'keyId': keyId,
        'key_ptr': key_ptr,
        'keySz': keySz,
        'k_ptr': k_ptr,
        'kSz': kSz,
        'h_ptr': h_ptr,
        'hSz': hSz,
        'sessionId_ptr': sessionId_ptr,
        'sessionIdSz': sessionIdSz,
        'ret_addr': ret_addr
    }

# ═══════════════════════════════════════════════════════════════════════════
# WC_SSH_KDF CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════

def wc_ssh_kdf_entry(frame, bp_loc, internal_dict):
    """
    Entry callback for wc_SSH_KDF() function

    Extracts parameters from registers/stack based on architecture,
    stores pointers in internal_dict, and sets exit breakpoint.
    """
    global _arch, _target

    if _arch is None:
        print("[WOLFSSH_KDF] ERROR: Architecture not detected!")
        return False

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    # Extract parameters based on architecture
    if _arch == 'aarch64':
        params = extract_wc_ssh_kdf_params_aarch64(frame, process)
    elif _arch == 'x86_64':
        params = extract_wc_ssh_kdf_params_x86_64(frame, process)
    else:
        print(f"[WOLFSSH_KDF] ERROR: Unsupported architecture: {_arch}")
        return False

    keyId = params['keyId']
    keyId_char = chr(keyId) if 0x41 <= keyId <= 0x46 else f"0x{keyId:02x}"

    print(f"\n[WOLFSSH_KDF_ENTRY] PID {pid} | keyId={keyId_char} | arch={_arch}")
    print(f"  hashId=0x{params['hashId']:02x} keySz={params['keySz']} kSz={params['kSz']} hSz={params['hSz']} sessionIdSz={params['sessionIdSz']}")

    # Set one-shot exit breakpoint
    ret_addr = params['ret_addr']
    if ret_addr == 0:
        print(f"[WOLFSSH_KDF_ENTRY] ERROR: Invalid return address, cannot set exit breakpoint")
        return False

    # Store all parameters in global state dictionary (keyed by return address)
    global _kdf_state
    _kdf_state[ret_addr] = params
    print(f"[WOLFSSH_KDF_ENTRY] Stored parameters in global state for ret_addr=0x{ret_addr:x}")

    exit_bp = _target.BreakpointCreateByAddress(ret_addr)
    if not exit_bp.IsValid():
        print(f"[WOLFSSH_KDF_ENTRY] ERROR: Failed to create exit breakpoint at 0x{ret_addr:x}")
        return False

    exit_bp.SetOneShot(True)
    exit_bp.SetScriptCallbackFunction("wolfssh_client_callbacks.wc_ssh_kdf_exit")

    print(f"[WOLFSSH_KDF_ENTRY] Exit breakpoint set at 0x{ret_addr:x}")

    return False  # Continue execution

def wc_ssh_kdf_exit(frame, bp_loc, internal_dict):
    """
    Exit callback for wc_SSH_KDF() function

    Reads memory at stored pointers (values now populated),
    extracts keys and writes to dual keylogs.
    """
    global _session_logged, _kdf_state, _state_machine, _kdf_counter, _kex_session

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()
    error = lldb.SBError()

    # FIX: Refresh stale process reference in state machine
    # State machine was created during setup with old process reference.
    # By the time EXIT callback fires, that reference becomes stale (0 modules).
    # Solution: Refresh with current process from frame (like OpenSSH does).
    if _state_machine:
        _state_machine.process = process  # Update to fresh process reference

    # Get return address (PC at exit breakpoint)
    pc = frame.GetPC()

    print(f"\n[WOLFSSH_KDF_EXIT] PID {pid} | PC=0x{pc:x}")

    # Retrieve stored parameters from global state
    if pc not in _kdf_state:
        print(f"[WOLFSSH_KDF_EXIT] ERROR: No stored parameters for PC=0x{pc:x}")
        print(f"[WOLFSSH_KDF_EXIT] Available keys: {[hex(k) for k in _kdf_state.keys()]}")
        return False

    params = _kdf_state[pc]
    hashId = params['hashId']
    keyId = params['keyId']
    key_ptr = params['key_ptr']
    keySz = params['keySz']
    k_ptr = params['k_ptr']
    kSz = params['kSz']
    h_ptr = params['h_ptr']
    hSz = params['hSz']
    sessionId_ptr = params['sessionId_ptr']
    sessionIdSz = params['sessionIdSz']

    keyId_char = chr(keyId) if 0x41 <= keyId <= 0x46 else f"0x{keyId:02x}"

    print(f"[WOLFSSH_KDF_EXIT] Retrieved parameters for keyId={keyId_char}")

    # Read derived key (output parameter - now populated)
    if key_ptr and keySz > 0:
        key_data = process.ReadMemory(key_ptr, keySz, error)
        if error.Success():
            key_hex = key_data.hex()
        else:
            print(f"[WOLFSSH_KDF_EXIT] ERROR reading key: {error}")
            key_hex = None
    else:
        key_hex = None

    # Read shared secret k (input parameter - for debug log)
    if k_ptr and kSz > 0:
        k_data = process.ReadMemory(k_ptr, kSz, error)
        if error.Success():
            k_hex = k_data.hex()
        else:
            print(f"[WOLFSSH_KDF_EXIT] ERROR reading k: {error}")
            k_hex = None
    else:
        k_hex = None

    # Read exchange hash H (input parameter - for debug log)
    if h_ptr and hSz > 0:
        h_data = process.ReadMemory(h_ptr, hSz, error)
        if error.Success():
            h_hex = h_data.hex()
        else:
            print(f"[WOLFSSH_KDF_EXIT] ERROR reading H: {error}")
            h_hex = None
    else:
        h_hex = None

    # Read session ID (input parameter - for debug log)
    if sessionId_ptr and sessionIdSz > 0:
        sessionId_data = process.ReadMemory(sessionId_ptr, sessionIdSz, error)
        if error.Success():
            sessionId_hex = sessionId_data.hex()
        else:
            print(f"[WOLFSSH_KDF_EXIT] ERROR reading sessionId: {error}")
            sessionId_hex = None
    else:
        sessionId_hex = None

    # Map keyId to OpenSSH-compatible key names (RFC 4253)
    KEY_NAME_MAP = {
        0x41: "A_IV_CLIENT_TO_SERVER",              # 'A'
        0x42: "B_IV_SERVER_TO_CLIENT",              # 'B'
        0x43: "C_ENCRYPTION_KEY_CLIENT_TO_SERVER",  # 'C'
        0x44: "D_ENCRYPTION_KEY_SERVER_TO_CLIENT",  # 'D'
        0x45: "E_MAC_KEY_CLIENT_TO_SERVER",         # 'E' (not used in AEAD)
        0x46: "F_MAC_KEY_SERVER_TO_CLIENT"          # 'F' (not used in AEAD)
    }

    key_name = KEY_NAME_MAP.get(keyId, f"UNKNOWN_{keyId_char}")

    # Write to standard keylog (OpenSSH-compatible format with KEX suffix for rekey tracking)
    if key_hex:
        # Get Unix timestamp with microseconds for precise correlation
        import time
        timestamp = time.time()
        write_keylog(f"{timestamp:.6f} CLIENT {key_name}_KEX{_kex_session}: {key_hex}")

        # Log timing (key derivation event) - use keyId_char for key ID (A, B, C, D, etc.)
        log_timing(keyId_char, "derived")

    # Write to debug keylog (extended format)
    # Write shared secrets for each KEX session (removed one-time flag for rekey support)
    if k_hex and h_hex and sessionId_hex:
        # Log to both main and debug keylogs (with KEX suffix)
        write_keylog(f"SHARED_SECRET_KEX{_kex_session} {k_hex}")
        write_keylog_debug(f"SHARED_SECRET_KEX{_kex_session} {k_hex}")
        write_keylog_debug(f"EXCHANGE_HASH_KEX{_kex_session} {h_hex}")
        write_keylog_debug(f"SESSION_ID_KEX{_kex_session} {sessionId_hex}")
        print(f"[WOLFSSH_DEBUG] KEX{_kex_session} secrets logged (k={kSz}B, H={hSz}B, sessionId={sessionIdSz}B)")

    # Write extended key entry with metadata (debug log with KEX suffix)
    if key_hex:
        write_keylog_debug(f"CLIENT {key_name}_KEX{_kex_session}: {key_hex} # KEYID={keyId_char} SIZE={keySz}B")

    # SET WATCHPOINTS for C & D encryption keys
    if key_data and key_ptr and keyId in [0x43, 0x44]:  # C & D keys only
        try:
            global _target, _debugger
            target = process.GetTarget()
            _target = target
            _debugger = target.GetDebugger()

            # Create descriptive watchpoint name (use wp_name to avoid shadowing key_name)
            wp_name = f"KEY_{keyId_char}"  # e.g., "KEY_C" or "KEY_D"

            print(f"[WOLFSSH_KDF_EXIT] Setting watchpoint for {wp_name} ({key_name}) at 0x{key_ptr:x}")
            _set_watchpoint(wp_name, key_ptr, key_data, keyId_char)
        except Exception as e:
            print(f"[WOLFSSH_KDF_EXIT] ERROR setting watchpoint: {e}")
            import traceback
            traceback.print_exc()
            # Continue anyway - don't let watchpoint failures stop key extraction

    # v2.0: STATE MACHINE TRANSITIONS
    # (global declaration moved to function start at line 555)

    # Update KEX session tracking (for rekey lifecycle)
    # wolfSSH extracts 4 keys per KEX session (A-D for AEAD cipher)
    prev_kdf_counter = _kdf_counter
    _kdf_counter += 1
    _kex_session = (_kdf_counter - 1) // 4 + 1  # Session 1: keys 1-4, Session 2: keys 5-8, etc.

    if _state_machine and ENABLE_MEMORY_DUMPS:
        try:
            # REKEY_START: Trigger when entering session 2 (second KEX begins)
            # This happens when prev counter was 4 and current counter > 4
            if prev_kdf_counter == 4 and _kdf_counter > 4:
                _state_machine.transition(
                    ssh_state_machine.SSHState.REKEY_START,
                    metadata={
                        'kex_session': _kex_session,
                        'trigger': 'rekey_initiated',
                        'total_keys': _kdf_counter
                    }
                )

            # Transition at KEY milestones (wolfSSH calls wc_SSH_KDF 4 times: A-D for AEAD ciphers)
            if _kdf_counter == 4 or _kdf_counter == 8:
                # KEX complete (all 4 keys extracted - AEAD cipher, no separate MAC keys)
                # Event 1: HANDSHAKE (KEX_COMPLETE) - creates pre/post dumps
                _state_machine.transition(
                    ssh_state_machine.SSHState.KEX_COMPLETE,
                    metadata={
                        'keys_extracted': 4,
                        'method': 'wc_SSH_KDF',
                        'keyId_last': keyId_char,
                        'cipher_type': 'AEAD (ChaCha20-Poly1305)',
                        'kex_session': _kex_session
                    }
                )
                # Event 2: TRAFFIC START (ACTIVE) - creates pre/post dumps
                # Changed from quick_transition() to transition() to ensure lifecycle dumps are created
                _state_machine.transition(
                    ssh_state_machine.SSHState.ACTIVE,
                    metadata={'ready_for_traffic': True, 'kdf_counter': _kdf_counter, 'kex_session': _kex_session}
                )

                # REKEY_COMPLETE: Trigger when second KEX session completes (all 8 keys extracted)
                if _kdf_counter == 8 and _kex_session == 2:
                    _state_machine.transition(
                        ssh_state_machine.SSHState.REKEY_COMPLETE,
                        metadata={
                            'kex_session': _kex_session,
                            'keys_extracted': 4,
                            'total_keys': _kdf_counter
                        }
                    )
        except Exception as e:
            print(f"[WOLFSSH_KDF_EXIT] ERROR during state machine transitions: {e}")
            import traceback
            traceback.print_exc()
            # Continue anyway - don't let dump failures stop key extraction

    # Cleanup: Remove processed entry from global state
    del _kdf_state[pc]
    print(f"[WOLFSSH_KDF_EXIT] Cleaned up state for PC=0x{pc:x}")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def wolfssh_setup_monitoring(debugger, command, result, internal_dict):
    """
    Setup wolfSSH client-side monitoring v2.0

    Sets breakpoint on wc_SSH_KDF() in libwolfssl.so and initializes state machine.
    """
    global _debugger, _target, _arch, _state_machine, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()

    if not _target.IsValid():
        print("[WOLFSSH_SETUP] ERROR: No valid target")
        return

    # Detect architecture using shared utility (from ssh_extraction_utils)
    _arch = detect_architecture(_target)

    print("\n" + "="*70)
    print("[WOLFSSH_SETUP] wolfSSH Client-Side Monitoring v3.0")
    print(f"[WOLFSSH_SETUP] Architecture: {_arch}")
    print("[WOLFSSH_SETUP] Function Entry Monitoring: 3 lifecycle functions")
    print("="*70)

    if _arch == 'unknown':
        triple = _target.GetTriple()
        print(f"[WOLFSSH_SETUP] WARNING: Unknown architecture in triple: {triple}")

    # v2.0: Initialize state machine for lifecycle tracking
    # Initialize if EITHER dumps OR watchpoints are enabled (both need state machine)
    if (ENABLE_MEMORY_DUMPS or ENABLE_WATCHPOINTS) and STATE_MACHINE_AVAILABLE:
        _process = _target.GetProcess()
        _state_machine = ssh_state_machine.create_state_machine(
            _process, DUMPS_DIR, dump_type=DUMP_TYPE, enable_dumps=ENABLE_MEMORY_DUMPS
        )
        print(f"[WOLFSSH_SETUP] ✓ State machine initialized")
        if ENABLE_MEMORY_DUMPS:
            print(f"[WOLFSSH_SETUP]   → Memory dumps: ENABLED ({DUMP_TYPE} mode)")
            print(f"[WOLFSSH_SETUP]   → Output: {DUMPS_DIR}")
        else:
            print(f"[WOLFSSH_SETUP]   → Memory dumps: DISABLED")
        if ENABLE_WATCHPOINTS:
            print(f"[WOLFSSH_SETUP]   → Watchpoints: ENABLED (timing CSVs)")
        else:
            print(f"[WOLFSSH_SETUP]   → Watchpoints: DISABLED")
    elif (ENABLE_MEMORY_DUMPS or ENABLE_WATCHPOINTS) and not STATE_MACHINE_AVAILABLE:
        print(f"[WOLFSSH_SETUP] ⚠️  Lifecycle tracking requested but state machine modules unavailable")
        print(f"[WOLFSSH_SETUP] Continuing without lifecycle tracking (missing ssh_state_machine)")
    else:
        print(f"[WOLFSSH_SETUP] State machine: Disabled (dumps and watchpoints both disabled)")
        print(f"[WOLFSSH_SETUP] Memory dumps: DISABLED")
        print(f"[WOLFSSH_SETUP] Watchpoints: DISABLED")

    # Set breakpoint on wc_SSH_KDF in libwolfssl
    bp = _target.BreakpointCreateByName("wc_SSH_KDF")

    if not bp.IsValid():
        print("[WOLFSSH_SETUP] ERROR: Failed to create breakpoint on wc_SSH_KDF")
        return

    # Attach callback BEFORE checking locations (works for pending breakpoints)
    bp.SetScriptCallbackFunction("wolfssh_client_callbacks.wc_ssh_kdf_entry")

    num_locs = bp.GetNumLocations()
    if num_locs == 0:
        print(f"[WOLFSSH_SETUP] ⚠️  Breakpoint pending (0 locations) - will resolve when library loads")
        print(f"[WOLFSSH_SETUP]   Callback attached: wolfssh_client_callbacks.wc_ssh_kdf_entry")
    else:
        print(f"[WOLFSSH_SETUP] ✓ Breakpoint set on wc_SSH_KDF ({num_locs} location(s))")
        for i in range(num_locs):
            loc = bp.GetLocationAtIndex(i)
            addr = loc.GetLoadAddress()
            print(f"[WOLFSSH_SETUP]   Location {i}: 0x{addr:x}")

    # ═══ NEW v3.0: Session close detection ═══
    print(f"[WOLFSSH_SETUP] Setting up session close detection...")

    close_bp = _target.BreakpointCreateByName("wolfSSH_shutdown")
    if not close_bp.IsValid() or close_bp.GetNumLocations() == 0:
        # Try alternative function
        close_bp = _target.BreakpointCreateByName("wolfSSH_free")

    if close_bp.IsValid() and close_bp.GetNumLocations() > 0:
        close_bp.SetScriptCallbackFunction("wolfssh_client_callbacks.session_close_callback")
        close_bp.SetAutoContinue(False)
        print(f"[WOLFSSH_SETUP] ✓ Session close breakpoint set (ID {close_bp.GetID()}, {close_bp.GetNumLocations()} locations)")
    else:
        print(f"[WOLFSSH_SETUP] ⚠️  Could not set session close breakpoint (non-critical)")

    # ═══ NEW v3.0: Function Entry Monitoring ═══
    if ENABLE_ENTRY_DUMPS:
        print(f"[WOLFSSH_SETUP] Setting up function entry monitoring (v3.1 with lifecycle dumps)...")

        # Lifecycle functions with before/after dumps (v3.1)
        entry_functions = {
            # Cleanup functions
            'wolfSSH_shutdown': 'wolfssh_shutdown_entry',
            'wolfSSH_free': 'wolfssh_free_entry',
            'wolfSSH_Cleanup': 'wolfssh_cleanup_entry',
            'wolfSSH_TriggerKeyExchange': 'wolfssh_trigger_kex_entry',
            # KEX protocol functions
            'DoKexInit': 'do_kex_init_entry',
            'DoNewKeys': 'do_new_keys_entry',
            'SendKexDhInit': 'send_kex_dh_init_entry',
            'DoKexDhInit': 'do_kex_dh_init_entry',
            'SendKexDhReply': 'send_kex_dh_reply_entry',
            'DoKexDhReply': 'do_kex_dh_reply_entry',
            'SendKexInit': 'send_kex_init_entry_v2'
        }

        # Rekey detection functions (optional, controlled by ENTRY_DUMP_FUNCTIONS)
        # These help identify which crypto functions are invoked during rekey operations
        rekey_detection_functions = {
            'SendKexInit': 'send_kex_init_entry',
            'GenerateKey': 'generate_key_entry',
            'wc_AesCbcEncryptWithKey': 'wc_aescbc_encrypt_entry',
            'wc_DhCheckPrivKey': 'wc_dh_checkprivkey_entry',
            'wc_Chacha_SetKey': 'wc_chacha_setkey_entry',
            'wc_DhGenerateParams': 'wc_dh_generateparams_entry',
            'wc_Chacha_encrypt_bytes': 'wc_chacha_encrypt_entry',
            'wc_ecc_shared_secret_ex': 'wc_ecc_shared_secret_ex_entry',
            'wc_ecc_shared_secret': 'wc_ecc_shared_secret_entry',
            'wc_ecc_gen_k': 'wc_ecc_gen_k_entry'
        }

        # Merge rekey detection functions into entry_functions
        entry_functions.update(rekey_detection_functions)

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
                bp.SetScriptCallbackFunction(f"wolfssh_client_callbacks.{callback_name}")
                bp.SetAutoContinue(False)
                entry_bp_count += 1

                num_locs = bp.GetNumLocations()
                if num_locs > 0:
                    print(f"[WOLFSSH_SETUP] ✓ Entry breakpoint: {func_name}() (ID {bp.GetID()}, {num_locs} locations)")
                else:
                    pending_bp_count += 1
                    print(f"[WOLFSSH_SETUP] ✓ Entry breakpoint: {func_name}() (ID {bp.GetID()}, pending - will resolve when library loads)")
            else:
                print(f"[WOLFSSH_SETUP] ⚠️  Entry breakpoint: {func_name}() invalid")

        if pending_bp_count > 0:
            print(f"[WOLFSSH_SETUP] Entry monitoring: {entry_bp_count}/{len(entry_functions)} functions set ({pending_bp_count} pending, will resolve when library loads)")
        else:
            print(f"[WOLFSSH_SETUP] Entry monitoring: {entry_bp_count}/{len(entry_functions)} functions found")
    else:
        print(f"[WOLFSSH_SETUP] Function entry monitoring: DISABLED (set LLDB_ENABLE_ENTRY_DUMPS=true to enable)")

    print(f"[WOLFSSH_SETUP] Keylog files:")
    print(f"[WOLFSSH_SETUP]   Standard: {LLDB_KEYLOG}")
    print(f"[WOLFSSH_SETUP]   Debug:    {LLDB_KEYLOG_DEBUG}")

# ═══════════════════════════════════════════════════════════════════════════
# SESSION CLOSE CALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def session_close_callback(frame, bp_loc, internal_dict):
    """
    Callback triggered when wolfSSH_shutdown() or wolfSSH_free() is called.
    Transitions to SESSION_CLOSED state (cleanup begins).

    This captures the moment when SSH session close is initiated, before
    keep-alive period and process exit.
    """
    global _state_machine

    func_name = frame.GetFunctionName()
    print(f"\n{'='*70}")
    print(f"[WOLFSSH_CLOSE] Session Close Detected: {func_name}()")
    print(f"{'='*70}")

    if _state_machine:
        _state_machine.transition(
            ssh_state_machine.SSHState.SESSION_CLOSED,
            metadata={
                'trigger': 'wolfssh_shutdown',
                'function': func_name
            }
        )
        print(f"[WOLFSSH_CLOSE] ✓ SESSION_CLOSED dump completed")
    else:
        print(f"[WOLFSSH_CLOSE] ⚠️  State machine not available")

    print(f"{'='*70}\n")
    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# FUNCTION ENTRY MONITORING (v3.0)
# ═══════════════════════════════════════════════════════════════════════════

def generic_function_entry_callback(frame, bp_loc, internal_dict, func_name, event_type):
    """
    Generic entry callback for any wolfSSH function.
    Takes memory dump at function entry and logs the event.

    Args:
        frame: LLDB stack frame
        bp_loc: Breakpoint location
        internal_dict: LLDB internal dictionary
        func_name: Function name (e.g., "wolfSSH_shutdown")
        event_type: Event type for dump label (e.g., "shutdown")
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
            print(f"[FUNCTION_EXIT] ERROR: Unknown architecture {_arch}")
            return False

        # Retrieve stored metadata
        if pc not in _function_exit_state:
            print(f"[FUNCTION_EXIT] WARNING: No stored state for PC=0x{pc:x}")
            print(f"[FUNCTION_EXIT] Available keys: {[hex(k) for k in _function_exit_state.keys()]}")
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

    This is the two-breakpoint pattern: entry callback sets exit breakpoint,
    exit callback takes the "after" dump.

    Args:
        frame: LLDB stack frame
        bp_loc: Breakpoint location
        internal_dict: LLDB internal dictionary
        func_name: Function name (e.g., "DoKexInit")
        event_type: Event type for dump label (e.g., "kex_init")
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
                    'phase': 'entry',
                    'arguments': args_info
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
        if _arch == 'aarch64':
            ret_addr = get_return_address_aarch64(frame)
        elif _arch == 'x86_64':
            thread = frame.GetThread()
            process = thread.GetProcess()
            ret_addr = get_return_address_x86_64(frame, process)
        else:
            print(f"[{func_name}] ERROR: Unknown architecture {_arch}")
            ret_addr = None

        if ret_addr and ret_addr != 0:
            # Store metadata for exit callback
            _function_exit_state[ret_addr] = {
                'func_name': func_name,
                'event_type': event_type
            }
            print(f"[{func_name}] Stored exit state for ret_addr=0x{ret_addr:x}")

            # Create exit breakpoint
            exit_bp = _target.BreakpointCreateByAddress(ret_addr)
            if exit_bp.IsValid():
                exit_bp.SetOneShot(True)
                exit_bp.SetScriptCallbackFunction("wolfssh_client_callbacks.generic_function_exit_callback")
                print(f"[{func_name}] ✓ Exit breakpoint set at 0x{ret_addr:x}")
            else:
                print(f"[{func_name}] ERROR: Failed to create exit breakpoint at 0x{ret_addr:x}")
        else:
            print(f"[{func_name}] ERROR: Invalid return address, cannot set exit breakpoint")

        print(f"[{func_name}] Entry callback complete")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[{func_name}] ERROR: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# LIFECYCLE FUNCTION WRAPPERS (with before/after dumps)
# ═══════════════════════════════════════════════════════════════════════════

# Cleanup functions (wolfSSH_shutdown, wolfSSH_free, wolfSSH_Cleanup)
def wolfssh_shutdown_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for wolfSSH_shutdown()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="wolfSSH_shutdown",
        event_type="shutdown"
    )

def wolfssh_free_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for wolfSSH_free()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="wolfSSH_free",
        event_type="free"
    )

def wolfssh_cleanup_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for wolfSSH_Cleanup()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="wolfSSH_Cleanup",
        event_type="cleanup"
    )

def wolfssh_trigger_kex_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for wolfSSH_TriggerKeyExchange()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="wolfSSH_TriggerKeyExchange",
        event_type="trigger_kex"
    )

# KEX protocol functions (DoKexInit, DoNewKeys, SendKexInit, etc.)
def do_kex_init_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for DoKexInit()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="DoKexInit",
        event_type="kex_init"
    )

def do_new_keys_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for DoNewKeys()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="DoNewKeys",
        event_type="kex_newkeys"
    )

def send_kex_dh_init_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for SendKexDhInit()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="SendKexDhInit",
        event_type="kex_dh_init_send"
    )

def do_kex_dh_init_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for DoKexDhInit()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="DoKexDhInit",
        event_type="kex_dh_init_do"
    )

def send_kex_dh_reply_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for SendKexDhReply()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="SendKexDhReply",
        event_type="kex_dh_reply_send"
    )

def do_kex_dh_reply_entry(frame, bp_loc, internal_dict):
    """Entry+exit callback for DoKexDhReply()"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="DoKexDhReply",
        event_type="kex_dh_reply_do"
    )

def send_kex_init_entry_v2(frame, bp_loc, internal_dict):
    """Entry+exit callback for SendKexInit() - v2 with dumps"""
    return generic_function_entry_exit_callback(
        frame, bp_loc, internal_dict,
        func_name="SendKexInit",
        event_type="kex_init_send"
    )

# ═══════════════════════════════════════════════════════════════════════════
# REKEY DETECTION CALLBACKS
# ═══════════════════════════════════════════════════════════════════════════

def send_kex_init_entry(frame, bp_loc, internal_dict):
    """Entry callback for SendKexInit()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="SendKexInit",
        event_type="REKEY_SEND_KEX_INIT"
    )

def generate_key_entry(frame, bp_loc, internal_dict):
    """Entry callback for GenerateKey()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="GenerateKey",
        event_type="REKEY_GENERATE_KEY"
    )

def wc_aescbc_encrypt_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_AesCbcEncryptWithKey()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_AesCbcEncryptWithKey",
        event_type="REKEY_AES_CBC_ENCRYPT"
    )

def wc_dh_checkprivkey_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_DhCheckPrivKey()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_DhCheckPrivKey",
        event_type="REKEY_DH_CHECK_PRIVKEY"
    )

def wc_chacha_setkey_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_Chacha_SetKey()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_Chacha_SetKey",
        event_type="REKEY_CHACHA_SETKEY"
    )

def wc_dh_generateparams_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_DhGenerateParams()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_DhGenerateParams",
        event_type="REKEY_DH_GENERATE_PARAMS"
    )

def wc_chacha_encrypt_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_Chacha_encrypt_bytes()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_Chacha_encrypt_bytes",
        event_type="REKEY_CHACHA_ENCRYPT"
    )

def wc_ecc_shared_secret_ex_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_ecc_shared_secret_ex()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_ecc_shared_secret_ex",
        event_type="REKEY_ECC_SHARED_SECRET_EX"
    )

def wc_ecc_shared_secret_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_ecc_shared_secret()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_ecc_shared_secret",
        event_type="REKEY_ECC_SHARED_SECRET"
    )

def wc_ecc_gen_k_entry(frame, bp_loc, internal_dict):
    """Entry callback for wc_ecc_gen_k()"""
    return generic_function_entry_callback(
        frame, bp_loc, internal_dict,
        func_name="wc_ecc_gen_k",
        event_type="REKEY_ECC_GEN_K"
    )

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE LOOP
# ═══════════════════════════════════════════════════════════════════════════

def wolfssh_auto_continue(debugger, command, result, internal_dict):
    """
    Auto-continue command with keep-alive loop v2.0

    Continuously checks process state and resumes if stopped.
    v2.0: Adds SESSION_CLOSED and CLEANUP state transitions on exit.

    LIFECYCLE EVENT COVERAGE (BASE mode):
    - Event 1: HANDSHAKE (KEX_COMPLETE) ✓ - Captured when 4th KDF call completes
    - Event 2: TRAFFIC (ACTIVE) ✓ - Captured immediately after KEX_COMPLETE
    - Event 3: SESSION_CLOSE (SESSION_CLOSED) ⚠️  - Currently only on process exit
    - Event 4: CLEANUP (CLEANUP) ⚠️  - Currently only on process exit

    NOTE: SESSION_CLOSED and CLEANUP currently trigger on process exit rather than during
    normal SSH session lifecycle. For proper lifecycle tracking, we need to add breakpoints
    on wolfSSH_shutdown() or similar session termination functions. This is acceptable for
    short-lived client connections but may miss early cleanup events in long-running sessions.
    """
    global _debugger, _target, _state_machine, _kdf_counter

    if _target is None:
        _target = debugger.GetSelectedTarget()

    process = _target.GetProcess()
    if not process.IsValid():
        print("[WOLFSSH_AUTO] ERROR: No valid process")
        return

    # Initial continue
    process.Continue()
    print("[WOLFSSH_AUTO] Process running - entering keep-alive loop v3.0")
    print("[WOLFSSH_AUTO] Monitoring wc_SSH_KDF() calls...")
    print("[WOLFSSH_AUTO] Monitoring for /tmp/lldb_dump_pre_exit trigger file")

    # Keep-alive loop: continuously check and resume
    stop_count = 0
    max_iterations = 1000  # Safety limit to prevent infinite loops
    iteration = 0
    pre_session_close_triggered = False  # Track if we've dumped pre-exit state

    while process.GetState() != lldb.eStateExited and iteration < max_iterations:
        iteration += 1
        current_state = process.GetState()

        # ═══ File-based trigger for PRE_SESSION_CLOSE ═══
        if not pre_session_close_triggered and os.path.exists('/tmp/lldb_dump_pre_exit'):
            print(f"\n[WOLFSSH_AUTO] ⚡ Detected pre-exit trigger file at iteration {iteration}!")

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
                print(f"[WOLFSSH_AUTO] ✓ PRE_SESSION_CLOSE dump completed")

            # Clean up trigger file
            try:
                os.remove('/tmp/lldb_dump_pre_exit')
                print(f"[WOLFSSH_AUTO] ✓ Trigger file removed")
            except Exception as e:
                print(f"[WOLFSSH_AUTO] ⚠️  Failed to remove trigger file: {e}")

            pre_session_close_triggered = True

        if current_state == lldb.eStateStopped:
            stop_count += 1
            # Process stopped (breakpoint hit)
            process.Continue()
            if stop_count % 100 == 0:  # Log every 100 stops to avoid spam
                print(f"[WOLFSSH_AUTO] Process STOPPED (#{stop_count}), continuing...")

        time.sleep(0.1)  # Brief sleep to avoid busy-waiting

    # Check if we hit the iteration limit
    if iteration >= max_iterations:
        print(f"\n[WOLFSSH_AUTO] ⚠️  WARNING: Hit maximum iteration limit ({max_iterations})")
        print(f"[WOLFSSH_AUTO] Process state: {current_state}")
        print(f"[WOLFSSH_AUTO] Total stops: {stop_count}")
        print(f"[WOLFSSH_AUTO] This suggests the process is stuck in a stop-continue loop")
        print(f"[WOLFSSH_AUTO] Forcing exit...")
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
                'total_kdf_calls': _kdf_counter
            }
        )

        # Print state machine summary
        _state_machine.summary()

    print(f"\n[WOLFSSH_AUTO] Process exited (total stops: {stop_count})")
    print(f"[WOLFSSH_AUTO] wc_SSH_KDF calls: {_kdf_counter}")
    print(f"[WOLFSSH_AUTO] Keylog: {LLDB_KEYLOG}")
    print(f"[WOLFSSH_AUTO] Debug keylog: {LLDB_KEYLOG_DEBUG}")

    # Exit LLDB to allow container/entrypoint to exit cleanly
    print(f"[WOLFSSH_AUTO] Exiting LLDB...")
    _debugger.HandleCommand("quit")

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
    global ENABLE_WATCHPOINTS, _watchpoints, _kdf_counter

    print(f"\n[WATCHPOINT_STATUS] === Watchpoint Status ===")
    print(f"[WATCHPOINT_STATUS] Global state: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED'}")
    print(f"[WATCHPOINT_STATUS] Active watchpoints: {len(_watchpoints)}")
    print(f"[WATCHPOINT_STATUS] KDF counter: {_kdf_counter}")

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
    """Called automatically when script is imported by LLDB"""
    debugger.HandleCommand(
        'command script add -f wolfssh_client_callbacks.wolfssh_setup_monitoring wolfssh_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f wolfssh_client_callbacks.wolfssh_auto_continue wolfssh_auto_continue'
    )
    debugger.HandleCommand(
        'command script add -f wolfssh_client_callbacks.watchpoints_toggle watchpoints_toggle'
    )
    debugger.HandleCommand(
        'command script add -f wolfssh_client_callbacks.watchpoints_status watchpoints_status'
    )
    debugger.HandleCommand(
        'command script add -f wolfssh_client_callbacks.watchpoints_list watchpoints_list'
    )
    print("[WOLFSSH_CALLBACKS] Commands registered:")
    print("[WOLFSSH_CALLBACKS]   - wolfssh_setup_monitoring")
    print("[WOLFSSH_CALLBACKS]   - wolfssh_auto_continue")
    print("[WOLFSSH_CALLBACKS]   - watchpoints_toggle, watchpoints_status, watchpoints_list")
