#!/usr/bin/env python3
"""
Dropbear LLDB callbacks V2 - CORRECTED fork pattern understanding

Updated: 2025-10-22 with corrected Dropbear fork behavior based on manual testing

CORRECTED Dropbear Fork Behavior (verified via LLDB attach test):
────────────────────────────────────────────────────────────────────
Fork #1: Parent (PID 1) → Connection handler (e.g., PID 78)
  - Connection handler process handles SSH protocol layer
  - KEX (key exchange) happens in this process
  - Cryptographic keys are derived here

Fork #2: Connection handler (PID 78) → Session child
  ├─ Connection handler (PID 78): **STAYS ALIVE**
  │  - Manages SSH protocol (encryption/decryption)
  │  - Waits in __select() for network I/O
  │  - Handles rekeying if triggered
  │  - Persists for entire SSH session lifetime
  │
  └─ Session child: Runs user shell/command
     - Executes user's command (hostname, bash, etc.)
     - Communicates with connection handler via pipes

Previous (INCORRECT) assumption: Connection handler exits after fork #2
Actual behavior: Connection handler stays alive, managing protocol throughout session

Fork Monitoring Strategy:
- Stay attached to connection handler (PID 78) after fork #2
- This allows monitoring: rekey events, key cleanup, session termination
- Session remains functional - no detach needed

Key structures (from Dropbear source):
- Global: ses (struct sshsession)
- ses.newkeys->trans.mackey[MAX_MAC_LEN] - Client->Server MAC
- ses.newkeys->recv.mackey[MAX_MAC_LEN] - Server->Client MAC
- ses.newkeys->trans.cipher_state - ChaCha20-Poly1305 state
"""

import lldb
import json
import time
import os
import struct



# Global state
_target = None  # LLDB target for setting return breakpoints
_debugger = None  # LLDB debugger for watchpoint commands

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


def set_debugger(debugger):
    """Set LLDB debugger for watchpoint management"""
    global _debugger
    _debugger = debugger

# Configuration
KEYLOG_PATH = os.environ.get('LLDB_KEYLOG', '/data/keylogs/ssh_keylog_dropbear.log')
_wp_env = os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')
ENABLE_WATCHPOINTS = _wp_env.lower() in ('true', '1', 'yes')
_md_env = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'false')
ENABLE_MEMORY_DUMPS = _md_env.lower() in ('true', '1', 'yes')
_ac_env = os.environ.get('LLDB_AUTO_CONTINUE', 'false')
ENABLE_AUTO_CONTINUE = _ac_env.lower() in ('true', '1', 'yes')
_debug_env = os.environ.get('LLDB_DEBUG_OUTPUT', 'true')
ENABLE_DEBUG_OUTPUT = _debug_env.lower() in ('true', '1', 'yes')

# V2: Fork handling strategy
_fork_strategy_env = os.environ.get('LLDB_FORK_STRATEGY', 'follow_connection')
FORK_STRATEGY = _fork_strategy_env
# Options:
# - 'follow_connection': Stay with connection handler after fork #2 (DEFAULT, RECOMMENDED)
#                        Allows monitoring rekey, session lifetime, key cleanup
# - 'follow_session':    Let LLDB follow session child (not useful for key monitoring)
# - 'detach_on_fork2':   Detach after fork #2 (legacy r18 behavior, for compatibility)

# Log configuration at module load time
print(f"[CONFIG] LLDB_ENABLE_WATCHPOINTS env var: '{_wp_env}'")
print(f"[CONFIG] Watchpoints enabled: {ENABLE_WATCHPOINTS}")
print(f"[CONFIG] LLDB_ENABLE_MEMORY_DUMPS env var: '{_md_env}'")
print(f"[CONFIG] Memory dumps enabled: {ENABLE_MEMORY_DUMPS}")
print(f"[CONFIG] LLDB_AUTO_CONTINUE env var: '{_ac_env}'")
print(f"[CONFIG] Auto-continue enabled: {ENABLE_AUTO_CONTINUE}")
print(f"[CONFIG] LLDB_DEBUG_OUTPUT env var: '{_debug_env}'")
print(f"[CONFIG] Debug output enabled: {ENABLE_DEBUG_OUTPUT}")
print(f"[CONFIG] LLDB_FORK_STRATEGY env var: '{_fork_strategy_env}'")
print(f"[CONFIG] Fork strategy: {FORK_STRATEGY}")

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
__version__ = "dropbear-cb-v2 2025.10.22-fork-mode-fix-v2"
_load_time = __import__("time").time()
_kex_counter = 0  # Track number of KEX operations (0 = first/init, >0 = rekey)
_fork_count = 0   # Track number of forks (Dropbear does double-fork: 0=none, 1=connection, 2=session)
_fork_mode_switched = False  # V2_FIX: Track if we've switched to parent mode after following fork #1 child

# V2: Process tracking for corrected fork understanding
_connection_handler_pid = None  # PID of connection handler (stays alive throughout session)
_session_child_pid = None       # PID of session child (runs user command)

def _verify_expected_process(process, callback_name):
    """V2: Verify callback is executing in expected process (connection handler, not session child)

    Returns: True if in expected process, False otherwise
    """
    global _connection_handler_pid, _fork_count

    current_pid = process.GetProcessID()

    # Before fork #1, we don't have a connection handler yet
    if _fork_count == 0:
        return True

    # After fork #1, we should be in connection handler
    if _connection_handler_pid is not None and current_pid != _connection_handler_pid:
        print(f"\n{'='*72}")
        print(f"[PID_WARNING] {callback_name} firing in unexpected process!")
        print(f"[PID_WARNING] Expected: {_connection_handler_pid} (connection handler)")
        print(f"[PID_WARNING] Actual: {current_pid}")
        print(f"[PID_WARNING] This may indicate LLDB followed session child after fork #2")
        print(f"{'='*72}\n")
        return False

    # Callback is in expected process
    if ENABLE_DEBUG_OUTPUT and _connection_handler_pid is not None:
        print(f"[PID_VERIFY] {callback_name} ✓ in connection handler (PID {current_pid})")

    return True

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

def _verify_process_state(process, check_name="process_check"):
    """V2: Verify and log process state for debugging fork behavior"""
    if not ENABLE_DEBUG_OUTPUT:
        return

    pid = process.GetProcessID()
    state = process.GetState()
    state_str = lldb.SBDebugger.StateAsCString(state)

    print(f"[VERIFY_{check_name.upper()}] PID: {pid}")
    print(f"[VERIFY_{check_name.upper()}] State: {state_str}")
    print(f"[VERIFY_{check_name.upper()}] Valid: {process.IsValid()}")
    print(f"[VERIFY_{check_name.upper()}] Num threads: {process.GetNumThreads()}")

    # Try to read /proc/PID/status for additional info
    try:
        with open(f"/proc/{pid}/status", 'r') as f:
            for line in f:
                if line.startswith(('State:', 'PPid:', 'TracerPid:')):
                    print(f"[VERIFY_{check_name.upper()}] {line.strip()}")
    except FileNotFoundError:
        print(f"[VERIFY_{check_name.upper()}] /proc/{pid}/status not found (process may have exited)")
    except Exception as e:
        print(f"[VERIFY_{check_name.upper()}] Could not read /proc/{pid}/status: {e}")

    return state_str

def get_process_type(process):
    """
    Determine which Dropbear process we're in: parent, fork1 (connection), or fork2 (session)

    Returns:
        str: "parent", "fork1_connection", or "fork2_session"

    Dropbear fork hierarchy:
    - Parent (fork_count=0): Main dropbear process waiting for connections
    - Fork #1 (fork_count=1): Connection handler - handles KEX and session protocol
    - Fork #2 (fork_count>=2): Session child - runs user command
    """
    global _fork_count, _connection_handler_pid

    current_pid = process.GetProcessID()

    # Before any forks
    if _fork_count == 0:
        return "parent"

    # After fork #1, we're in connection handler
    if _fork_count == 1:
        if _connection_handler_pid is None:
            _connection_handler_pid = current_pid
        return "fork1_connection"

    # After fork #2, check if we're in connection handler or session child
    if _fork_count >= 2:
        if _connection_handler_pid and current_pid == _connection_handler_pid:
            return "fork1_connection"  # Still in connection handler (it stays alive)
        else:
            return "fork2_session"  # In session child

    return "unknown"

def _set_watchpoint(key_name, address, key_data, key_id):
    """Set hardware watchpoint on a key using the proven IPsec pattern

    Pattern:
    1. Generate callback as f-string with full function definition
    2. Inject into Python namespace with debugger.HandleCommand("script ...")
    3. Attach to watchpoint with debugger.HandleCommand("watchpoint command add -F ...")

    The -F flag means "function name" - LLDB automatically passes frame, bp_loc, internal_dict
    """
    global _watchpoints, _target, _debugger, _timing_logger, _fork_count, _process

    # Get current process type
    if not _process:
        print(f"[WATCHPOINT] ERROR: No process object available")
        return

    process_type = get_process_type(_process)
    current_pid = _process.GetProcessID()

    print(f"[WATCHPOINT] Attempting to set {key_name}")
    print(f"[WATCHPOINT] Process type: {process_type}")
    print(f"[WATCHPOINT] Current PID: {current_pid}")
    print(f"[WATCHPOINT] Fork count: {_fork_count}")

    # Skip if already watching this key
    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    if not _debugger or not _target:
        print(f"[WATCHPOINT] ERROR: No debugger/target for {key_name}")
        print(f"[WATCHPOINT] _debugger is None: {_debugger is None}")
        print(f"[WATCHPOINT] _target is None: {_target is None}")
        return

    # POST-FORK STRATEGY: Only set watchpoints when we're IN fork1 (connection handler)
    # NOT when we're in parent preparing for fork
    # This tests if setting watchpoints POST-fork avoids trace mode issue
    if process_type != "fork1_connection":
        print(f"[WATCHPOINT_SKIP] Skipping {key_name} - process type is '{process_type}', not 'fork1_connection'")
        print(f"[WATCHPOINT_SKIP] Watchpoints only set POST-fork in fork #1 (connection handler)")
        print(f"[WATCHPOINT_SKIP] This tests if POST-fork watchpoints avoid trace mode")
        return

    try:
        print(f"[WATCHPOINT] Attempting to set watchpoint on {key_name} at 0x{address:x}")
        print(f"[WATCHPOINT] Key data length: {len(key_data)} bytes")
        print(f"[WATCHPOINT] Key preview: {_hex_dump(key_data, 16)}")

        error = lldb.SBError()

        # Set write watchpoint on 1 byte (sufficient to detect overwrites)
        # Reduced from 4 bytes to potentially avoid trace mode issues with fork
        print(f"[WATCHPOINT] Calling WatchAddress(0x{address:x}, 1, False, True)")
        watchpoint = _target.WatchAddress(address, 1, False, True, error)

        print(f"[WATCHPOINT] WatchAddress returned, checking status...")
        print(f"[WATCHPOINT] error.Success(): {error.Success()}")
        print(f"[WATCHPOINT] error message: {error.GetCString()}")
        print(f"[WATCHPOINT] watchpoint.IsValid(): {watchpoint.IsValid() if watchpoint else 'watchpoint is None'}")

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] FAILED to set on {key_name}: {error.GetCString()}")
            return

        wp_id = watchpoint.GetID()
        print(f"[WATCHPOINT] Successfully created watchpoint ID {wp_id} for {key_name}")

        # EXPERIMENT: Test immediate enable/disable to see if this prevents trace mode
        print(f"[WATCHPOINT_TEST] Testing immediate disable/enable cycle on wp {wp_id}")
        watchpoint.SetEnabled(False)
        print(f"[WATCHPOINT_TEST] Disabled wp {wp_id}")
        time.sleep(0.05)  # Brief pause
        watchpoint.SetEnabled(True)
        print(f"[WATCHPOINT_TEST] Re-enabled wp {wp_id}")

        # NOTE: SBWatchpoint doesn't support SetAutoContinue() unlike SBBreakpoint
        # Watchpoints will stop execution when they fire - this is an LLDB limitation
        # To disable watchpoints, set environment: LLDB_ENABLE_WATCHPOINTS=false

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
    # import time
    # import lldb
    # timestamp = time.time()
    from datetime import datetime
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_key_name}' at 0x{fixed_addr:x} on Timestamp {{hit_time}} ==!!!==")

    # Log the overwrite event
    #print(f"[KEY_OVERWRITE] {fixed_key_name} overwritten at {{timestamp}}")
    #print(f"[KEY_OVERWRITE] Address: 0x{fixed_addr:x}")
    #print(f"[KEY_OVERWRITE] Original key: {fixed_key_hex[:64]}...")

    # CRITICAL: Clear single-step/trace mode and continue
    # Watchpoints can leave thread in trace mode, causing stops at every instruction
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        error = lldb.SBError()

        new_data = process.ReadMemory({fixed_addr}, 16, error)
        if error.Success():
            data_hex = ' '.join(f'{{b:02x}}' for b in new_data[:16])
            print(f"[WATCHPOINT] New value: {{data_hex}}")

            from ssh_monitor import log_timing
            if log_timing:
                log_timing("{fixed_key_id}", "overwritten_data_read", time.time())

        print(f"[WATCHPOINT] Process continued after {{frame.GetFunctionName() or 'unknown'}}")
    except Exception as e:
        print(f"[WATCHPOINT_ERROR] Failed to continue: {{e}}")

    # CRITICAL: Delete the watchpoint after first hit (one-shot watchpoint)
    # This prevents the process from stopping repeatedly on subsequent memory writes
    try:
        target = process.GetTarget()
        target.DeleteWatchpoint({wp_id})
        print(f"[WATCHPOINT] Deleted watchpoint {wp_id} after first hit (one-shot)")
    except Exception as e:
        print(f"[WATCHPOINT_ERROR] Failed to delete watchpoint: {{e}}")

    import dropbear_callbacks_v2
    dropbear_callbacks_v2._watchpoints.pop("{fixed_key_name}", None)

    # Return False to tell LLDB not to stop again at this location
    return False
'''

        try:
            _debugger.HandleCommand(f"script {callback_code}")
        except Exception as e:
            print(f"[WATCHPOINT] ERROR injecting callback code via _debugger: {e}")
            pass
        
        # Inject callback into module namespace first
        try:
            exec(callback_code, globals())
            print("[WATCHPOINT] Callback function injected via exec()")
        except Exception as e:
            print(f"[WATCHPOINT] ERROR injecting callback code via exec(): {e}")
            pass

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
                watchpoint.SetAutoContinue(True)
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

    # Use global configuration flag (no local override)
    global ENABLE_WATCHPOINTS

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

        # Try to set watchpoint on new non-zero key (use global config)
        if ENABLE_WATCHPOINTS and new_trans != '00' * 32:
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

        # Try to set watchpoint on new non-zero key (use global config)
        if ENABLE_WATCHPOINTS and new_recv != '00' * 32:
            log_event("KEY_RECHECK", "recv_mackey now has non-zero value, attempting watchpoint")
            _set_watchpoint("recv_mackey_post_switch", recv_mackey_addr, recv_mackey_data, key_id)
    else:
        log_event("KEY_RECHECK_UNCHANGED", f"recv_mackey unchanged (still {new_recv[:32]}...)")

def fork_callback(frame, bp_loc, internal_dict):
    """V2: Callback for fork() - CORRECTED Dropbear fork behavior

    VERIFIED Dropbear fork pattern (via manual LLDB testing):
    ──────────────────────────────────────────────────────────────
    Fork #1: Parent (PID 1) → Connection handler (e.g., PID 78)
      - Connection handler manages SSH protocol layer
      - KEX happens in this process
      - Keys extracted here

    Fork #2: Connection handler (PID 78) → Session child
      - Connection handler STAYS ALIVE (waits in __select)
      - Session child runs user command
      - BOTH processes continue running

    Fork Strategy (configurable via LLDB_FORK_STRATEGY):
    - 'follow_connection': Stay attached to connection handler (DEFAULT)
      → Allows monitoring: rekey, key cleanup, session termination
      → Connection handler manages SSH protocol throughout session

    - 'follow_session': Let LLDB follow session child
      → Not useful for key monitoring (SSH protocol stays in handler)

    - 'detach_on_fork2': Detach after fork #2 (legacy compatibility)
      → Loses ability to monitor rekey and cleanup
    """
    global _fork_count, _connection_handler_pid, FORK_STRATEGY, ENABLE_DEBUG_OUTPUT

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()
    tid = thread.GetThreadID()

    # Detect process type BEFORE incrementing fork count
    process_type_before = get_process_type(process)

    _fork_count += 1

    # Detect process type AFTER incrementing fork count (for next callback)
    process_type_after = get_process_type(process)

    print("\n" + "="*72)
    print(f"[FORK_V2] Fork #{_fork_count} detected in PID {pid}")
    print(f"[FORK_V2] Process type before fork: {process_type_before}")
    print(f"[FORK_V2] Process type after fork count update: {process_type_after}")

    if ENABLE_DEBUG_OUTPUT:
        print(f"[FORK_V2_DEBUG] Thread ID: {tid}")
        print(f"[FORK_V2_DEBUG] Fork strategy: {FORK_STRATEGY}")

        # Show stack trace
        print(f"[FORK_V2_DEBUG] Call stack:")
        for i in range(min(3, thread.GetNumFrames())):
            frame_i = thread.GetFrameAtIndex(i)
            func_name = frame_i.GetFunctionName() or "unknown"
            pc = frame_i.GetPC()
            print(f"[FORK_V2_DEBUG]   #{i}: {func_name} @ 0x{pc:x}")

        # Verify process state before fork
        _verify_process_state(process, f"fork{_fork_count}_before")

    if _fork_count == 1:
        # ═══════════════════════════════════════════════════════════
        # FORK #1: Creates connection handler
        # ═══════════════════════════════════════════════════════════
        print(f"[FORK_V2] FIRST FORK: Parent (PID {pid}) → Connection handler")
        print(f"[FORK_V2] LLDB follows child (connection handler)")
        print(f"[FORK_V2] KEX will happen in child process")

        # V2_FIX: DO NOT switch fork-mode here!
        # Switching during fork callback affects the CURRENT fork, not the next one
        # The mode switch must happen AFTER LLDB has followed the child
        # We'll switch mode in kex_init_callback after confirming we're in child
        print(f"[FORK_V2] ℹ️  Fork-mode will be switched to 'parent' after following child")
        print(f"[FORK_V2] → This ensures fork #2 keeps us with connection handler")
        print("="*72 + "\n")

        # Track the connection handler PID (will be updated when LLDB follows child)
        _connection_handler_pid = pid

    elif _fork_count == 2:
        # ═══════════════════════════════════════════════════════════
        # FORK #2: Connection handler creates session child
        # ═══════════════════════════════════════════════════════════
        print(f"[FORK_V2] SECOND FORK: Connection handler (PID {pid}) → Session child")
        print(f"[FORK_V2] 🔑 Keys already extracted ✓")
        print(f"[FORK_V2] ⚡ Connection handler (PID {pid}) STAYS ALIVE")
        print(f"[FORK_V2] 📋 Strategy: {FORK_STRATEGY}")
        print("="*72)

        if FORK_STRATEGY == 'follow_connection':
            # ═══════════════════════════════════════════════════════════
            # DEFAULT STRATEGY: Stay with connection handler
            # ═══════════════════════════════════════════════════════════
            print(f"[FORK_V2] ✓ Staying attached to connection handler (PID {pid})")
            print(f"[FORK_V2] This process manages SSH protocol layer:")
            print(f"[FORK_V2]   - Encryption/decryption of SSH packets")
            print(f"[FORK_V2]   - Rekey negotiation (if triggered)")
            print(f"[FORK_V2]   - Session key lifecycle")
            print(f"[FORK_V2]   - Connection termination and cleanup")
            print(f"[FORK_V2] Session child (user command) runs independently")
            print("="*72 + "\n")

            # Don't detach - this is the correct process to monitor!
            # Connection handler will continue running, managing SSH protocol
            # We can monitor rekey events, key cleanup, etc.

        elif FORK_STRATEGY == 'follow_session':
            # ═══════════════════════════════════════════════════════════
            # ALTERNATIVE: Follow session child (not recommended)
            # ═══════════════════════════════════════════════════════════
            print(f"[FORK_V2] ⚠ Following session child (not recommended)")
            print(f"[FORK_V2] LLDB's follow-fork-mode will handle this automatically")
            print(f"[FORK_V2] Note: SSH protocol monitoring will be lost!")
            print("="*72 + "\n")

            # LLDB's follow-fork-mode setting handles this automatically
            # No explicit action needed

        elif FORK_STRATEGY == 'detach_on_fork2':
            # ═══════════════════════════════════════════════════════════
            # LEGACY: Detach (for compatibility with r18 behavior)
            # ═══════════════════════════════════════════════════════════
            print(f"[FORK_V2] 🔓 DETACHING from PID {pid} (legacy mode)")
            print(f"[FORK_V2] Connection handler will run independently")
            print(f"[FORK_V2] Cannot monitor: rekey, cleanup, termination")
            print("="*72 + "\n")

            try:
                error = process.Detach()

                if error and hasattr(error, 'Success'):
                    if error.Success():
                        print(f"[FORK_V2] ✓ Successfully detached from PID {pid}")
                    else:
                        print(f"[FORK_V2] ✗ Detach failed: {error.GetCString()}")
                else:
                    print(f"[FORK_V2] ✓ Detach called (void return)")

            except Exception as e:
                print(f"[FORK_V2] ✗ Exception during detach: {e}")
                if ENABLE_DEBUG_OUTPUT:
                    import traceback
                    traceback.print_exc()

        if ENABLE_DEBUG_OUTPUT:
            # Verify state after fork handling
            import time
            time.sleep(0.1)  # Brief pause to let fork complete
            print(f"\n[FORK_V2_DEBUG] Post-fork verification:")
            _verify_process_state(process, f"fork{_fork_count}_after")

    else:
        # ═══════════════════════════════════════════════════════════
        # UNEXPECTED: More than 2 forks
        # ═══════════════════════════════════════════════════════════
        print(f"[FORK_V2] ⚠ WARNING: Unexpected fork #{_fork_count} in PID {pid}")
        print(f"[FORK_V2] Dropbear typically forks exactly twice")
        print("="*72 + "\n")

    # Return False to let LLDB continue process
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

    # V2: Verify we're in the expected process
    if not _verify_expected_process(process, "gen_new_keys_entry"):
        log_event("PID_ERROR", "gen_new_keys_entry fired in wrong process - skipping")
        return False

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
    if ENABLE_MEMORY_DUMPS:
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
            bp.SetScriptCallbackFunction("dropbear_callbacks_v2.gen_new_keys_exit")
    elif 'aarch64' in arch or 'arm64' in arch:
        lr = frame.FindRegister("lr")
        if lr:
            ret_addr = lr.GetValueAsUnsigned()
            bp = target.BreakpointCreateByAddress(ret_addr)
            bp.SetOneShot(True)
            bp.SetScriptCallbackFunction("dropbear_callbacks_v2.gen_new_keys_exit")

    return False

def gen_new_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys() - NOW WITH KEY EXTRACTION"""
    global next_key_id, _kex_counter, ENABLE_DEBUG_OUTPUT
    timestamp = time.time()

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    # V2: Verify we're in the expected process
    if not _verify_expected_process(process, "gen_new_keys_exit"):
        log_event("PID_ERROR", "gen_new_keys_exit fired in wrong process - skipping")
        return False

    # Detect if this is a rekey
    is_rekey = (_kex_counter > 0)
    event_type = "REKEY_EXIT" if is_rekey else "KEX_EXIT"

    key_id = f"dropbear_key_{next_key_id}"
    next_key_id += 1

    if ENABLE_DEBUG_OUTPUT:
        print(f"\n[GEN_KEYS_DEBUG] Exited gen_new_keys() in PID {pid}")
        print(f"[GEN_KEYS_DEBUG] Key ID: {key_id}")
        print(f"[GEN_KEYS_DEBUG] Is rekey: {is_rekey}")
        print(f"[GEN_KEYS_DEBUG] KEX counter before increment: {_kex_counter}")

    # Increment KEX counter AFTER using it for detection
    _kex_counter += 1

    if ENABLE_DEBUG_OUTPUT:
        print(f"[GEN_KEYS_DEBUG] KEX counter after increment: {_kex_counter}")
        print(f"[GEN_KEYS_DEBUG] Fork count: {_fork_count}")

    log_event(event_type, f"Key {key_id} {'rekeyed' if is_rekey else 'generated'} (KEX #{_kex_counter})", {
        'timestamp': timestamp,
        'is_rekey': is_rekey,
        'kex_number': _kex_counter
    })
    log_timing(key_id, "rekeyed" if is_rekey else "generated", timestamp)

    # Dump full memory after key generation
    dump_type = "rekey_exit" if is_rekey else "kex_exit"
    if ENABLE_MEMORY_DUMPS:
        log_event("DUMP_START", f"Dumping memory after {'rekey' if is_rekey else 'key generation'} for {key_id}")
        if ENABLE_DEBUG_OUTPUT:
            print(f"[GEN_KEYS_DEBUG] Starting memory dump: {dump_type}")
        dump_full_memory(process, dump_type, key_id)

    # Initialize key tracking
    active_keys[key_id] = {
        'generated_at': timestamp,
        'status': 'active'
    }

    if ENABLE_DEBUG_OUTPUT:
        print(f"[GEN_KEYS_DEBUG] About to extract keys and set watchpoints...")

    # EXTRACT KEYS AND SET WATCHPOINTS
    _extract_and_watch_keys(frame, key_id)

    if ENABLE_DEBUG_OUTPUT:
        print(f"[GEN_KEYS_DEBUG] Key extraction complete for {key_id}\n")

    return False

def switch_keys_callback(frame, bp_loc, internal_dict):
    """Breakpoint for switch_keys() - RE-CHECK KEYS AND DUMP MEMORY"""
    # Process type detection
    thread = frame.GetThread()
    process = thread.GetProcess()
    process_type = get_process_type(process)
    pid = process.GetProcessID()

    print(f"\n[SWITCH_KEYS] Called in {process_type.upper()} (PID {pid})")

    timestamp = time.time()

    log_event("KEYS_ACTIVATED", "Keys activated via switch_keys()", {
        'timestamp': timestamp,
        'process_type': process_type,
        'pid': pid
    })

    if active_keys:
        latest_key = max(active_keys.keys(), key=lambda k: active_keys[k].get('generated_at', 0))
        log_timing(latest_key, "activated", timestamp)

        # RE-EXTRACT KEYS to see if they have values now
        log_event("KEY_RECHECK", f"Re-extracting keys for {latest_key} after switch_keys()")
        _recheck_keys(frame, latest_key)

        # Dump memory AFTER NEWKEYS activation (keys are now active)
        if ENABLE_MEMORY_DUMPS:
            print(f"[DEBUG] value of ENABLE_MEMORY_DUMPS is {ENABLE_MEMORY_DUMPS} on line 685")
            # thread and process already defined at function start
            log_event("DUMP_START", f"Dumping memory after NEWKEYS activation (keys active for {latest_key})")
            dump_full_memory(process, "after_newkeys_activate", latest_key)

    return False

def kex_init_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint for KEX initialization functions
    Detects initial KEX vs rekey based on function name or KEX counter
    """
    global _kex_counter, _fork_count, _fork_mode_switched, _connection_handler_pid

    # Get process info for logging
    thread = frame.GetThread()
    process = thread.GetProcess()
    process_type = get_process_type(process)
    pid = process.GetProcessID()

    print(f"\n[KEX_INIT] Called in {process_type.upper()} (PID {pid})")

    # V2_FIX: Switch fork-mode to 'parent' AFTER we've successfully followed child from fork #1
    # This must happen here (not in fork callback) because:
    # - Fork callback executes BEFORE fork completes
    # - Changing mode there affects the CURRENT fork, causing LLDB to stay with parent
    # - By switching here, LLDB has already followed child, and mode change only affects future forks
    if _fork_count == 1 and not _fork_mode_switched:
        # thread and process already defined at function start
        target = process.GetTarget()
        debugger = target.GetDebugger()

        current_pid = pid  # Use pid from function start
        _connection_handler_pid = current_pid  # Update with actual child PID

        print("\n" + "="*72)
        print(f"[FORK_MODE_SWITCH] KEX callback executing in PID {current_pid}")
        print(f"[FORK_MODE_SWITCH] This confirms LLDB successfully followed fork #1 child")
        print(f"[FORK_MODE_SWITCH] Now switching to 'follow-fork-mode parent' for fork #2")

        debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
        _fork_mode_switched = True

        print(f"[FORK_MODE_SWITCH] ✓ Mode switched successfully")
        print(f"[FORK_MODE_SWITCH] → On fork #2, LLDB will stay with connection handler")
        print("="*72 + "\n")

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
    # Process type detection
    thread = frame.GetThread()
    process = thread.GetProcess()
    process_type = get_process_type(process)
    pid = process.GetProcessID()

    print(f"\n[ABORT] Called in {process_type.upper()} (PID {pid})")

    timestamp = time.time()

    # Get function name that triggered this callback
    func_name = frame.GetFunctionName() or "unknown"

    log_event("CONNECTION_ABORT", f"Connection aborted via {func_name}", {
        'timestamp': timestamp,
        'function': func_name,
        'process_type': process_type,
        'pid': pid
    })

    # Dump memory before abort
    if ENABLE_MEMORY_DUMPS:
        # thread and process already defined at function start
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
    # Process type detection
    thread = frame.GetThread()
    process = thread.GetProcess()
    process_type = get_process_type(process)
    pid = process.GetProcessID()

    print(f"\n[KEXDH_INIT] Called in {process_type.upper()} (PID {pid})")

    timestamp = time.time()
    log_event("KEX_DH_INIT", "Received KEX DH init message (before shared secret)", {
        'timestamp': timestamp,
        'process_type': process_type,
        'pid': pid
    })

    # Dump memory BEFORE shared secret K is computed
    if ENABLE_MEMORY_DUMPS:
        # thread and process already defined
        log_event("DUMP_START", "Dumping memory before shared secret computation")
        dump_full_memory(process, "before_kexdh_reply")

    return False

def send_msg_kexdh_reply_callback(frame, bp_loc, internal_dict):
    """KEX DH reply callback - AFTER shared secret computation"""
    # Process type detection
    thread = frame.GetThread()
    process = thread.GetProcess()
    process_type = get_process_type(process)
    pid = process.GetProcessID()

    print(f"\n[KEXDH_REPLY] Called in {process_type.upper()} (PID {pid})")

    timestamp = time.time()
    log_event("KEX_DH_REPLY", "Sending KEX DH reply message (after shared secret)", {
        'timestamp': timestamp,
        'process_type': process_type,
        'pid': pid
    })

    # Dump memory AFTER shared secret K is computed (but before it's cleared)
    if ENABLE_MEMORY_DUMPS:
        # thread and process already defined
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
    if ENABLE_MEMORY_DUMPS:
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
    if ENABLE_MEMORY_DUMPS:
        print(f"[DEBUG] value of ENABLE_MEMORY_DUMPS is {ENABLE_MEMORY_DUMPS} on line 825")
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
            print(f"[DEBUG] Failed to read mp_int.dp pointer at offset 16, trying offset 12")
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

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup command: Configure breakpoints and watchpoints (IPsec two-command pattern)"""

    # Display configuration
    import os
    _wp_env = os.environ.get('LLDB_ENABLE_WATCHPOINTS', 'true')
    _wp_enabled = _wp_env.lower() in ('true', '1', 'yes')
    _md_env = os.environ.get('LLDB_ENABLE_MEMORY_DUMPS', 'true')
    _md_enabled = _md_env.lower() in ('true', '1', 'yes')

    print("=" * 72)
    print("Setting up Dropbear monitoring...")
    print(f"[DROPBEAR_CB_VERSION] {__version__}")
    print(f"Environment: LLDB_ENABLE_WATCHPOINTS = '{_wp_env}'")
    print(f"Environment: LLDB_ENABLE_MEMORY_DUMPS = '{_md_env}'")
    print(f"Configuration: Watchpoints {'ENABLED' if _wp_enabled else 'DISABLED'}")
    print(f"Configuration: Memory dumps {'ENABLED' if _md_enabled else 'DISABLED'}")
    if not _wp_enabled and not _md_enabled:
        print("Mode: Key extraction only (no watchpoints, no memory dumps)")
    elif not _wp_enabled:
        print("Mode: Memory dumps and key extraction (no watchpoints)")
    elif not _md_enabled:
        print("Mode: Watchpoints and key extraction (no memory dumps)")
    else:
        print("Mode: Full monitoring with hardware watchpoints and memory dumps")
    print("=" * 72)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("ERROR: No valid target available")
        return

    # Set breakpoints
    bp1 = target.BreakpointCreateByName("gen_new_keys")
    bp1.SetScriptCallbackFunction("dropbear_callbacks_v2.gen_new_keys_entry")
    bp1.SetAutoContinue(True)
    print(f"✓ Set breakpoint on gen_new_keys (bp {bp1.GetID()})")

    # Add breakpoints for KEX initialization functions to detect rekey
    for kex_func in ["kexfirstinitialise", "kexinitialise"]:
        bp_kex = target.BreakpointCreateByName(kex_func)
        if bp_kex.IsValid() and bp_kex.GetNumLocations() > 0:
            bp_kex.SetScriptCallbackFunction("dropbear_callbacks_v2.kex_init_callback")
            bp_kex.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {kex_func} (bp {bp_kex.GetID()}, {bp_kex.GetNumLocations()} locations)")
        else:
            print(f"⚠ Could not set breakpoint on {kex_func} (static symbol or not found)")

    # Add KEX message handlers (called during both initial KEX and rekey)
    for kex_msg in ["recv_msg_kexinit", "send_msg_kexinit"]:
        bp_msg = target.BreakpointCreateByName(kex_msg)
        if bp_msg.IsValid():
            bp_msg.SetScriptCallbackFunction("dropbear_callbacks_v2.kex_init_callback")
            bp_msg.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {kex_msg} for rekey detection (bp {bp_msg.GetID()})")

    for alt_name in ["recv_msg_kexdh_init", "send_msg_kexdh_reply", "send_msg_newkeys", "recv_msg_newkeys", "switch_keys"]:
        bp_alt = target.BreakpointCreateByName(alt_name)
        if bp_alt.IsValid():
            if alt_name == "switch_keys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_v2.switch_keys_callback")
            elif alt_name == "recv_msg_kexdh_init":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_v2.recv_msg_kexdh_init_callback")
            elif alt_name == "send_msg_kexdh_reply":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_v2.send_msg_kexdh_reply_callback")
            elif alt_name == "send_msg_newkeys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_v2.send_msg_newkeys_callback")
            elif alt_name == "recv_msg_newkeys":
                bp_alt.SetScriptCallbackFunction("dropbear_callbacks_v2.recv_msg_newkeys_callback")
            bp_alt.SetAutoContinue(True)
            print(f"✓ Set breakpoint on {alt_name} (bp {bp_alt.GetID()})")

    # Add shared secret extraction breakpoints (for handshake secret K)
    for kex_func in ["kexdh_comb_key", "kexecdh_comb_key", "kexcurve25519_comb_key"]:
        bp_kex = target.BreakpointCreateByName(kex_func)
        if bp_kex.IsValid() and bp_kex.GetNumLocations() > 0:
            bp_kex.SetScriptCallbackFunction("dropbear_callbacks_v2.kex_comb_key_exit_callback")
            bp_kex.SetOneShot(False)  # Should fire on every call (initial + rekey)
            bp_kex.SetAutoContinue(True)
            print(f"✓ Set shared secret breakpoint on {kex_func} (bp {bp_kex.GetID()})")
        else:
            print(f"⚠ Could not set breakpoint on {kex_func} (static symbol or not found)")

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
                bp_abort.SetScriptCallbackFunction("dropbear_callbacks_v2.abort_callback")
                bp_abort.SetAutoContinue(True)
                print(f"✓ Set abort breakpoint on {func_name} (bp {bp_abort.GetID()})")
            else:
                print(f"⚠ Warning: Abort function '{func_name}' not found in binary")

    # Verify module-level configuration matches what we read
    global ENABLE_WATCHPOINTS, ENABLE_MEMORY_DUMPS
    print(f"\nVerification: Module-level ENABLE_WATCHPOINTS = {ENABLE_WATCHPOINTS}")
    print(f"Verification: Module-level ENABLE_MEMORY_DUMPS = {ENABLE_MEMORY_DUMPS}")
    if ENABLE_WATCHPOINTS != _wp_enabled:
        print(f"WARNING: Mismatch detected! Module WATCHPOINTS={ENABLE_WATCHPOINTS}, Local={_wp_enabled}")
        # Override the module-level variable to match the current environment
        ENABLE_WATCHPOINTS = _wp_enabled
        print(f"Corrected: ENABLE_WATCHPOINTS now set to {ENABLE_WATCHPOINTS}")
    if ENABLE_MEMORY_DUMPS != _md_enabled:
        print(f"WARNING: Mismatch detected! Module MEMORY_DUMPS={ENABLE_MEMORY_DUMPS}, Local={_md_enabled}")
        # Override the module-level variable to match the current environment
        ENABLE_MEMORY_DUMPS = _md_enabled
        print(f"Corrected: ENABLE_MEMORY_DUMPS now set to {ENABLE_MEMORY_DUMPS}")

    # Success messages based on configuration
    print("\n✓ Dropbear monitoring setup complete")
    if ENABLE_WATCHPOINTS:
        print("  Hardware watchpoints: ENABLED - will be set when keys are generated")
    else:
        print("  Hardware watchpoints: DISABLED")
    if ENABLE_MEMORY_DUMPS:
        print("  Memory dumps: ENABLED - will be captured at key lifecycle events")
    else:
        print("  Memory dumps: DISABLED")

    print(f"  Abort hooks: {', '.join(abort_hooks)}")

    # Add a breakpoint on fork() itself to detect when Dropbear forks
    print("\n" + "="*72)
    print("Setting up fork detection...")
    bp_fork = target.BreakpointCreateByName("fork")
    if bp_fork.IsValid() and bp_fork.GetNumLocations() > 0:
        bp_fork.SetScriptCallbackFunction("dropbear_callbacks_v2.fork_callback")
        bp_fork.SetAutoContinue(True)
        print(f"✓ Set breakpoint on fork() (bp {bp_fork.GetID()}, {bp_fork.GetNumLocations()} locations) - AUTO-CONTINUE")
        print("  This will fire when Dropbear forks to handle SSH connection")
    else:
        print("⚠ Could not set breakpoint on fork() - will rely on follow-fork-mode")

    print("="*72)
    print("\n[SETUP_COMPLETE] Use 'dropbear_auto_continue' command to start monitoring")


def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue command with keep-alive loop (IPsec two-command pattern)

    This function implements the proven pattern from IPsec monitoring:
    - Explicit keep-alive loop continuously polls process state
    - When stopped (breakpoint, watchpoint, etc.), calls process.Continue()
    - Must be called from OUTSIDE callbacks (not inside) for clean continuation
    - Runs until process exits or is detached
    """
    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[AUTO_CONTINUE] ERROR: No valid target")
        return

    process = target.GetProcess()
    if not process or not process.IsValid():
        print("[AUTO_CONTINUE] ERROR: No valid process attached")
        return

    pid = process.GetProcessID()
    print("=" * 72)
    print(f"[AUTO_CONTINUE] Starting keep-alive loop for Dropbear (PID {pid})")
    print(f"[AUTO_CONTINUE] Pattern: IPsec two-command architecture")
    print(f"[AUTO_CONTINUE] Will auto-resume after breakpoints, watchpoints, and forks")
    print("=" * 72)

    # Initial continue to start process running
    print(f"[AUTO_CONTINUE] Initial continue...")
    error = process.Continue()
    if error.Fail():
        print(f"[AUTO_CONTINUE] ERROR: Initial continue failed: {error.GetCString()}")
        return

    print(f"[AUTO_CONTINUE] ✓ Process running - entering keep-alive loop")
    print(f"[AUTO_CONTINUE] Monitoring process state (poll interval: 0.5s)")
    print(f"[AUTO_CONTINUE] Press Ctrl+C to stop monitoring\n")
    sys.stdout.flush()

    iteration = 0
    last_continue_time = time.time()

    # Keep-alive loop: continuously check and resume
    while True:
        iteration += 1

        # Check process state
        current_state = process.GetState()

        if current_state == lldb.eStateStopped:
            # Process stopped - automatically continue
            now = time.time()
            elapsed = now - last_continue_time

            # Get stop reason for logging
            stop_reason_str = "unknown"
            for thread in process:
                if thread.GetStopReason() != lldb.eStopReasonNone:
                    stop_reason = thread.GetStopReason()
                    stop_reason_str = {
                        lldb.eStopReasonBreakpoint: "breakpoint",
                        lldb.eStopReasonWatchpoint: "watchpoint",
                        lldb.eStopReasonTrace: "trace",
                        lldb.eStopReasonSignal: "signal",
                        lldb.eStopReasonException: "exception",
                        lldb.eStopReasonExec: "exec",
                        lldb.eStopReasonFork: "fork",
                    }.get(stop_reason, f"reason_{stop_reason}")
                    break

            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))
            print(f"[{timestamp}] [AUTO_CONTINUE] Process STOPPED (iteration {iteration}, reason: {stop_reason_str}, {elapsed:.2f}s since last continue)")

            # Auto-continue
            error = process.Continue()
            if error.Fail():
                print(f"[AUTO_CONTINUE] ERROR: Continue failed: {error.GetCString()}")
                # Don't break - keep trying
            else:
                print(f"[AUTO_CONTINUE] ✓ Process auto-continued after {stop_reason_str}")
                last_continue_time = now

            sys.stdout.flush()

        elif current_state == lldb.eStateExited:
            exit_code = process.GetExitStatus()
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            print(f"\n[{timestamp}] [AUTO_CONTINUE] Process EXITED with code {exit_code}")
            print(f"[AUTO_CONTINUE] Total iterations: {iteration}")
            print(f"[AUTO_CONTINUE] Keep-alive loop terminated")
            break

        elif current_state == lldb.eStateCrashed:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            print(f"\n[{timestamp}] [AUTO_CONTINUE] Process CRASHED")
            print(f"[AUTO_CONTINUE] Keep-alive loop terminated")
            break

        elif current_state == lldb.eStateDetached:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            print(f"\n[{timestamp}] [AUTO_CONTINUE] Debugger DETACHED")
            print(f"[AUTO_CONTINUE] Keep-alive loop terminated")
            break

        elif current_state == lldb.eStateInvalid:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            print(f"\n[{timestamp}] [AUTO_CONTINUE] Process state INVALID")
            print(f"[AUTO_CONTINUE] Keep-alive loop terminated")
            break

        # Brief sleep to avoid busy-waiting (0.5s = responsive but not wasteful)
        time.sleep(0.5)

    print("=" * 72)


def __lldb_init_module(debugger, internal_dict):
    """Initialize module when imported by LLDB

    This function ONLY registers commands - it does NOT set up monitoring.
    This is the IPsec two-command pattern: separate registration from execution.

    Usage:
        lldb -o 'command script import /path/to/dropbear_callbacks_v2.py' \\
             -o 'process attach -p $PID' \\
             -o 'dropbear_setup_monitoring' \\
             -o 'dropbear_auto_continue'
    """

    # Register the two commands
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_v2.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_v2.dropbear_auto_continue dropbear_auto_continue'
    )

    print("=" * 72)
    print("Dropbear LLDB Callbacks V2 - Two-Command Pattern")
    print(f"[VERSION] {__version__}")
    print(f"[LOADED ] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_load_time))} local")
    print(f"[FILE   ] {__file__}")
    print("=" * 72)
    print("Commands registered:")
    print("  dropbear_setup_monitoring  - Configure breakpoints and watchpoints")
    print("  dropbear_auto_continue     - Start keep-alive loop with auto-resume")
    print("=" * 72)
    print("\nUsage:")
    print("  1. Attach to process (if not already attached)")
    print("  2. Run: dropbear_setup_monitoring")
    print("  3. Run: dropbear_auto_continue")
    print("=" * 72)
