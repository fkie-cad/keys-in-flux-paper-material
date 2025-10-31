#!/usr/bin/env python3
"""
OpenSSH LLDB Callbacks - Production Monitoring (Two-Command Pattern)

Applies Dropbear/strongSwan lessons:
- Two-command architecture (setup + auto-continue, NOT SetAutoContinue)
- Register-based key extraction (fork-resilient, no symbolic dependencies)
- Proper fork handling (simpler than Dropbear - only 1 fork)
- One-shot exit breakpoints using LR/return address
- Targeted heap dumps during execution, full dumps at checkpoints

Architecture Support: x86-64 and ARM64

Key Functions Monitored:
- fork() - Track OpenSSH master → connection handler fork
- kex_derive_keys() - Main KEX function (entry + exit)

OpenSSH Fork Pattern (simpler than Dropbear):
  Fork #1: Master process (PID 1) → Connection handler
  - KEX happens in connection handler
  - No second fork (privilege separation disabled)
"""

import lldb
import json
import time
import os
import struct
import sys

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_fork_count = 0
_fork_mode_switched = False
_connection_handler_pid = None
_kex_counter = 0
_keys_extracted = {}
_target = None
_debugger = None
_process = None

# Configuration from environment
LLDB_KEYLOG = os.getenv("LLDB_KEYLOG", "/data/keylogs/ssh_keylog.log")
LLDB_OUTDIR = os.getenv("LLDB_OUTDIR", "/data/dumps")
LLDB_RESULTS_DIR = os.getenv("LLDB_RESULTS_DIR", "/data/lldb_results")

# Feature flags (watchpoints disabled for initial phase)
ENABLE_MEMORY_DUMPS = os.getenv("LLDB_ENABLE_MEMORY_DUMPS", "true").lower() == "true"
ENABLE_WATCHPOINTS = os.getenv("LLDB_ENABLE_WATCHPOINTS", "false").lower() == "true"  # Phase 5

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def log(message, level="INFO"):
    """Thread-safe logging"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)

def log_json_event(event_type, metadata):
    """Log structured event to JSONL file"""
    event_file = os.path.join(LLDB_OUTDIR, "openssh_events.jsonl")
    event = {
        "timestamp": time.time(),
        "event_type": event_type,
        "metadata": metadata
    }
    try:
        with open(event_file, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        log(f"Failed to write event: {e}", "ERROR")

def write_keylog(cookie_hex, shared_secret_hex):
    """Write keylog entry (Wireshark-compatible format)"""
    try:
        with open(LLDB_KEYLOG, "a") as f:
            f.write(f"{cookie_hex} SHARED_SECRET {shared_secret_hex}\n")
        log(f"✓ Keylog written: {cookie_hex[:16]}... SHARED_SECRET {shared_secret_hex[:16]}...")
    except Exception as e:
        log(f"Failed to write keylog: {e}", "ERROR")

def dump_heap_targeted(process, label, key_id=None):
    """
    Targeted heap dump - parse /proc/PID/maps and dump [heap] region only.
    Much smaller than full dump (~10MB vs ~100MB+).
    """
    if not ENABLE_MEMORY_DUMPS:
        return

    pid = process.GetProcessID()
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                if "[heap]" in line:
                    parts = line.split()
                    addr_range = parts[0]
                    start, end = addr_range.split("-")
                    start_addr = int(start, 16)
                    end_addr = int(end, 16)
                    size = end_addr - start_addr

                    error = lldb.SBError()
                    heap_data = process.ReadMemory(start_addr, size, error)
                    if error.Fail():
                        log(f"Failed to read heap: {error}", "ERROR")
                        return

                    timestamp = time.strftime("%Y%m%d_%H%M%S")
                    suffix = f"_{key_id}" if key_id else ""
                    filename = f"{timestamp}_{label}_openssh_heap{suffix}.dump"
                    filepath = os.path.join(LLDB_OUTDIR, filename)

                    with open(filepath, "wb") as dump_file:
                        dump_file.write(heap_data)

                    log(f"✓ Heap dump: {filename} ({size // 1024} KB)")
                    return
    except Exception as e:
        log(f"Targeted heap dump failed: {e}", "ERROR")

def dump_full_process(process, label, key_id=None):
    """Full process memory dump using gcore (checkpoint dumps only)"""
    if not ENABLE_MEMORY_DUMPS:
        return

    pid = process.GetProcessID()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    suffix = f"_{key_id}" if key_id else ""
    filename = f"{timestamp}_{label}_openssh_full{suffix}.core"
    filepath = os.path.join(LLDB_OUTDIR, filename)

    try:
        os.system(f"gcore -o {filepath} {pid} > /dev/null 2>&1")
        log(f"✓ Full dump: {filename}")
    except Exception as e:
        log(f"Full dump failed: {e}", "ERROR")

# ═══════════════════════════════════════════════════════════════════════════
# FORK TRACKING
# ═══════════════════════════════════════════════════════════════════════════

def fork_callback(frame, bp_loc, internal_dict):
    """
    Track OpenSSH forks (OpenSSH 10.x: sshd → sshd-session fork/exec).

    Critical: Only follow FIRST fork (sshd → sshd-session), then stop following.
    Otherwise we follow into short-lived privilege separation children that exit.
    """
    global _fork_count, _fork_mode_switched

    _fork_count += 1
    process_name = _target.GetExecutable().GetFilename() if _target else "unknown"

    log(f"[FORK] Fork #{_fork_count} in {process_name}")

    # After Fork #1, we're in sshd-session - switch to parent mode to STAY here
    if _fork_count == 1 and not _fork_mode_switched:
        log("[FORK] ✓ Entered sshd-session - switching to parent mode to stay here")
        _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
        _fork_mode_switched = True
    elif "sshd-session" in process_name and _fork_count > 1:
        log(f"[FORK] In sshd-session fork #{_fork_count} (staying with parent)")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# KEX MONITORING
# ═══════════════════════════════════════════════════════════════════════════

def kex_entry_callback(frame, bp_loc, internal_dict):
    """
    kex_derive_keys() ENTRY callback.

    Function signature (OpenSSH 8.9p1):
      int kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
                          const struct sshbuf *shared_secret)

    Register mapping:
      ARM64:  x0=ssh*, x1=hash*, x2=hashlen, x3=shared_secret*
      x86-64: rdi=ssh*, rsi=hash*, rdx=hashlen, rcx=shared_secret*

    Actions:
      1. Dump PRE-KEX heap (targeted)
      2. Set one-shot exit breakpoint using LR/return address
    """
    global _kex_counter, _target

    _kex_counter += 1
    kex_id = f"kex_{_kex_counter}"

    log(f"[KEX_ENTRY] Entered kex_derive_keys() - {kex_id}")

    process = frame.GetThread().GetProcess()

    # Dump PRE-KEX memory (targeted heap)
    log(f"[DUMP] PRE-KEX heap dump for {kex_id}")
    dump_heap_targeted(process, "pre_kex", kex_id)

    # Set one-shot exit breakpoint using LR (ARM64) or stack (x86-64)
    arch = _target.GetTriple().lower()
    error = lldb.SBError()

    if "arm64" in arch or "aarch64" in arch:
        # ARM64: Return address in LR register
        lr = frame.FindRegister("lr")
        if lr and lr.IsValid():
            retaddr = lr.GetValueAsUnsigned()
            log(f"[KEX_ENTRY] ARM64: Return address from LR = {retaddr:#x}")
        else:
            log(f"[KEX_ENTRY] Failed to read LR register", "ERROR")
            return False
    elif "x86_64" in arch or "amd64" in arch:
        # x86-64: Return address at [rsp]
        rsp = frame.FindRegister("rsp")
        if rsp and rsp.IsValid():
            rsp_val = rsp.GetValueAsUnsigned()
            retaddr_bytes = process.ReadMemory(rsp_val, 8, error)
            if error.Fail():
                log(f"[KEX_ENTRY] Failed to read return address from stack: {error}", "ERROR")
                return False
            retaddr = struct.unpack("<Q", retaddr_bytes)[0]
            log(f"[KEX_ENTRY] x86-64: Return address from [rsp] = {retaddr:#x}")
        else:
            log(f"[KEX_ENTRY] Failed to read RSP register", "ERROR")
            return False
    else:
        log(f"[KEX_ENTRY] Unsupported architecture: {arch}", "ERROR")
        return False

    # Create one-shot exit breakpoint
    exit_bp = _target.BreakpointCreateByAddress(retaddr)
    if exit_bp and exit_bp.IsValid():
        exit_bp.SetOneShot(True)
        exit_bp.SetScriptCallbackFunction("openssh_callbacks.kex_exit_callback")
        log(f"[KEX_ENTRY] ✓ One-shot exit breakpoint set at {retaddr:#x} (bp {exit_bp.GetID()})")

        # Store KEX ID in internal_dict for exit callback
        exit_bp.SetScriptCallbackBody(f"return openssh_callbacks.kex_exit_callback(frame, bp_loc, {{'kex_id': '{kex_id}'}})")
    else:
        log(f"[KEX_ENTRY] Failed to set exit breakpoint at {retaddr:#x}", "ERROR")

    log_json_event("kex_entry", {"kex_id": kex_id, "retaddr": retaddr})

    return False  # Continue execution

def kex_exit_callback(frame, bp_loc, internal_dict):
    """
    kex_derive_keys() EXIT callback.

    Keys have been derived - extract them using register-based approach.

    Register extraction strategy (fork-resilient, no symbolic dependencies):
      1. Read function parameters from registers (still valid on return in many ABIs)
      2. Extract session hash/cookie from hash pointer
      3. Extract shared_secret from sshbuf structure
      4. Write keylog entry
      5. Dump POST-KEX heap
    """
    kex_id = internal_dict.get("kex_id", f"kex_{_kex_counter}")

    log(f"[KEX_EXIT] Exited kex_derive_keys() - {kex_id}")

    process = frame.GetThread().GetProcess()
    arch = _target.GetTriple().lower()
    error = lldb.SBError()

    # Extract keys using register-based approach
    keys = extract_keys_register_based(frame, arch, process)

    if keys:
        log(f"[KEX_EXIT] ✓ Keys extracted: cookie={keys['cookie_hex'][:16]}..., secret={keys['shared_secret_hex'][:16]}...")

        # Write keylog
        write_keylog(keys["cookie_hex"], keys["shared_secret_hex"])

        # Store extracted keys
        _keys_extracted[kex_id] = {
            "timestamp": time.time(),
            "cookie": keys["cookie_hex"],
            "shared_secret": keys["shared_secret_hex"]
        }

        log_json_event("kex_exit", {
            "kex_id": kex_id,
            "cookie": keys["cookie_hex"],
            "secret_length": len(keys["shared_secret_hex"]) // 2
        })
    else:
        log(f"[KEX_EXIT] ✗ Failed to extract keys", "ERROR")

    # Dump POST-KEX memory (targeted heap)
    log(f"[DUMP] POST-KEX heap dump for {kex_id}")
    dump_heap_targeted(process, "post_kex", kex_id)

    return False  # Continue execution

def extract_keys_register_based(frame, arch, process):
    """
    Register-based key extraction (Dropbear pattern).

    OpenSSH kex_derive_keys() signature:
      int kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen,
                          const struct sshbuf *shared_secret)

    Register mapping:
      ARM64:  x0=ssh*, x1=hash*, x2=hashlen, x3=shared_secret*
      x86-64: rdi=ssh*, rsi=hash*, rdx=hashlen, rcx=shared_secret*

    Returns: dict with 'cookie_hex' and 'shared_secret_hex', or None
    """
    error = lldb.SBError()
    result = {}

    try:
        # Get register values based on architecture
        if "arm64" in arch or "aarch64" in arch:
            ssh_ptr = frame.FindRegister("x0").GetValueAsUnsigned()
            hash_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
            hashlen = frame.FindRegister("x2").GetValueAsUnsigned()
            shared_secret_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
            log(f"[EXTRACT] ARM64: ssh={ssh_ptr:#x}, hash={hash_ptr:#x}, hashlen={hashlen}, secret={shared_secret_ptr:#x}")
        elif "x86_64" in arch or "amd64" in arch:
            ssh_ptr = frame.FindRegister("rdi").GetValueAsUnsigned()
            hash_ptr = frame.FindRegister("rsi").GetValueAsUnsigned()
            hashlen = frame.FindRegister("rdx").GetValueAsUnsigned()
            shared_secret_ptr = frame.FindRegister("rcx").GetValueAsUnsigned()
            log(f"[EXTRACT] x86-64: ssh={ssh_ptr:#x}, hash={hash_ptr:#x}, hashlen={hashlen}, secret={shared_secret_ptr:#x}")
        else:
            log(f"[EXTRACT] Unsupported architecture: {arch}", "ERROR")
            return None

        # Extract session hash/cookie
        if hash_ptr and hashlen > 0:
            hash_data = process.ReadMemory(hash_ptr, hashlen, error)
            if error.Fail():
                log(f"[EXTRACT] Failed to read hash: {error}", "ERROR")
                return None
            result["cookie_hex"] = hash_data.hex()
            log(f"[EXTRACT] ✓ Cookie extracted: {result['cookie_hex'][:32]}... ({hashlen} bytes)")
        else:
            log(f"[EXTRACT] Invalid hash pointer or length", "ERROR")
            return None

        # Extract shared secret from sshbuf structure
        # struct sshbuf { u_char *d; size_t off; size_t size; size_t max_size; ... }
        if shared_secret_ptr:
            # Read first 3 fields (pointers are 8 bytes on 64-bit)
            data_ptr_bytes = process.ReadMemory(shared_secret_ptr, 8, error)
            if error.Fail():
                log(f"[EXTRACT] Failed to read sshbuf->d: {error}", "ERROR")
                return None
            data_ptr = struct.unpack("<Q", data_ptr_bytes)[0]

            # Read offset field (size_t)
            off_bytes = process.ReadMemory(shared_secret_ptr + 8, 8, error)
            if error.Fail():
                log(f"[EXTRACT] Failed to read sshbuf->off: {error}", "ERROR")
                return None
            off = struct.unpack("<Q", off_bytes)[0]

            # Read size field (size_t)
            size_bytes = process.ReadMemory(shared_secret_ptr + 16, 8, error)
            if error.Fail():
                log(f"[EXTRACT] Failed to read sshbuf->size: {error}", "ERROR")
                return None
            size = struct.unpack("<Q", size_bytes)[0]

            log(f"[EXTRACT] sshbuf: d={data_ptr:#x}, off={off}, size={size}")

            # Read actual secret data (accounting for offset)
            secret_data = process.ReadMemory(data_ptr + off, size - off, error)
            if error.Fail():
                log(f"[EXTRACT] Failed to read shared secret: {error}", "ERROR")
                return None

            result["shared_secret_hex"] = secret_data.hex()
            log(f"[EXTRACT] ✓ Shared secret extracted: {result['shared_secret_hex'][:32]}... ({size - off} bytes)")
        else:
            log(f"[EXTRACT] Invalid shared_secret pointer", "ERROR")
            return None

        return result

    except Exception as e:
        log(f"[EXTRACT] Exception during key extraction: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return None

# ═══════════════════════════════════════════════════════════════════════════
# TWO-COMMAND ARCHITECTURE (Dropbear/strongSwan Pattern)
# ═══════════════════════════════════════════════════════════════════════════

def openssh_setup_monitoring(debugger, command, result, internal_dict):
    """
    Command 1: Setup monitoring (does NOT start auto-continue).

    Registers breakpoints:
      - fork() - Track OpenSSH master → connection handler
      - kex_derive_keys() - Main KEX function

    Does NOT call process.Continue() - that's done by openssh_auto_continue.
    """
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    if not _target.IsValid():
        log("ERROR: No valid target", "ERROR")
        return

    if not _process.IsValid():
        log("ERROR: No valid process", "ERROR")
        return

    log("="*80)
    log("OpenSSH LLDB Monitoring - Setup Phase")
    log("="*80)
    log(f"Target: {_target.GetExecutable().GetFilename()}")
    log(f"Process: PID {_process.GetProcessID()}")
    log(f"Architecture: {_target.GetTriple()}")
    log(f"Keylog: {LLDB_KEYLOG}")
    log(f"Dumps: {LLDB_OUTDIR}")
    log(f"Memory dumps: {'ENABLED' if ENABLE_MEMORY_DUMPS else 'DISABLED'}")
    log(f"Watchpoints: {'ENABLED' if ENABLE_WATCHPOINTS else 'DISABLED (Phase 5)'}")
    log("="*80)

    # Breakpoint 1: fork() - Track connection handler fork
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp and fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("openssh_callbacks.fork_callback")
        log(f"[SETUP] ✓ Breakpoint 1: fork() (bp {fork_bp.GetID()})")
    else:
        log(f"[SETUP] ✗ Failed to set fork() breakpoint", "ERROR")

    # Breakpoint 2: kex_derive_keys() - Main KEX function
    kex_bp = _target.BreakpointCreateByName("kex_derive_keys")
    if kex_bp and kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("openssh_callbacks.kex_entry_callback")
        log(f"[SETUP] ✓ Breakpoint 2: kex_derive_keys() (bp {kex_bp.GetID()})")
    else:
        log(f"[SETUP] ✗ Failed to set kex_derive_keys() breakpoint", "WARN")
        log(f"[SETUP]   Trying pattern-based approach...", "INFO")

    log("="*80)
    log("[SETUP] ✓ Monitoring setup complete")
    log("[SETUP] Ready for 'openssh_auto_continue' command")
    log("="*80)

def openssh_auto_continue(debugger, command, result, internal_dict):
    """
    Command 2: Auto-continue loop (Dropbear/strongSwan pattern).

    Keep-alive loop:
      1. Start process with Continue()
      2. Poll process state every 50ms
      3. If stopped (breakpoint/watchpoint hit), call Continue() again
      4. Loop until process exits

    This is the ONLY place that calls process.Continue() in automated mode.
    Callbacks return False (don't continue) - loop handles continuation.
    """
    global _process

    if not _process or not _process.IsValid():
        log("[AUTO] ERROR: No valid process", "ERROR")
        return

    log("="*80)
    log("[AUTO] Starting auto-continue loop")
    log("[AUTO] Process will run continuously until exit")
    log("[AUTO] Breakpoint callbacks will execute transparently")
    log("="*80)

    # Initial continue
    _process.Continue()
    log("[AUTO] ✓ Process started")

    iteration = 0
    last_state = None

    # Keep-alive loop
    while _process.GetState() != lldb.eStateExited:
        current_state = _process.GetState()

        # State change logging (only on transitions)
        if current_state != last_state:
            state_name = lldb.SBDebugger.StateAsCString(current_state)
            if current_state == lldb.eStateStopped:
                log(f"[AUTO] Process stopped (iteration {iteration})")
            elif current_state == lldb.eStateRunning:
                log(f"[AUTO] Process running (iteration {iteration})")
            last_state = current_state

        # Auto-resume if stopped
        if current_state == lldb.eStateStopped:
            log(f"[AUTO] Resuming process...")
            _process.Continue()

        # Brief sleep to avoid busy-waiting
        time.sleep(0.05)
        iteration += 1

    log("="*80)
    log(f"[AUTO] Process exited after {iteration} iterations")
    log("[AUTO] Auto-continue loop terminated")
    log("="*80)

# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def __lldb_init_module(debugger, internal_dict):
    """
    Called automatically when script is imported by LLDB.

    Registers custom commands:
      - openssh_setup_monitoring
      - openssh_auto_continue

    Does NOT start monitoring - user must call commands explicitly.
    """
    debugger.HandleCommand(
        'command script add -f openssh_callbacks.openssh_setup_monitoring openssh_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f openssh_callbacks.openssh_auto_continue openssh_auto_continue'
    )

    log("="*80)
    log("OpenSSH LLDB Callbacks - Two-Command Pattern")
    log("="*80)
    log("Commands registered:")
    log("  - openssh_setup_monitoring  : Setup breakpoints")
    log("  - openssh_auto_continue     : Start monitoring loop")
    log("")
    log("Usage:")
    log("  (lldb) openssh_setup_monitoring")
    log("  (lldb) openssh_auto_continue")
    log("="*80)
