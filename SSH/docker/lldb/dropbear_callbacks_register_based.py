#!/usr/bin/env python3
"""
Dropbear Register-Based Watchpoint - Phase 6A

REGISTER-BASED KEY EXTRACTION (Matching IPsec Pattern)
=======================================================

This approach matches the proven IPsec/strongSwan pattern that works successfully:
- Uses DIRECT REGISTER READING instead of symbolic navigation
- Reads runtime memory addresses from function arguments
- No dependency on LLDB symbol table state
- Should work reliably across fork operations

Target Function: dropbear_chachapoly_start(cipher, IV, key, keylen, num_rounds, state)

ARM64 Register Layout:
  x0: cipher (unused)
  x1: IV (unused)
  x2: ⭐ key pointer (64 bytes: ChaCha20 main + header keys)
  x3: keylen (should be 64)
  x4: num_rounds (unused)
  x5: state pointer (destination)

Method:
1. Breakpoint on dropbear_chachapoly_start ENTRY
2. Read x2 register to get key pointer (runtime address)
3. Read and verify 64 bytes at that address
4. Set watchpoint on key_ptr + 0 (first byte of main encryption key)
5. IMMEDIATE ENABLE (no delay)
6. Check for trace mode

Expected Outcome:
  ✅ trace_count == 0 → Register-based approach works like IPsec
  ❌ trace_count > 10 → Need timing delay (test Phase 6B)
"""

import lldb
import time
import os

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_fork_count = 0
_watchpoint_set = False
_key_address = None
_key_value = None

# LLDB objects (set during setup)
_target = None
_debugger = None
_process = None

# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def __lldb_init_module(debugger, internal_dict):
    """Called when script is imported by LLDB"""
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_register_based.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_register_based.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[REGISTER] Commands registered: dropbear_setup_monitoring, dropbear_auto_continue")

# ═══════════════════════════════════════════════════════════════════════════
# FORK CALLBACK (for reference, detect fork count)
# ═══════════════════════════════════════════════════════════════════════════

def fork_callback(frame, bp_loc, internal_dict):
    """Fork breakpoint - track fork count for diagnostics"""
    global _fork_count, _debugger

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    _fork_count += 1

    print(f"\n[REGISTER_FORK] Fork #{_fork_count} detected in PID {pid}")

    if _fork_count == 1:
        print(f"[REGISTER_FORK] This is FORK #1: Parent → Connection handler")
    elif _fork_count == 2:
        print(f"[REGISTER_FORK] This is FORK #2: Connection handler → Session")
        # Switch to parent mode to stay with connection handler
        if _debugger:
            _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
            print(f"[REGISTER_FORK] ✓ Fork-mode switched to PARENT")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# CHACHAPOLY START CALLBACK (Register-based key extraction)
# ═══════════════════════════════════════════════════════════════════════════

def chachapoly_start_callback(frame, bp_loc, internal_dict):
    """
    Callback for dropbear_chachapoly_start(cipher, IV, key, keylen, num_rounds, state)

    Extracts key address from x2 register (ARM64 arg2) and sets watchpoint.
    This matches the IPsec pattern: direct register reading, no symbolic navigation.
    """
    global _watchpoint_set, _key_address, _key_value, _target, _debugger, _process, _fork_count

    if _watchpoint_set:
        print(f"[REGISTER] Watchpoint already set, skipping")
        return False

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[REGISTER] dropbear_chachapoly_start() ENTRY in PID {pid} (fork count: {_fork_count})")
    print(f"[REGISTER] Using REGISTER-BASED extraction (matching IPsec pattern)")

    try:
        # ═══════════════════════════════════════════════════════════════════
        # STEP 1: Read x2 register to get key pointer (ARM64 arg2)
        # ═══════════════════════════════════════════════════════════════════

        x2_reg = frame.FindRegister("x2")
        if not x2_reg or not x2_reg.IsValid():
            print(f"[REGISTER] ERROR: Could not read x2 register")
            return False

        key_ptr = x2_reg.GetValueAsUnsigned()
        if key_ptr == 0:
            print(f"[REGISTER] ERROR: x2 register is NULL")
            return False

        print(f"[REGISTER] ✓ x2 (key pointer) = 0x{key_ptr:x}")

        # ═══════════════════════════════════════════════════════════════════
        # STEP 2: Read x3 register to verify keylen (should be 64)
        # ═══════════════════════════════════════════════════════════════════

        x3_reg = frame.FindRegister("x3")
        if x3_reg and x3_reg.IsValid():
            keylen = x3_reg.GetValueAsUnsigned()
            print(f"[REGISTER] ✓ x3 (keylen) = {keylen} bytes")
            if keylen != 64:
                print(f"[REGISTER] ⚠️  WARNING: Expected keylen=64, got {keylen}")

        # ═══════════════════════════════════════════════════════════════════
        # STEP 3: Read 64 bytes from key pointer
        # ═══════════════════════════════════════════════════════════════════

        error = lldb.SBError()
        key_data = process.ReadMemory(key_ptr, 64, error)

        if not error.Success():
            print(f"[REGISTER] ERROR reading key memory: {error}")
            return False

        if len(key_data) != 64:
            print(f"[REGISTER] ERROR: Only read {len(key_data)} bytes, expected 64")
            return False

        # First 32 bytes: Main ChaCha20 encryption key
        # Second 32 bytes: Header encryption key
        main_key = key_data[:32]
        header_key = key_data[32:64]

        print(f"[REGISTER] ✓ Read 64 bytes from 0x{key_ptr:x}")
        print(f"[REGISTER] Main encryption key (first 32 bytes):")
        print(f"[REGISTER]   {main_key.hex()}")
        print(f"[REGISTER] Header encryption key (second 32 bytes):")
        print(f"[REGISTER]   {header_key.hex()}")

        _key_address = key_ptr
        _key_value = main_key

        # ═══════════════════════════════════════════════════════════════════
        # STEP 4: Create watchpoint on main encryption key (IMMEDIATE ENABLE)
        # ═══════════════════════════════════════════════════════════════════

        print(f"\n[REGISTER] Creating watchpoint on main encryption key...")
        print(f"[REGISTER] Address: 0x{key_ptr:x} (from x2 register)")
        print(f"[REGISTER] Mode: IMMEDIATE ENABLE (Phase 6A)")

        wp_error = lldb.SBError()
        watchpoint = _target.WatchAddress(key_ptr, 4, False, True, wp_error)

        if not wp_error.Success():
            print(f"[REGISTER] ERROR: Watchpoint failed: {wp_error}")
            return False

        wp_id = watchpoint.GetID()
        print(f"[REGISTER] ✓ Watchpoint {wp_id} created at 0x{key_ptr:x}")

        # Inject one-shot callback (IPsec pattern)
        callback_name = f"register_wp_cb_{wp_id}"
        callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    print("\\n[REGISTER_WP] 🎯 WATCHPOINT HIT!")
    print(f"[REGISTER_WP] Key at 0x{key_ptr:x} was overwritten")
    print(f"[REGISTER_WP] PID: {{frame.GetThread().GetProcess().GetProcessID()}}")
    print(f"[REGISTER_WP] PC: 0x{{frame.GetPC():x}}")
    print("[REGISTER_WP] One-shot: Returning False to disable")
    return False
"""

        _debugger.HandleCommand(f"script {callback_code}")
        _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")

        print(f"[REGISTER] ✓ One-shot callback attached")
        print(f"[REGISTER] ✓ Watchpoint ENABLED and ready")
        _watchpoint_set = True

        print(f"\n[REGISTER] Register-based extraction complete")
        print(f"[REGISTER] If trace_count == 0, IPsec pattern works! ✅")

    except Exception as e:
        print(f"[REGISTER] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND (Register breakpoints)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup register-based monitoring (Phase 6A)"""
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[REGISTER] Dropbear Register-Based Watchpoint - Phase 6A")
    print("[REGISTER] IMMEDIATE ENABLE (No Delay)")
    print("="*70)
    print("[REGISTER] Matching IPsec pattern:")
    print("[REGISTER]  - Direct register reading (x2 = key pointer)")
    print("[REGISTER]  - No symbolic navigation")
    print("[REGISTER]  - Runtime address from function argument")
    print("[REGISTER]")
    print("[REGISTER] Expected Outcomes:")
    print("[REGISTER]  ✅ trace_count == 0 → Register approach works!")
    print("[REGISTER]  ❌ trace_count > 10 → Try Phase 6B (delayed enable)")
    print("="*70)

    # Set follow-fork-mode to CHILD initially (to follow fork #1)
    print("[REGISTER] Setting initial follow-fork-mode: CHILD")
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")

    # Breakpoint 1: fork() - to detect forks and switch modes
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("dropbear_callbacks_register_based.fork_callback")
        print(f"[REGISTER] ✓ Breakpoint on fork() (ID {fork_bp.GetID()})")
    else:
        print(f"[REGISTER] ⚠️  Could not set breakpoint on fork()")

    # Breakpoint 2: dropbear_chachapoly_start - register-based key extraction
    chachapoly_bp = _target.BreakpointCreateByName("dropbear_chachapoly_start")
    if chachapoly_bp.IsValid():
        chachapoly_bp.SetScriptCallbackFunction("dropbear_callbacks_register_based.chachapoly_start_callback")
        print(f"[REGISTER] ✓ Breakpoint on dropbear_chachapoly_start() (ID {chachapoly_bp.GetID()})")
    else:
        print(f"[REGISTER] ⚠️  Could not set breakpoint on dropbear_chachapoly_start()")
        print(f"[REGISTER] This is CRITICAL - cannot proceed without this function")

    print("[REGISTER] Setup complete - ready for auto_continue")
    print("[REGISTER] Watchpoint will be set from x2 register (ARM64 arg2)")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND (Keep-alive loop with trace detection)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop with trace mode detection"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[REGISTER_AUTO] Starting auto-continue loop")
    print("[REGISTER_AUTO] Monitoring for trace mode...")
    print("[REGISTER_AUTO] Expecting ZERO if register approach works (like IPsec)")

    # Initial continue
    process.Continue()

    trace_count = 0
    iteration = 0

    while process.GetState() != lldb.eStateExited:
        iteration += 1
        current_state = process.GetState()

        if current_state == lldb.eStateStopped:
            thread = process.GetSelectedThread()
            stop_reason = thread.GetStopReason()

            if stop_reason == lldb.eStopReasonTrace:
                trace_count += 1
                print(f"[REGISTER_AUTO] ⚠️  TRACE MODE detected (iteration {iteration}, count {trace_count})")

                if trace_count > 10:
                    print("[REGISTER_AUTO] ❌ EXCESSIVE TRACE MODE - Phase 6A FAILED")
                    print("[REGISTER_AUTO] Register approach alone not sufficient")
                    print("[REGISTER_AUTO] Next: Test Phase 6B (register + delayed enable)")
                    break

            elif stop_reason == lldb.eStopReasonWatchpoint:
                print(f"[REGISTER_AUTO] ✓ Watchpoint hit (iteration {iteration})")

            elif stop_reason == lldb.eStopReasonBreakpoint:
                # Breakpoint hit, callbacks will handle it
                pass

            # Continue process
            process.Continue()

        time.sleep(0.05)  # Standard polling interval

    print("\n" + "="*70)
    print("[REGISTER_AUTO] Process exited")
    print("="*70)
    print(f"[REGISTER_AUTO] Total iterations: {iteration}")
    print(f"[REGISTER_AUTO] Trace mode count: {trace_count}")
    print(f"[REGISTER_AUTO] Watchpoint set: {_watchpoint_set}")
    print(f"[REGISTER_AUTO] Key extracted: {_key_value is not None}")
    print(f"[REGISTER_AUTO] Fork count: {_fork_count}")

    if trace_count == 0:
        print("\n[REGISTER_AUTO] ✅✅✅ PHASE 6A SUCCESS!")
        print("[REGISTER_AUTO] Register-based approach works like IPsec!")
        print("[REGISTER_AUTO] No symbolic navigation needed")
        print("[REGISTER_AUTO] Direct register reading is the key")
    elif trace_count <= 2:
        print("\n[REGISTER_AUTO] ⚠️  INCONCLUSIVE (minimal trace mode)")
        print("[REGISTER_AUTO] May need additional testing")
    else:
        print("\n[REGISTER_AUTO] ❌❌❌ PHASE 6A FAILED")
        print("[REGISTER_AUTO] Register approach alone not sufficient")
        print("[REGISTER_AUTO] Try Phase 6B: register + delayed enable")

    print("="*70)
