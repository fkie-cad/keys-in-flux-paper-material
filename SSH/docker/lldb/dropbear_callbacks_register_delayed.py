#!/usr/bin/env python3
"""
Dropbear Register-Based Watchpoint with Delayed Enable - Phase 6B

REGISTER-BASED + DELAYED ENABLE STRATEGY
==========================================

Combines two successful patterns:
1. Register-based extraction (like IPsec - avoids symbolic navigation)
2. Delayed enable (like Phase 5 - watchpoint created disabled, enabled after delay)

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
3. Read and print 64 bytes at that address
4. Create watchpoint DISABLED
5. DELAY 1.5 seconds (wait for fork #2, NEWKEYS exchange to complete)
6. RE-READ first 16 bytes to verify memory stability
7. ENABLE watchpoint
8. Check for trace mode

Expected Outcomes:
  ✅ trace_count == 0 → Need BOTH register approach AND timing delay
  ❌ trace_count > 10 → Problem is deeper than expected
"""

import lldb
import time
import os

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_fork_count = 0
_watchpoint_set = False
_watchpoint_enabled = False
_key_address = None
_key_value = None
_watchpoint_obj = None

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
        'command script add -f dropbear_callbacks_register_delayed.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_register_delayed.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[REGISTER_DELAY] Commands registered: dropbear_setup_monitoring, dropbear_auto_continue")

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

    print(f"\n[REGISTER_DELAY_FORK] Fork #{_fork_count} detected in PID {pid}")

    if _fork_count == 1:
        print(f"[REGISTER_DELAY_FORK] This is FORK #1: Parent → Connection handler")
    elif _fork_count == 2:
        print(f"[REGISTER_DELAY_FORK] This is FORK #2: Connection handler → Session")
        # Switch to parent mode to stay with connection handler
        if _debugger:
            _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
            print(f"[REGISTER_DELAY_FORK] ✓ Fork-mode switched to PARENT")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# CHACHAPOLY START CALLBACK (Register-based with delayed enable)
# ═══════════════════════════════════════════════════════════════════════════

def chachapoly_start_callback(frame, bp_loc, internal_dict):
    """
    Callback for dropbear_chachapoly_start(cipher, IV, key, keylen, num_rounds, state)

    Extracts key address from x2 register, creates watchpoint DISABLED,
    then delegates to auto_continue loop for delayed enable.
    """
    global _watchpoint_set, _watchpoint_obj, _key_address, _key_value, _target, _debugger, _process, _fork_count

    if _watchpoint_set:
        print(f"[REGISTER_DELAY] Watchpoint already set, skipping")
        return False

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[REGISTER_DELAY] dropbear_chachapoly_start() ENTRY in PID {pid} (fork count: {_fork_count})")
    print(f"[REGISTER_DELAY] Using REGISTER-BASED extraction + DELAYED ENABLE")

    try:
        # ═══════════════════════════════════════════════════════════════════
        # STEP 1: Read x2 register to get key pointer (ARM64 arg2)
        # ═══════════════════════════════════════════════════════════════════

        x2_reg = frame.FindRegister("x2")
        if not x2_reg or not x2_reg.IsValid():
            print(f"[REGISTER_DELAY] ERROR: Could not read x2 register")
            return False

        key_ptr = x2_reg.GetValueAsUnsigned()
        if key_ptr == 0:
            print(f"[REGISTER_DELAY] ERROR: x2 register is NULL")
            return False

        print(f"[REGISTER_DELAY] ✓ x2 (key pointer) = 0x{key_ptr:x}")

        # ═══════════════════════════════════════════════════════════════════
        # STEP 2: Read x3 register to verify keylen (should be 64)
        # ═══════════════════════════════════════════════════════════════════

        x3_reg = frame.FindRegister("x3")
        if x3_reg and x3_reg.IsValid():
            keylen = x3_reg.GetValueAsUnsigned()
            print(f"[REGISTER_DELAY] ✓ x3 (keylen) = {keylen} bytes")
            if keylen != 64:
                print(f"[REGISTER_DELAY] ⚠️  WARNING: Expected keylen=64, got {keylen}")

        # ═══════════════════════════════════════════════════════════════════
        # STEP 3: Read 64 bytes from key pointer
        # ═══════════════════════════════════════════════════════════════════

        error = lldb.SBError()
        key_data = process.ReadMemory(key_ptr, 64, error)

        if not error.Success():
            print(f"[REGISTER_DELAY] ERROR reading key memory: {error}")
            return False

        if len(key_data) != 64:
            print(f"[REGISTER_DELAY] ERROR: Only read {len(key_data)} bytes, expected 64")
            return False

        # First 32 bytes: Main ChaCha20 encryption key
        # Second 32 bytes: Header encryption key
        main_key = key_data[:32]
        header_key = key_data[32:64]

        print(f"[REGISTER_DELAY] ✓ Read 64 bytes from 0x{key_ptr:x}")
        print(f"[REGISTER_DELAY] Main encryption key (first 32 bytes):")
        print(f"[REGISTER_DELAY]   {main_key.hex()}")
        print(f"[REGISTER_DELAY] Header encryption key (second 32 bytes):")
        print(f"[REGISTER_DELAY]   {header_key.hex()}")

        _key_address = key_ptr
        _key_value = main_key

        # ═══════════════════════════════════════════════════════════════════
        # STEP 4: Create watchpoint DISABLED (will enable after delay)
        # ═══════════════════════════════════════════════════════════════════

        print(f"\n[REGISTER_DELAY] Creating watchpoint DISABLED...")
        print(f"[REGISTER_DELAY] Address: 0x{key_ptr:x} (from x2 register)")
        print(f"[REGISTER_DELAY] Mode: DELAYED ENABLE (Phase 6B)")

        wp_error = lldb.SBError()
        watchpoint = _target.WatchAddress(key_ptr, 4, False, True, wp_error)

        if not wp_error.Success():
            print(f"[REGISTER_DELAY] ERROR: Watchpoint failed: {wp_error}")
            return False

        wp_id = watchpoint.GetID()
        print(f"[REGISTER_DELAY] ✓ Watchpoint {wp_id} created at 0x{key_ptr:x}")

        # Inject one-shot callback (IPsec pattern)
        callback_name = f"register_delay_wp_cb_{wp_id}"
        callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    print("\\n[REGISTER_DELAY_WP] 🎯 WATCHPOINT HIT!")
    print(f"[REGISTER_DELAY_WP] Key at 0x{key_ptr:x} was overwritten")
    print(f"[REGISTER_DELAY_WP] PID: {{frame.GetThread().GetProcess().GetProcessID()}}")
    print(f"[REGISTER_DELAY_WP] PC: 0x{{frame.GetPC():x}}")
    print("[REGISTER_DELAY_WP] One-shot: Returning False to disable")
    return False
"""

        _debugger.HandleCommand(f"script {callback_code}")
        _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")
        print(f"[REGISTER_DELAY] ✓ One-shot callback attached")

        # DISABLE the watchpoint immediately
        watchpoint.SetEnabled(False)
        _watchpoint_obj = watchpoint
        print(f"[REGISTER_DELAY] ✓ Watchpoint {wp_id} is now DISABLED")
        print(f"[REGISTER_DELAY] Will enable after 1.5 second delay in auto_continue loop")

        _watchpoint_set = True

        print(f"\n[REGISTER_DELAY] Register-based extraction complete")
        print(f"[REGISTER_DELAY] Watchpoint ready for delayed enable")

    except Exception as e:
        print(f"[REGISTER_DELAY] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND (Register breakpoints)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup register-based monitoring with delayed enable (Phase 6B)"""
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[REGISTER_DELAY] Dropbear Register-Based + Delayed Enable - Phase 6B")
    print("[REGISTER_DELAY] DELAYED ENABLE (1.5 second delay)")
    print("="*70)
    print("[REGISTER_DELAY] Combining two strategies:")
    print("[REGISTER_DELAY]  1. Register-based extraction (like IPsec)")
    print("[REGISTER_DELAY]  2. Delayed enable (like Phase 5)")
    print("[REGISTER_DELAY]")
    print("[REGISTER_DELAY] Expected Outcomes:")
    print("[REGISTER_DELAY]  ✅ trace_count == 0 → Need both register + delay")
    print("[REGISTER_DELAY]  ❌ trace_count > 10 → Problem is deeper")
    print("="*70)

    # Set follow-fork-mode to CHILD initially (to follow fork #1)
    print("[REGISTER_DELAY] Setting initial follow-fork-mode: CHILD")
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")

    # Breakpoint 1: fork() - to detect forks and switch modes
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("dropbear_callbacks_register_delayed.fork_callback")
        print(f"[REGISTER_DELAY] ✓ Breakpoint on fork() (ID {fork_bp.GetID()})")
    else:
        print(f"[REGISTER_DELAY] ⚠️  Could not set breakpoint on fork()")

    # Breakpoint 2: dropbear_chachapoly_start - register-based key extraction
    chachapoly_bp = _target.BreakpointCreateByName("dropbear_chachapoly_start")
    if chachapoly_bp.IsValid():
        chachapoly_bp.SetScriptCallbackFunction("dropbear_callbacks_register_delayed.chachapoly_start_callback")
        print(f"[REGISTER_DELAY] ✓ Breakpoint on dropbear_chachapoly_start() (ID {chachapoly_bp.GetID()})")
    else:
        print(f"[REGISTER_DELAY] ⚠️  Could not set breakpoint on dropbear_chachapoly_start()")
        print(f"[REGISTER_DELAY] This is CRITICAL - cannot proceed without this function")

    print("[REGISTER_DELAY] Setup complete - ready for auto_continue")
    print("[REGISTER_DELAY] Watchpoint will be created disabled, then enabled after delay")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND (Keep-alive loop with delayed enable logic)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop with watchpoint delayed enable and trace detection"""
    global _watchpoint_set, _watchpoint_enabled, _watchpoint_obj, _key_address, _process

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[REGISTER_DELAY_AUTO] Starting auto-continue loop")
    print("[REGISTER_DELAY_AUTO] Will enable watchpoint after 1.5 second delay")
    print("[REGISTER_DELAY_AUTO] Monitoring for trace mode...")

    # Initial continue
    process.Continue()

    trace_count = 0
    iteration = 0
    delay_applied = False

    while process.GetState() != lldb.eStateExited:
        iteration += 1
        current_state = process.GetState()

        # ═══════════════════════════════════════════════════════════════════
        # DELAYED ENABLE LOGIC: After watchpoint set, wait and enable
        # ═══════════════════════════════════════════════════════════════════

        if _watchpoint_set and not _watchpoint_enabled and not delay_applied:
            print(f"\n[REGISTER_DELAY_AUTO] Watchpoint created disabled")
            print(f"[REGISTER_DELAY_AUTO] Waiting 1.5 seconds for process stabilization...")
            time.sleep(1.5)
            delay_applied = True

            # Re-read first 16 bytes to verify memory stability
            error = lldb.SBError()
            verify_data = process.ReadMemory(_key_address, 16, error)
            if error.Success():
                print(f"[REGISTER_DELAY_AUTO] After delay, first 16 bytes:")
                print(f"[REGISTER_DELAY_AUTO]   {verify_data.hex()}")

                # Compare with original
                if _key_value and verify_data == _key_value[:16]:
                    print(f"[REGISTER_DELAY_AUTO] ✓ Memory STABLE (matches original)")
                else:
                    print(f"[REGISTER_DELAY_AUTO] ⚠️  Memory CHANGED during delay!")
            else:
                print(f"[REGISTER_DELAY_AUTO] ⚠️  Could not re-read memory: {error}")

            # ENABLE the watchpoint NOW
            if _watchpoint_obj:
                _watchpoint_obj.SetEnabled(True)
                print(f"\n[REGISTER_DELAY_AUTO] ✓ Watchpoint ENABLED after delay")
                print(f"[REGISTER_DELAY_AUTO] Watchpoint ID: {_watchpoint_obj.GetID()}")
                print(f"[REGISTER_DELAY_AUTO] Address: 0x{_key_address:x}")
                _watchpoint_enabled = True
            else:
                print(f"[REGISTER_DELAY_AUTO] ERROR: No watchpoint object to enable")

        # ═══════════════════════════════════════════════════════════════════

        if current_state == lldb.eStateStopped:
            thread = process.GetSelectedThread()
            stop_reason = thread.GetStopReason()

            if stop_reason == lldb.eStopReasonTrace:
                trace_count += 1
                print(f"[REGISTER_DELAY_AUTO] ⚠️  TRACE MODE detected (iteration {iteration}, count {trace_count})")

                if trace_count > 10:
                    print("[REGISTER_DELAY_AUTO] ❌ EXCESSIVE TRACE MODE - Phase 6B FAILED")
                    print("[REGISTER_DELAY_AUTO] Register + delay combination not sufficient")
                    print("[REGISTER_DELAY_AUTO] Problem may be deeper than expected")
                    break

            elif stop_reason == lldb.eStopReasonWatchpoint:
                print(f"[REGISTER_DELAY_AUTO] ✓ Watchpoint hit (iteration {iteration})")

            elif stop_reason == lldb.eStopReasonBreakpoint:
                # Breakpoint hit, callbacks will handle it
                pass

            # Continue process
            process.Continue()

        time.sleep(0.05)  # Standard polling interval

    print("\n" + "="*70)
    print("[REGISTER_DELAY_AUTO] Process exited")
    print("="*70)
    print(f"[REGISTER_DELAY_AUTO] Total iterations: {iteration}")
    print(f"[REGISTER_DELAY_AUTO] Trace mode count: {trace_count}")
    print(f"[REGISTER_DELAY_AUTO] Watchpoint set: {_watchpoint_set}")
    print(f"[REGISTER_DELAY_AUTO] Watchpoint enabled: {_watchpoint_enabled}")
    print(f"[REGISTER_DELAY_AUTO] Key extracted: {_key_value is not None}")
    print(f"[REGISTER_DELAY_AUTO] Fork count: {_fork_count}")

    if trace_count == 0:
        print("\n[REGISTER_DELAY_AUTO] ✅✅✅ PHASE 6B SUCCESS!")
        print("[REGISTER_DELAY_AUTO] Register + delayed enable combination works!")
        print("[REGISTER_DELAY_AUTO] Need BOTH: register-based extraction AND timing delay")
    elif trace_count <= 2:
        print("\n[REGISTER_DELAY_AUTO] ⚠️  INCONCLUSIVE (minimal trace mode)")
        print("[REGISTER_DELAY_AUTO] May need additional testing")
    else:
        print("\n[REGISTER_DELAY_AUTO] ❌❌❌ PHASE 6B FAILED")
        print("[REGISTER_DELAY_AUTO] Register + delay not sufficient")
        print("[REGISTER_DELAY_AUTO] Problem is deeper than expected")

    print("="*70)
