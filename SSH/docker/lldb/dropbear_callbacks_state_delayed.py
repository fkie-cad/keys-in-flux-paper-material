#!/usr/bin/env python3
"""
Dropbear State-Based Watchpoint - Phase 6C-Delayed

WATCHING PERSISTENT STATE STORAGE + DELAYED ENABLE (Backup Strategy)
=====================================================================

This combines the state-based approach (Phase 6C-Immediate) with
the delayed enable strategy (Phase 6B).

Rationale:
- Phase 6C-Immediate watches the RIGHT location (state->chacha, persistent)
- But as backup, test if memory needs stabilization time before enable
- If Phase 6C-Immediate succeeds, this test confirms timing isn't a factor
- If Phase 6C-Immediate fails, this tests if delay + location together help

Target Function: dropbear_chachapoly_start(cipher, IV, key, keylen, num_rounds, state)

ARM64 Register Layout:
  x0: cipher (unused)
  x1: IV (unused)
  x2: key pointer (temporary stack - DON'T watch this)
  x3: keylen (64 bytes)
  x4: num_rounds (unused)
  x5: ⭐ state pointer (persistent - WATCH THIS)

Method:
1. Breakpoint on dropbear_chachapoly_start ENTRY
2. Set one-shot EXIT breakpoint (using LR register)
3. On EXIT: key is now in state->chacha
4. Read x5 (state pointer) and x2 (original key)
5. Search for key within state structure memory
6. Create watchpoint DISABLED
7. Auto-continue loop waits 1.5 seconds
8. Verify memory stability
9. ENABLE watchpoint
10. Check for trace mode

Expected Outcomes:
  ✅ trace_count == 0 → Either location alone works (6C-Immediate) OR need both location+delay
  ❌ trace_count > 10 → Deeper problem (unlikely)

Key Difference from Phase 6C-Immediate:
  6C-Immediate: state-based + immediate enable
  6C-Delayed:   state-based + 1.5 second delay + enable

Key Difference from Phase 6B:
  6B:         stack-based (x2) + delay → Expected to fail
  6C-Delayed: state-based (x5) + delay → Expected to succeed
"""

import lldb
import time

# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_debugger = None
_target = None
_process = None
_entry_bp = None
_exit_bp = None
_watchpoint_obj = None
_watchpoint_set = False
_watchpoint_enabled = False
_trace_count = 0
_auto_continue_active = False
_fork_count = 0

# Extracted data
_key_address = 0
_state_ptr = 0
_key_data = None

# Results tracking
_results = {
    "test_name": "Phase 6C-Delayed: State-based + Delayed Enable",
    "watchpoint_created": False,
    "watchpoint_enabled": False,
    "watchpoint_hits": 0,
    "trace_hits": 0,
    "memory_verified": False,
    "delay_seconds": 0.5,
    "conclusion": "PENDING"
}


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY BREAKPOINT CALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def chachapoly_start_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry breakpoint: Set one-shot EXIT breakpoint using LR register

    CRITICAL: Read x2 (key) and x5 (state) HERE at ENTRY while they're valid!
    """
    global _debugger, _target, _process, _exit_bp, _key_data, _state_ptr

    print("\n" + "="*80)
    print("[STATE_ENTRY] dropbear_chachapoly_start() ENTRY")
    print("="*80)

    thread = frame.GetThread()
    process = thread.GetProcess()
    _process = process

    # ═══════════════════════════════════════════════════════════════════
    # CRITICAL FIX: Read x2 (key) and x5 (state) at ENTRY when valid!
    # ═══════════════════════════════════════════════════════════════════

    # Read x2 (key pointer) - MUST do this at entry while x2 is valid
    x2_reg = frame.FindRegister("x2")
    if x2_reg and x2_reg.IsValid():
        key_ptr = x2_reg.GetValueAsUnsigned()
        if key_ptr != 0:
            error = lldb.SBError()
            _key_data = process.ReadMemory(key_ptr, 64, error)  # Read 64 bytes
            if not error.Fail():
                print(f"[STATE_ENTRY] ✓ Stored key from x2 (64 bytes)")
            else:
                print(f"[STATE_ENTRY] WARNING: Could not read key: {error}")
                _key_data = None
        else:
            print(f"[STATE_ENTRY] WARNING: x2 is NULL")
            _key_data = None
    else:
        print(f"[STATE_ENTRY] WARNING: Could not read x2 register")
        _key_data = None

    # Read x5 (state pointer)
    x5_reg = frame.FindRegister("x5")
    if x5_reg and x5_reg.IsValid():
        _state_ptr = x5_reg.GetValueAsUnsigned()
        print(f"[STATE_ENTRY] ✓ Stored state pointer from x5: 0x{_state_ptr:x}")
    else:
        print(f"[STATE_ENTRY] WARNING: Could not read x5 register")
        _state_ptr = 0

    # Read LR (Link Register) to get return address
    lr_reg = frame.FindRegister("lr")
    if not lr_reg or not lr_reg.IsValid():
        print("[STATE_ENTRY] ❌ ERROR: Cannot read LR register")
        return False

    ret_addr = lr_reg.GetValueAsUnsigned()
    print(f"[STATE_ENTRY] LR (return address) = 0x{ret_addr:x}")

    # Create one-shot exit breakpoint at return address
    _exit_bp = _target.BreakpointCreateByAddress(ret_addr)
    _exit_bp.SetOneShot(True)
    _exit_bp.SetScriptCallbackFunction("dropbear_callbacks_state_delayed.chachapoly_start_exit_callback")

    print(f"[STATE_ENTRY] ✓ Exit breakpoint set at 0x{ret_addr:x}")
    print("[STATE_ENTRY] Continuing to function exit...")

    return False  # Continue execution


# ═══════════════════════════════════════════════════════════════════════════
# EXIT BREAKPOINT CALLBACK
# ═══════════════════════════════════════════════════════════════════════════

def chachapoly_start_exit_callback(frame, bp_loc, internal_dict):
    """
    Exit breakpoint: NOW key has been copied to state->chacha (persistent location)

    This is where we set the watchpoint on the DESTINATION (state) not SOURCE (key parameter).
    """
    global _debugger, _target, _process, _watchpoint_obj, _watchpoint_set, _watchpoint_enabled
    global _key_address, _state_ptr, _key_data, _results

    print("\n" + "="*80)
    print("[STATE_EXIT] dropbear_chachapoly_start() EXIT")
    print("[STATE_EXIT] Key has NOW been copied to state->chacha (persistent storage)")
    print("="*80)

    if _watchpoint_set:
        print("[STATE_EXIT] ⚠️ Watchpoint already set, skipping")
        return False

    # ═══════════════════════════════════════════════════════════════════
    # Use STORED state pointer (read at entry when valid)
    # ═══════════════════════════════════════════════════════════════════

    if not _state_ptr or _state_ptr == 0:
        print("[STATE_EXIT] ❌ ERROR: State pointer was not captured at entry")
        return False

    print(f"[STATE_EXIT] ✓ Using stored state pointer = 0x{_state_ptr:x}")

    # ═══════════════════════════════════════════════════════════════════
    # Use STORED key value (read at entry when x2 was valid)
    # ═══════════════════════════════════════════════════════════════════

    if not _key_data or len(_key_data) < 32:
        print("[STATE_EXIT] ❌ ERROR: Key was not captured at entry")
        return False

    original_key = bytes(_key_data[:32])  # First 32 bytes
    original_key_hex = original_key.hex()
    print(f"[STATE_EXIT] ✓ Using stored key (32 bytes): {original_key_hex[:64]}...")

    # Read state structure memory (search region)
    # ChaCha state is typically first 64-128 bytes of the structure
    state_mem_size = 512  # Read enough to find the key
    error = lldb.SBError()
    state_mem = _process.ReadMemory(_state_ptr, state_mem_size, error)
    if error.Fail():
        print(f"[STATE_EXIT] ❌ ERROR: Cannot read state memory: {error}")
        return False

    print(f"[STATE_EXIT] Read {state_mem_size} bytes from state structure")

    # Search for key within state structure
    key_offset = state_mem.find(original_key)
    if key_offset == -1:
        print("[STATE_EXIT] ❌ ERROR: Key not found in state structure")
        print(f"[STATE_EXIT] State memory (first 128 bytes): {state_mem[:128].hex()}")
        return False

    _key_address = _state_ptr + key_offset
    _key_data = original_key

    print(f"[STATE_EXIT] ✅ Key FOUND in state at offset {key_offset}")
    print(f"[STATE_EXIT] Absolute address: 0x{_key_address:x}")
    print(f"[STATE_EXIT] This is PERSISTENT storage (state->chacha)")

    # Create hardware watchpoint on the KEY WITHIN STATE (4-byte write, persistent)
    wp_error = lldb.SBError()
    _watchpoint_obj = _target.WatchAddress(_key_address, 1, False, True, wp_error)

    if wp_error.Fail() or not _watchpoint_obj.IsValid():
        print(f"[STATE_EXIT] ❌ ERROR: Failed to create watchpoint: {wp_error}")
        return False

    wp_id = _watchpoint_obj.GetID()
    print(f"[STATE_EXIT] ✅ Watchpoint {wp_id} created at 0x{_key_address:x}")
    print(f"[STATE_EXIT] Watching 1 bytes (write access)")

    # IMPORTANT: Create watchpoint DISABLED (will enable after delay)
    _watchpoint_obj.SetEnabled(False)
    _watchpoint_set = True
    _watchpoint_enabled = False
    _results["watchpoint_created"] = True

    print("[STATE_EXIT] ⏸️  Watchpoint created but DISABLED")
    print("[STATE_EXIT] Auto-continue loop will enable after 0.5 second delay")

    # Generate and inject watchpoint callback
    callback_name = f"wp_callback_{wp_id}"
    callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    """Watchpoint hit: Key in state->chacha was overwritten"""
    import dropbear_callbacks_state_delayed
    print("\\n" + "="*80)
    print("[STATE_WP] 🎯 WATCHPOINT HIT!")
    print("[STATE_WP] Key at 0x{_key_address:x} (state->chacha) was overwritten")
    print("="*80)

    dropbear_callbacks_state_delayed._results["watchpoint_hits"] += 1

    # Delete watchpoint (one-shot behavior)
    target = frame.GetThread().GetProcess().GetTarget()
    target.DeleteWatchpoint({wp_id})
    print("[STATE_WP] ✓ Watchpoint deleted (one-shot)")

    # Return False to disable (standard one-shot pattern)
    return False
'''

    _debugger.HandleCommand(f"script {callback_code}")
    _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")
    print(f"[STATE_EXIT] ✓ Watchpoint callback '{callback_name}' attached")

    print("[STATE_EXIT] Continuing execution...")
    return False


# ═══════════════════════════════════════════════════════════════════════════
# SETUP MONITORING
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup entry breakpoint on dropbear_chachapoly_start"""
    global _debugger, _target, _process, _entry_bp

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    if not _target.IsValid():
        print("[STATE_SETUP] ❌ ERROR: No valid target")
        return

    if not _process.IsValid():
        print("[STATE_SETUP] ❌ ERROR: No valid process")
        return

    print("\n" + "="*80)
    print("Version 1.0")
    print("Dropbear State-Based Watchpoint Setup - Phase 6C-Delayed")
    print("="*80)
    print("Strategy: Watch state->chacha (persistent) + DELAYED ENABLE (0.5s)")
    print("")
    print("Architecture: ARM64")
    print("Target Function: dropbear_chachapoly_start")
    print("Register Layout:")
    print("  x2 = key pointer (temporary stack - DON'T watch)")
    print("  x5 = state pointer (persistent - WATCH THIS)")
    print("")
    print("Method:")
    print("  1. Entry breakpoint → Set exit breakpoint via LR")
    print("  2. Exit breakpoint → Key now in state->chacha")
    print("  3. Create watchpoint DISABLED on state->chacha")
    print("  4. Wait 0.5 seconds (memory stabilization)")
    print("  5. Verify key still present")
    print("  6. ENABLE watchpoint")
    print("  7. Monitor for trace mode")
    print("="*80 + "\n")

    # Create ENTRY breakpoint using symbol (simpler than pattern matching)
    _entry_bp = _target.BreakpointCreateByName("dropbear_chachapoly_start")
    if _entry_bp.IsValid():
        _entry_bp.SetScriptCallbackFunction("dropbear_callbacks_state_delayed.chachapoly_start_entry_callback")
        print(f"[STATE_SETUP] ✓ Entry breakpoint {_entry_bp.GetID()} set on dropbear_chachapoly_start()")
        print("[STATE_SETUP] Entry callback will set EXIT breakpoint via LR register")
        print("[STATE_SETUP] Setup complete!")
        print("")
    else:
        print(f"[STATE_SETUP] ❌ ERROR: Could not set breakpoint on dropbear_chachapoly_start()")
        print(f"[STATE_SETUP] This is CRITICAL - cannot proceed without this function")
        return


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE LOOP
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """
    Auto-continue loop with watchpoint enable after delay

    This is the TWO-COMMAND pattern that allows watchpoints to work
    in automated mode:
      1. Setup command registers callbacks and breakpoints
      2. This command handles continuation and state polling

    The loop:
      - Detects stopped state
      - Checks if watchpoint needs delayed enable
      - Continues process
      - Monitors for trace mode
    """
    global _debugger, _target, _process, _watchpoint_obj, _watchpoint_enabled
    global _trace_count, _auto_continue_active, _results, _key_address, _key_data

    _auto_continue_active = True

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    # Initial continue
    process.Continue()
    print("[STATE_AUTO] ✅ Process RUNNING - entering keep-alive loop")
    print("[STATE_AUTO] Will enable watchpoint after 0.5 second delay")
    print("")

    delay_applied = False
    loop_start = time.time()

    while process.GetState() != lldb.eStateExited:
        current_state = process.GetState()

        # ═══════════════════════════════════════════════════════════════════
        # Check if watchpoint needs delayed enable (OUTSIDE stopped-state check)
        # This runs every loop iteration (0.1s) regardless of process state
        # ═══════════════════════════════════════════════════════════════════
        if _watchpoint_set and not _watchpoint_enabled and not delay_applied:
            elapsed = time.time() - loop_start

            if elapsed >= _results["delay_seconds"]:
                print("\n" + "="*80)
                print("[STATE_AUTO] ⏰ 0.5 second delay elapsed")
                print("[STATE_AUTO] Stopping process to enable watchpoint safely...")
                print("="*80)

                # Stop process first (safe state for enabling watchpoint)
                if current_state == lldb.eStateRunning:
                    process.Stop()
                    time.sleep(0.1)  # Brief wait for stop to complete

                # Verify memory stability (key should still be at same location)
                error = lldb.SBError()
                verify_data = process.ReadMemory(_key_address, 16, error)

                if not error.Fail():
                    verify_hex = verify_data.hex()
                    original_hex = _key_data[:16].hex() if _key_data else ""

                    if verify_hex == original_hex:
                        print(f"[STATE_AUTO] ✅ Memory STABLE (key unchanged)")
                        _results["memory_verified"] = True
                    else:
                        print(f"[STATE_AUTO] ⚠️ Memory CHANGED")
                        print(f"[STATE_AUTO]   Original: {original_hex}")
                        print(f"[STATE_AUTO]   Current:  {verify_hex}")

                # Enable watchpoint
                _watchpoint_obj.SetEnabled(True)
                _watchpoint_enabled = True
                _results["watchpoint_enabled"] = True

                print(f"[STATE_AUTO] ✅ Watchpoint ENABLED at 0x{_key_address:x}")
                print("[STATE_AUTO] Monitoring for key overwrites...")
                print("[STATE_AUTO] Resuming process...")
                print("")

                delay_applied = True

                # Resume process (will be handled by normal flow below)
                process.Continue()

        # ═══════════════════════════════════════════════════════════════════
        # Handle stopped state (trace mode detection, breakpoints, etc.)
        # ═══════════════════════════════════════════════════════════════════
        if current_state == lldb.eStateStopped:
            stop_reason = process.GetSelectedThread().GetStopReason()

            # Check for trace mode
            if stop_reason == lldb.eStopReasonTrace:
                _trace_count += 1
                _results["trace_hits"] += 1

                if _trace_count == 1:
                    print(f"\n[STATE_AUTO] ⚠️ TRACE MODE detected (stop reason = trace)")
                    print(f"[STATE_AUTO] This indicates single-step execution mode")

                # Suppress repeated trace messages (too verbose)
                if _trace_count <= 3 or _trace_count % 10 == 0:
                    print(f"[STATE_AUTO] Trace hit #{_trace_count}")

                # If trace mode persists, conclude failure
                if _trace_count >= 11:
                    print("\n" + "="*80)
                    print(f"[STATE_AUTO] ❌ PHASE 6C-DELAYED FAILED")
                    print(f"[STATE_AUTO] Persistent trace mode detected ({_trace_count}+ trace hits)")
                    print("[STATE_AUTO] Even with state-based watching + delay, trace mode occurred")
                    print("="*80 + "\n")
                    _results["conclusion"] = "FAILED - Trace mode despite state-based + delay"
                    break

            # Continue execution
            process.Continue()

        time.sleep(0.1)  # Brief sleep to avoid busy-waiting

    # Process exited
    print("\n" + "="*80)
    print("[STATE_AUTO] Process EXITED")
    print("="*80)

    # Print final results
    print("\nPhase 6C-Delayed Test Results:")
    print("="*80)
    print("version 1.0")
    print(f"Test: {_results['test_name']}")
    print(f"Watchpoint created: {_results['watchpoint_created']}")
    print(f"Watchpoint enabled: {_results['watchpoint_enabled']}")
    print(f"Memory verified: {_results['memory_verified']}")
    print(f"Delay applied: {_results['delay_seconds']} seconds")
    print(f"Watchpoint hits: {_results['watchpoint_hits']}")
    print(f"Trace hits: {_results['trace_hits']}")
    print("")

    if _results["trace_hits"] == 0 and _results["watchpoint_enabled"]:
        print("✅ SUCCESS - No trace mode with state-based watching + delay!")
        print("   Conclusion: Need BOTH persistent location AND delay")
        _results["conclusion"] = "SUCCESS - State-based + delay works"
    elif _results["trace_hits"] == 0 and not _results["watchpoint_enabled"]:
        print("⚠️  INCOMPLETE - Watchpoint never enabled")
        _results["conclusion"] = "INCOMPLETE - Watchpoint enable failed"
    else:
        print(f"❌ FAILED - Trace mode occurred ({_results['trace_hits']} trace hits)")
        _results["conclusion"] = "FAILED - Trace mode despite state-based + delay"

    print("="*80 + "\n")


# ═══════════════════════════════════════════════════════════════════════════
# LLDB INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def __lldb_init_module(debugger, internal_dict):
    """
    Called automatically when LLDB imports this script

    Registers two commands:
      1. dropbear_setup_monitoring - Creates breakpoints
      2. dropbear_auto_continue - Runs keep-alive loop with delayed enable

    This two-command pattern is REQUIRED for watchpoints in batch mode.
    """
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_state_delayed.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_state_delayed.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[LLDB] Dropbear Phase 6C-Delayed callbacks loaded")
    print("[LLDB] version 1.0")
    print("[LLDB] Commands: dropbear_setup_monitoring, dropbear_auto_continue")
