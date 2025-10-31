#!/usr/bin/env python3
"""
Dropbear Test: Immediate Watchpoint Disable

HYPOTHESIS 3 VALIDATION TEST
============================
Tests if disabling watchpoint immediately after creation prevents trace mode.

Theory: LLDB's watchpoint disable/reenable cycle during single-step resume
corrupts ARM64 debug registers (MDSCR_EL1 SS bit), causing infinite trace mode.

Test Method:
1. Extract keys (same as minimal)
2. Create watchpoint (same as minimal)
3. **IMMEDIATELY disable watchpoint** before auto-continue
4. Check if trace mode still occurs

Expected Outcomes:
- If trace_count == 0: Problem is ACTIVE watchpoint monitoring ✅
- If trace_count > 10: Problem is watchpoint CREATION itself ❌

This helps narrow down:
- Creation corruption (immediate disable doesn't help)
- vs Active monitoring corruption (immediate disable fixes it)

Changes from dropbear_callbacks_test_nosigchld.py:
- Removed SIGCHLD blocking (proven ineffective)
- Added watchpoint.SetEnabled(False) immediately after creation
- Otherwise identical structure
"""

import lldb
import time
import os

# ═══════════════════════════════════════════════════════════════════════════
# MINIMAL GLOBAL STATE (matching Test 3 pattern)
# ═══════════════════════════════════════════════════════════════════════════

_fork_count = 0
_watchpoint_set = False
_watchpoint_disabled = False
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
        'command script add -f dropbear_callbacks_test_disable_wp.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_test_disable_wp.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[TEST_DISABLE_WP] Commands registered: dropbear_setup_monitoring, dropbear_auto_continue")

# ═══════════════════════════════════════════════════════════════════════════
# FORK CALLBACK (Test 3 pattern - immediate fork-mode switching)
# ═══════════════════════════════════════════════════════════════════════════

def fork_callback(frame, bp_loc, internal_dict):
    """Fork breakpoint - switch fork-mode immediately (Test 3 pattern)"""
    global _fork_count, _debugger, _process

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    _fork_count += 1

    print(f"\n[TEST_DISABLE_WP_FORK] Fork #{_fork_count} detected in PID {pid}")

    if _fork_count == 1:
        # Fork #1: Parent → Connection handler
        print(f"[TEST_DISABLE_WP_FORK] This is FORK #1: Parent → Child1 (connection handler)")
        print(f"[TEST_DISABLE_WP_FORK] LLDB will follow child (connection handler)")
        print(f"[TEST_DISABLE_WP_FORK] After this fork, will switch to 'parent' mode")

    elif _fork_count == 2:
        # Fork #2: Connection handler → Session child
        # CRITICAL: Switch fork-mode NOW (immediately, like Test 3)
        print(f"[TEST_DISABLE_WP_FORK] This is FORK #2: Child1 → Child2 (session)")
        print(f"[TEST_DISABLE_WP_FORK] Switching to PARENT mode NOW (stay with Child1)")

        # Use debugger object to switch mode
        if _debugger:
            _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
            print(f"[TEST_DISABLE_WP_FORK] ✓ Fork-mode switched to PARENT")
        else:
            print(f"[TEST_DISABLE_WP_FORK] ⚠️  WARNING: No debugger object, cannot switch fork-mode")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# KEY DERIVATION CALLBACK (Set watchpoint here)
# ═══════════════════════════════════════════════════════════════════════════

def kex_derive_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint on gen_new_keys - set exit breakpoint for key extraction"""
    global _fork_count, _target, _debugger

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[TEST_DISABLE_WP_KEX_ENTRY] gen_new_keys() ENTRY in PID {pid} (fork count: {_fork_count})")

    # Only set exit breakpoint after fork #1 (when in connection handler)
    if _fork_count < 1:
        print(f"[TEST_DISABLE_WP_KEX_ENTRY] Skipping - waiting for fork #1")
        return False

    # Set one-shot breakpoint at function return address (ARM64 pattern)
    print(f"[TEST_DISABLE_WP_KEX_ENTRY] Setting exit breakpoint...")

    # On ARM64, return address is in LR (link register)
    lr = frame.FindRegister("lr")
    if lr:
        ret_addr = lr.GetValueAsUnsigned()
        print(f"[TEST_DISABLE_WP_KEX_ENTRY] Return address from LR: 0x{ret_addr:x}")

        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)  # Fire once and auto-delete
        bp.SetScriptCallbackFunction("dropbear_callbacks_test_disable_wp.kex_derive_keys_exit")
        bp.SetAutoContinue(False)  # Don't auto-continue, let callback handle it
        print(f"[TEST_DISABLE_WP_KEX_ENTRY] ✓ Exit breakpoint set (bp {bp.GetID()}, one-shot)")
    else:
        print(f"[TEST_DISABLE_WP_KEX_ENTRY] ERROR: Could not read LR register")

    return False

def kex_derive_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys - extract keys and test immediate disable"""
    global _watchpoint_set, _watchpoint_disabled, _key_address, _key_value, _target, _debugger, _process, _fork_count

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[TEST_DISABLE_WP_KEX_EXIT] gen_new_keys() EXIT in PID {pid} (keys should be populated now)")

    if _watchpoint_set:
        print(f"[TEST_DISABLE_WP_KEX_EXIT] Watchpoint already set, skipping")
        return False

    print(f"[TEST_DISABLE_WP_KEX_EXIT] Extracting trans_cipher_key...")

    # Extract trans_cipher_key from ses.newkeys->trans.cipher_key
    # This uses the same extraction logic as Test 3's watched_value address lookup

    try:
        # Get ses global variable
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print("[TEST_DISABLE_WP_KEX] ERROR: Could not find 'ses' global")
            return False

        ses = ses_list.GetValueAtIndex(0)

        # Navigate: ses.newkeys (pointer)
        newkeys_var = ses.GetChildMemberWithName("newkeys")
        if not newkeys_var.IsValid():
            print("[TEST_DISABLE_WP_KEX] ERROR: Could not get ses.newkeys")
            return False

        # Get pointer address
        newkeys_addr = newkeys_var.GetValueAsUnsigned()
        if newkeys_addr == 0:
            print("[TEST_DISABLE_WP_KEX] ERROR: newkeys is NULL")
            return False

        print(f"[TEST_DISABLE_WP_KEX] Found ses.newkeys at 0x{newkeys_addr:x}")

        # Dereference pointer and get trans structure (v2 pattern)
        trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
        if not trans_var.IsValid():
            print("[TEST_DISABLE_WP_KEX] ERROR: Could not get newkeys->trans")
            return False

        # Get trans.cipher_state (union containing actual keys)
        trans_cipher_state = trans_var.GetChildMemberWithName("cipher_state")
        if not trans_cipher_state.IsValid():
            print("[TEST_DISABLE_WP_KEX] ERROR: Could not get trans.cipher_state")
            return False

        # Get cipher_state address and read raw memory
        trans_cipher_addr = trans_cipher_state.GetLoadAddress()
        print(f"[TEST_DISABLE_WP_KEX] trans.cipher_state at 0x{trans_cipher_addr:x}")

        # Read 80 bytes: ChaCha20-Poly1305 structure
        # 0-15: "expand 32-byte k" constant
        # 16-47: ChaCha20 key (32 bytes)
        # 48-79: Poly1305 key (32 bytes)
        error = lldb.SBError()
        trans_cipher_data = process.ReadMemory(trans_cipher_addr, 80, error)
        if not error.Success():
            print(f"[TEST_DISABLE_WP_KEX] ERROR reading cipher_state: {error}")
            return False

        # Check for ChaCha20-Poly1305 pattern
        if trans_cipher_data[:16] == b"expand 32-byte k":
            # Extract ChaCha20 key (bytes 16-47)
            _key_value = trans_cipher_data[16:48]
            _key_address = trans_cipher_addr + 16
            print(f"[TEST_DISABLE_WP_KEX] ✓ ChaCha20 key at 0x{_key_address:x}")
            print(f"[TEST_DISABLE_WP_KEX] Key preview: {_key_value.hex()[:32]}... (32 bytes)")
            print(f"[TEST_DISABLE_WP_KEX] Full key: {_key_value.hex()}")
        else:
            print(f"[TEST_DISABLE_WP_KEX] ERROR: cipher_state doesn't match ChaCha20 pattern")
            print(f"[TEST_DISABLE_WP_KEX] First 16 bytes: {trans_cipher_data[:16].hex()}")
            return False

        # ═══════════════════════════════════════════════════════════════════
        # HYPOTHESIS 3 TEST: Immediate Watchpoint Disable
        # ═══════════════════════════════════════════════════════════════════

        print(f"\n[TEST_DISABLE_WP_KEX] ═══════════════════════════════════════════")
        print(f"[TEST_DISABLE_WP_KEX] HYPOTHESIS 3 TEST: Immediate Watchpoint Disable")
        print(f"[TEST_DISABLE_WP_KEX] ═══════════════════════════════════════════")

        # Create watchpoint (same as minimal)
        print(f"[TEST_DISABLE_WP_KEX] Creating watchpoint...")
        wp_error = lldb.SBError()
        watchpoint = _target.WatchAddress(_key_address, 1, False, True, wp_error)

        if not wp_error.Success():
            print(f"[TEST_DISABLE_WP_KEX] ERROR: Watchpoint failed: {wp_error}")
            return False

        wp_id = watchpoint.GetID()
        print(f"[TEST_DISABLE_WP_KEX] ✓ Watchpoint {wp_id} created at 0x{_key_address:x}")

        # Inject one-shot callback (for completeness, though it should never fire)
        callback_name = f"disable_wp_cb_{wp_id}"
        callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    print("\\n[TEST_DISABLE_WP_WP] 🎯 WATCHPOINT HIT (unexpected!)")
    print(f"[TEST_DISABLE_WP_WP] This should NOT fire if watchpoint is disabled")
    print(f"[TEST_DISABLE_WP_WP] PID: {{frame.GetThread().GetProcess().GetProcessID()}}")
    print(f"[TEST_DISABLE_WP_WP] PC: 0x{{frame.GetPC():x}}")
    return False
"""

        _debugger.HandleCommand(f"script {callback_code}")
        _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")
        print(f"[TEST_DISABLE_WP_KEX] ✓ One-shot callback attached")

        # ⭐ KEY TEST: DISABLE WATCHPOINT IMMEDIATELY
        print(f"\n[TEST_DISABLE_WP_KEX] ⭐ DISABLING watchpoint IMMEDIATELY...")
        watchpoint.SetEnabled(False)
        _watchpoint_disabled = True

        # Verify it's disabled
        if not watchpoint.IsEnabled():
            print(f"[TEST_DISABLE_WP_KEX] ✓ Watchpoint {wp_id} is now DISABLED")
            print(f"[TEST_DISABLE_WP_KEX] Watchpoint exists but will NOT monitor memory")
        else:
            print(f"[TEST_DISABLE_WP_KEX] ⚠️  WARNING: Watchpoint still shows as enabled")

        print(f"[TEST_DISABLE_WP_KEX] ═══════════════════════════════════════════\n")

        _watchpoint_set = True

    except Exception as e:
        print(f"[TEST_DISABLE_WP_KEX] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND (Register breakpoints)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup minimal monitoring with immediate watchpoint disable test"""
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[TEST_DISABLE_WP] Dropbear Immediate Watchpoint Disable Test")
    print("[TEST_DISABLE_WP] HYPOTHESIS 3 VALIDATION")
    print("="*70)
    print("[TEST_DISABLE_WP] Tests if immediate disable prevents trace mode")
    print("[TEST_DISABLE_WP]")
    print("[TEST_DISABLE_WP] Expected Outcomes:")
    print("[TEST_DISABLE_WP]  ✅ trace_count == 0 → Active monitoring is the problem")
    print("[TEST_DISABLE_WP]  ❌ trace_count > 10 → Watchpoint creation itself corrupts state")
    print("="*70)

    # Set follow-fork-mode to CHILD initially (to follow fork #1)
    print("[TEST_DISABLE_WP] Setting initial follow-fork-mode: CHILD")
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")

    # Breakpoint 1: fork() - to detect forks and switch modes
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("dropbear_callbacks_test_disable_wp.fork_callback")
        print(f"[TEST_DISABLE_WP] ✓ Breakpoint on fork() (ID {fork_bp.GetID()})")
    else:
        print(f"[TEST_DISABLE_WP] ⚠️  Could not set breakpoint on fork()")

    # Breakpoint 2: gen_new_keys ENTRY - sets exit breakpoint for key extraction
    kex_bp = _target.BreakpointCreateByName("gen_new_keys")
    if kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("dropbear_callbacks_test_disable_wp.kex_derive_keys_entry")
        print(f"[TEST_DISABLE_WP] ✓ Breakpoint on gen_new_keys() ENTRY (ID {kex_bp.GetID()})")
    else:
        print(f"[TEST_DISABLE_WP] ⚠️  Could not set breakpoint on gen_new_keys()")

    print("[TEST_DISABLE_WP] Setup complete - ready for auto_continue")
    print("[TEST_DISABLE_WP] Watchpoint will be DISABLED immediately after creation")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND (Keep-alive loop with trace detection)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop with trace mode detection (Test 3 pattern)"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[TEST_DISABLE_WP_AUTO] Starting auto-continue loop")
    print("[TEST_DISABLE_WP_AUTO] Monitoring for trace mode...")
    print("[TEST_DISABLE_WP_AUTO] Expecting ZERO if immediate disable prevents trace mode")

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
                print(f"[TEST_DISABLE_WP_AUTO] ⚠️  TRACE MODE detected (iteration {iteration}, count {trace_count})")

                if trace_count > 10:
                    print("[TEST_DISABLE_WP_AUTO] ❌ EXCESSIVE TRACE MODE - Hypothesis 3 REJECTED")
                    print("[TEST_DISABLE_WP_AUTO] Watchpoint CREATION itself corrupts debug state")
                    print("[TEST_DISABLE_WP_AUTO] Problem is not active monitoring")
                    break

            elif stop_reason == lldb.eStopReasonWatchpoint:
                print(f"[TEST_DISABLE_WP_AUTO] ⚠️  Watchpoint hit (unexpected - should be disabled!)")

            elif stop_reason == lldb.eStopReasonBreakpoint:
                # Breakpoint hit, callbacks will handle it
                pass

            # Continue process
            process.Continue()

        time.sleep(0.05)  # Match Test 3 polling interval

    print("\n" + "="*70)
    print("[TEST_DISABLE_WP_AUTO] Process exited")
    print("="*70)
    print(f"[TEST_DISABLE_WP_AUTO] Total iterations: {iteration}")
    print(f"[TEST_DISABLE_WP_AUTO] Trace mode count: {trace_count}")
    print(f"[TEST_DISABLE_WP_AUTO] Watchpoint set: {_watchpoint_set}")
    print(f"[TEST_DISABLE_WP_AUTO] Watchpoint disabled: {_watchpoint_disabled}")
    print(f"[TEST_DISABLE_WP_AUTO] Key extracted: {_key_value is not None}")

    if trace_count == 0:
        print("\n[TEST_DISABLE_WP_AUTO] ✅✅✅ HYPOTHESIS 3 CONFIRMED (partial)!")
        print("[TEST_DISABLE_WP_AUTO] Immediate disable prevented trace mode")
        print("[TEST_DISABLE_WP_AUTO] Problem is ACTIVE watchpoint monitoring, not creation")
        print("[TEST_DISABLE_WP_AUTO] Next: Investigate watchpoint enable/disable cycle")
    elif trace_count <= 2:
        print("\n[TEST_DISABLE_WP_AUTO] ⚠️  INCONCLUSIVE (minimal trace mode)")
        print("[TEST_DISABLE_WP_AUTO] May need additional testing")
    else:
        print("\n[TEST_DISABLE_WP_AUTO] ❌❌❌ HYPOTHESIS 3 REJECTED")
        print("[TEST_DISABLE_WP_AUTO] Immediate disable did NOT prevent trace mode")
        print("[TEST_DISABLE_WP_AUTO] Watchpoint CREATION itself corrupts debug state")
        print("[TEST_DISABLE_WP_AUTO] This is a deeper LLDB/ARM64 issue")

    print("="*70)
