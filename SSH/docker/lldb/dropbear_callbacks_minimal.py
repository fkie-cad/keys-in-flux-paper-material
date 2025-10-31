#!/usr/bin/env python3
"""
Dropbear Minimal Callbacks - Based on Successful Test 3 Pattern

This simplified version replicates the exact pattern from test_fork2.py which
successfully ran hardware watchpoints with double-fork + fork-mode switching
WITHOUT any trace mode issues.

Key differences from dropbear_callbacks_v2.py:
- Only 2 breakpoints (fork + key derivation) vs 10+
- Immediate fork-mode switching at fork callback
- Single watchpoint (trans_cipher_key) vs 4
- No memory dumps
- Minimal global state

If this works, incrementally add features to identify what causes trace mode.
"""

import lldb
import time
import os

# ═══════════════════════════════════════════════════════════════════════════
# MINIMAL GLOBAL STATE (matching Test 3 pattern)
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
    print("[MINIMAL] Initializing dropbear_callbacks_minimal module ...")
    print("[MINIMAL] Version 1.0")
    """Called when script is imported by LLDB"""
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_minimal.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_minimal.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[MINIMAL] Commands registered: dropbear_setup_monitoring, dropbear_auto_continue")

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

    print(f"\n[MINIMAL_FORK] Fork #{_fork_count} detected in PID {pid}")

    if _fork_count == 1:
        # Fork #1: Parent → Connection handler
        print(f"[MINIMAL_FORK] This is FORK #1: Parent → Child1 (connection handler)")
        print(f"[MINIMAL_FORK] LLDB will follow child (connection handler)")
        print(f"[MINIMAL_FORK] After this fork, will switch to 'parent' mode")

    elif _fork_count == 2:
        # Fork #2: Connection handler → Session child
        # CRITICAL: Switch fork-mode NOW (immediately, like Test 3)
        print(f"[MINIMAL_FORK] This is FORK #2: Child1 → Child2 (session)")
        print(f"[MINIMAL_FORK] Switching to PARENT mode NOW (stay with Child1)")

        # Use debugger object to switch mode
        if _debugger:
            _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
            print(f"[MINIMAL_FORK] ✓ Fork-mode switched to PARENT")
        else:
            print(f"[MINIMAL_FORK] ⚠️  WARNING: No debugger object, cannot switch fork-mode")

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

    print(f"\n[MINIMAL_KEX_ENTRY] gen_new_keys() ENTRY in PID {pid} (fork count: {_fork_count})")

    # Only set exit breakpoint after fork #1 (when in connection handler)
    if _fork_count < 1:
        print(f"[MINIMAL_KEX_ENTRY] Skipping - waiting for fork #1")
        return False

    # Set one-shot breakpoint at function return address (ARM64 pattern)
    print(f"[MINIMAL_KEX_ENTRY] Setting exit breakpoint...")

    # On ARM64, return address is in LR (link register)
    lr = frame.FindRegister("lr")
    if lr:
        ret_addr = lr.GetValueAsUnsigned()
        print(f"[MINIMAL_KEX_ENTRY] Return address from LR: 0x{ret_addr:x}")

        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)  # Fire once and auto-delete
        bp.SetScriptCallbackFunction("dropbear_callbacks_minimal.kex_derive_keys_exit")
        bp.SetAutoContinue(False)  # Don't auto-continue, let callback handle it
        print(f"[MINIMAL_KEX_ENTRY] ✓ Exit breakpoint set (bp {bp.GetID()}, one-shot)")
    else:
        print(f"[MINIMAL_KEX_ENTRY] ERROR: Could not read LR register")

    return False

def kex_derive_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys - NOW extract keys"""
    global _watchpoint_set, _key_address, _key_value, _target, _debugger, _process, _fork_count

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[MINIMAL_KEX_EXIT] gen_new_keys() EXIT in PID {pid} (keys should be populated now)")

    if _watchpoint_set:
        print(f"[MINIMAL_KEX_EXIT] Watchpoint already set, skipping")
        return False

    print(f"[MINIMAL_KEX_EXIT] Extracting trans_cipher_key...")

    # Extract trans_cipher_key from ses.newkeys->trans.cipher_key
    # This uses the same extraction logic as Test 3's watched_value address lookup

    try:
        # Get ses global variable
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print("[MINIMAL_KEX] ERROR: Could not find 'ses' global")
            return False

        ses = ses_list.GetValueAtIndex(0)

        # Navigate: ses.newkeys (pointer)
        newkeys_var = ses.GetChildMemberWithName("newkeys")
        if not newkeys_var.IsValid():
            print("[MINIMAL_KEX] ERROR: Could not get ses.newkeys")
            return False

        # Get pointer address
        newkeys_addr = newkeys_var.GetValueAsUnsigned()
        if newkeys_addr == 0:
            print("[MINIMAL_KEX] ERROR: newkeys is NULL")
            return False

        print(f"[MINIMAL_KEX] Found ses.newkeys at 0x{newkeys_addr:x}")

        # Dereference pointer and get trans structure (v2 pattern)
        trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
        if not trans_var.IsValid():
            print("[MINIMAL_KEX] ERROR: Could not get newkeys->trans")
            return False

        # Get trans.cipher_state (union containing actual keys)
        trans_cipher_state = trans_var.GetChildMemberWithName("cipher_state")
        if not trans_cipher_state.IsValid():
            print("[MINIMAL_KEX] ERROR: Could not get trans.cipher_state")
            return False

        # Get cipher_state address and read raw memory
        trans_cipher_addr = trans_cipher_state.GetLoadAddress()
        print(f"[MINIMAL_KEX] trans.cipher_state at 0x{trans_cipher_addr:x}")

        # Read 80 bytes: ChaCha20-Poly1305 structure
        # 0-15: "expand 32-byte k" constant
        # 16-47: ChaCha20 key (32 bytes)
        # 48-79: Poly1305 key (32 bytes)
        error = lldb.SBError()
        trans_cipher_data = process.ReadMemory(trans_cipher_addr, 80, error)
        if not error.Success():
            print(f"[MINIMAL_KEX] ERROR reading cipher_state: {error}")
            return False

        # Check for ChaCha20-Poly1305 pattern
        if trans_cipher_data[:16] == b"expand 32-byte k":
            # Extract ChaCha20 key (bytes 16-47)
            _key_value = trans_cipher_data[16:48]
            _key_address = trans_cipher_addr + 16
            print(f"[MINIMAL_KEX] ✓ ChaCha20 key at 0x{_key_address:x}")
            print(f"[MINIMAL_KEX] Key preview: {_key_value.hex()[:32]}... (32 bytes)")
        else:
            print(f"[MINIMAL_KEX] ERROR: cipher_state doesn't match ChaCha20 pattern")
            print(f"[MINIMAL_KEX] First 16 bytes: {trans_cipher_data[:16].hex()}")
            return False

        # ENABLED: Testing watchpoint on updated system (Ubuntu 24.04 + LLDB 18 + Dropbear 2024.86)
        # Test 4 proved heap watchpoints work - let's test with real Dropbear
        print(f"[MINIMAL_KEX] Creating watchpoint on heap-allocated key...")
        wp_error = lldb.SBError()
        watchpoint = _target.WatchAddress(_key_address, 1, False, True, wp_error)

        if not wp_error.Success():
            print(f"[MINIMAL_KEX] ERROR: Watchpoint failed: {wp_error}")
            return False

        wp_id = watchpoint.GetID()
        print(f"[MINIMAL_KEX] ✓ Watchpoint {wp_id} created at 0x{_key_address:x}")

        # Inject one-shot callback (Test 3 pattern)
        callback_name = f"minimal_wp_cb_{wp_id}"
        callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    print("\\n[MINIMAL_WP] 🎯 WATCHPOINT HIT!")
    print(f"[MINIMAL_WP] PID: {{frame.GetThread().GetProcess().GetProcessID()}}")
    print(f"[MINIMAL_WP] PC: 0x{{frame.GetPC():x}}")
    print("[MINIMAL_WP] One-shot: Returning False to disable")
    return False
"""

        _debugger.HandleCommand(f"script {callback_code}")
        _debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")

        print(f"[MINIMAL_KEX] ✓ One-shot callback attached")
        _watchpoint_set = True

    except Exception as e:
        print(f"[MINIMAL_KEX] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND (Register breakpoints)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup minimal monitoring (2 breakpoints only)"""
    global _target, _debugger, _process

    print("[MINIMAL] Initializing dropbear_callbacks_minimal module ...")
    print("[MINIMAL] Version 1.0")

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[MINIMAL] Dropbear Minimal Monitoring - Test 4 Pattern")
    print("[MINIMAL] Version 1.0")
    print("="*70)

    # Set follow-fork-mode to CHILD initially (to follow fork #1)
    print("[MINIMAL] Setting initial follow-fork-mode: CHILD")
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")

    # Breakpoint 1: fork() - to detect forks and switch modes
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("dropbear_callbacks_minimal.fork_callback")
        print(f"[MINIMAL] ✓ Breakpoint on fork() (ID {fork_bp.GetID()})")
    else:
        print(f"[MINIMAL] ⚠️  Could not set breakpoint on fork()")

    # Breakpoint 2: gen_new_keys ENTRY - sets exit breakpoint for key extraction
    kex_bp = _target.BreakpointCreateByName("gen_new_keys")
    if kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("dropbear_callbacks_minimal.kex_derive_keys_entry")
        print(f"[MINIMAL] ✓ Breakpoint on gen_new_keys() ENTRY (ID {kex_bp.GetID()})")
    else:
        print(f"[MINIMAL] ⚠️  Could not set breakpoint on gen_new_keys()")

    print("[MINIMAL] Setup complete - ready for auto_continue")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND (Keep-alive loop with trace detection)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop with trace mode detection (Test 3 pattern)"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[MINIMAL_AUTO] Starting auto-continue loop")
    print("[MINIMAL_AUTO] Monitoring for trace mode...")

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
                print(f"[MINIMAL_AUTO] ⚠️  TRACE MODE detected (iteration {iteration}, count {trace_count})")

                if trace_count > 10:
                    print("[MINIMAL_AUTO] ❌ EXCESSIVE TRACE MODE - Test FAILED")
                    print("[MINIMAL_AUTO] Stopping auto-continue")
                    break

            elif stop_reason == lldb.eStopReasonWatchpoint:
                print(f"[MINIMAL_AUTO] ✓ Watchpoint hit (iteration {iteration})")

            elif stop_reason == lldb.eStopReasonBreakpoint:
                # Breakpoint hit, callbacks will handle it
                pass

            # Continue process
            process.Continue()

        time.sleep(0.05)  # Match Test 3 polling interval

    print("\n" + "="*70)
    print("[MINIMAL_AUTO] Process exited")
    print("="*70)
    print(f"[MINIMAL_AUTO] Total iterations: {iteration}")
    print(f"[MINIMAL_AUTO] Trace mode count: {trace_count}")
    print(f"[MINIMAL_AUTO] Watchpoint set: {_watchpoint_set}")

    if trace_count == 0:
        print("[MINIMAL_AUTO] ✅✅✅ SUCCESS - No trace mode!")
    elif trace_count <= 2:
        print("[MINIMAL_AUTO] ⚠️  Minimal trace mode (borderline)")
    else:
        print("[MINIMAL_AUTO] ❌❌❌ FAILURE - Trace mode detected")

    print("="*70)
