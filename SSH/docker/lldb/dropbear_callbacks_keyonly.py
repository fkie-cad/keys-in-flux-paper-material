#!/usr/bin/env python3
"""
Dropbear Key Extraction Only - NO Watchpoints

This version is identical to dropbear_callbacks_minimal.py EXCEPT it does NOT
create any watchpoints. This allows us to test if:
1. LLDB breakpoints work without trace mode ✅ (expected to work)
2. Key extraction works correctly ✅ (expected to work)
3. Fork handling works properly ✅ (expected to work)

If this succeeds with 0 trace hits, then we know watchpoint creation
is the specific trigger for trace mode in Dropbear.

Key features:
- 2 breakpoints only: fork() and gen_new_keys()
- Immediate fork-mode switching at fork callback
- Full key extraction (ChaCha20-Poly1305)
- NO watchpoints
- NO memory dumps
- Minimal global state
"""

import lldb
import time
import os

# ═══════════════════════════════════════════════════════════════════════════
# MINIMAL GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

_fork_count = 0
_key_extracted = False
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
        'command script add -f dropbear_callbacks_keyonly.dropbear_setup_monitoring dropbear_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f dropbear_callbacks_keyonly.dropbear_auto_continue dropbear_auto_continue'
    )
    print("[KEYONLY] Commands registered: dropbear_setup_monitoring, dropbear_auto_continue")

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

    print(f"\n[KEYONLY_FORK] Fork #{_fork_count} detected in PID {pid}")

    if _fork_count == 1:
        # Fork #1: Parent → Connection handler
        print(f"[KEYONLY_FORK] This is FORK #1: Parent → Child1 (connection handler)")
        print(f"[KEYONLY_FORK] LLDB will follow child (connection handler)")
        print(f"[KEYONLY_FORK] After this fork, will switch to 'parent' mode")

    elif _fork_count == 2:
        # Fork #2: Connection handler → Session child
        # CRITICAL: Switch fork-mode NOW (immediately, like Test 3)
        print(f"[KEYONLY_FORK] This is FORK #2: Child1 → Child2 (session)")
        print(f"[KEYONLY_FORK] Switching to PARENT mode NOW (stay with Child1)")

        # Use debugger object to switch mode
        if _debugger:
            _debugger.HandleCommand("settings set target.process.follow-fork-mode parent")
            print(f"[KEYONLY_FORK] ✓ Fork-mode switched to PARENT")
        else:
            print(f"[KEYONLY_FORK] ⚠️  WARNING: No debugger object, cannot switch fork-mode")

    return False  # Continue execution

# ═══════════════════════════════════════════════════════════════════════════
# KEY DERIVATION CALLBACK (Extract keys, NO watchpoints)
# ═══════════════════════════════════════════════════════════════════════════

def kex_derive_keys_entry(frame, bp_loc, internal_dict):
    """Entry breakpoint on gen_new_keys - set exit breakpoint for key extraction"""
    global _fork_count, _target, _debugger

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[KEYONLY_KEX_ENTRY] gen_new_keys() ENTRY in PID {pid} (fork count: {_fork_count})")

    # Only set exit breakpoint after fork #1 (when in connection handler)
    if _fork_count < 1:
        print(f"[KEYONLY_KEX_ENTRY] Skipping - waiting for fork #1")
        return False

    # Set one-shot breakpoint at function return address (ARM64 pattern)
    print(f"[KEYONLY_KEX_ENTRY] Setting exit breakpoint...")

    # On ARM64, return address is in LR (link register)
    lr = frame.FindRegister("lr")
    if lr:
        ret_addr = lr.GetValueAsUnsigned()
        print(f"[KEYONLY_KEX_ENTRY] Return address from LR: 0x{ret_addr:x}")

        bp = _target.BreakpointCreateByAddress(ret_addr)
        bp.SetOneShot(True)  # Fire once and auto-delete
        bp.SetScriptCallbackFunction("dropbear_callbacks_keyonly.kex_derive_keys_exit")
        bp.SetAutoContinue(False)  # Don't auto-continue, let callback handle it
        print(f"[KEYONLY_KEX_ENTRY] ✓ Exit breakpoint set (bp {bp.GetID()}, one-shot)")
    else:
        print(f"[KEYONLY_KEX_ENTRY] ERROR: Could not read LR register")

    return False

def kex_derive_keys_exit(frame, bp_loc, internal_dict):
    """Exit breakpoint for gen_new_keys - NOW extract keys (NO watchpoint)"""
    global _key_extracted, _key_address, _key_value, _target, _debugger, _process, _fork_count

    thread = frame.GetThread()
    process = thread.GetProcess()
    pid = process.GetProcessID()

    print(f"\n[KEYONLY_KEX_EXIT] gen_new_keys() EXIT in PID {pid} (keys should be populated now)")

    if _key_extracted:
        print(f"[KEYONLY_KEX_EXIT] Key already extracted, skipping")
        return False

    print(f"[KEYONLY_KEX_EXIT] Extracting trans_cipher_key...")

    # Extract trans_cipher_key from ses.newkeys->trans.cipher_key
    # This uses the same extraction logic as Test 3's watched_value address lookup

    try:
        # Get ses global variable
        ses_list = _target.FindGlobalVariables("ses", 1)
        if ses_list.GetSize() == 0:
            print("[KEYONLY_KEX] ERROR: Could not find 'ses' global")
            return False

        ses = ses_list.GetValueAtIndex(0)

        # Navigate: ses.newkeys (pointer)
        newkeys_var = ses.GetChildMemberWithName("newkeys")
        if not newkeys_var.IsValid():
            print("[KEYONLY_KEX] ERROR: Could not get ses.newkeys")
            return False

        # Get pointer address
        newkeys_addr = newkeys_var.GetValueAsUnsigned()
        if newkeys_addr == 0:
            print("[KEYONLY_KEX] ERROR: newkeys is NULL")
            return False

        print(f"[KEYONLY_KEX] Found ses.newkeys at 0x{newkeys_addr:x}")

        # Dereference pointer and get trans structure (v2 pattern)
        trans_var = newkeys_var.Dereference().GetChildMemberWithName("trans")
        if not trans_var.IsValid():
            print("[KEYONLY_KEX] ERROR: Could not get newkeys->trans")
            return False

        # Get trans.cipher_state (union containing actual keys)
        trans_cipher_state = trans_var.GetChildMemberWithName("cipher_state")
        if not trans_cipher_state.IsValid():
            print("[KEYONLY_KEX] ERROR: Could not get trans.cipher_state")
            return False

        # Get cipher_state address and read raw memory
        trans_cipher_addr = trans_cipher_state.GetLoadAddress()
        print(f"[KEYONLY_KEX] trans.cipher_state at 0x{trans_cipher_addr:x}")

        # Read 80 bytes: ChaCha20-Poly1305 structure
        # 0-15: "expand 32-byte k" constant
        # 16-47: ChaCha20 key (32 bytes)
        # 48-79: Poly1305 key (32 bytes)
        error = lldb.SBError()
        trans_cipher_data = process.ReadMemory(trans_cipher_addr, 80, error)
        if not error.Success():
            print(f"[KEYONLY_KEX] ERROR reading cipher_state: {error}")
            return False

        # Check for ChaCha20-Poly1305 pattern
        if trans_cipher_data[:16] == b"expand 32-byte k":
            # Extract ChaCha20 key (bytes 16-47)
            _key_value = trans_cipher_data[16:48]
            _key_address = trans_cipher_addr + 16
            print(f"[KEYONLY_KEX] ✓ ChaCha20 key at 0x{_key_address:x}")
            print(f"[KEYONLY_KEX] Key preview: {_key_value.hex()[:32]}... (32 bytes)")
            print(f"[KEYONLY_KEX] Full key: {_key_value.hex()}")
        else:
            print(f"[KEYONLY_KEX] ERROR: cipher_state doesn't match ChaCha20 pattern")
            print(f"[KEYONLY_KEX] First 16 bytes: {trans_cipher_data[:16].hex()}")
            return False

        # ═══════════════════════════════════════════════════════════════════════
        # KEY DIFFERENCE: NO WATCHPOINT CREATION
        # ═══════════════════════════════════════════════════════════════════════
        print(f"\n[KEYONLY_KEX] ═══════════════════════════════════════════════════════")
        print(f"[KEYONLY_KEX] ✅ Key extraction complete - NO watchpoint will be set")
        print(f"[KEYONLY_KEX] This tests if breakpoints alone work without trace mode")
        print(f"[KEYONLY_KEX] ═══════════════════════════════════════════════════════\n")

        _key_extracted = True

    except Exception as e:
        print(f"[KEYONLY_KEX] EXCEPTION: {e}")
        import traceback
        traceback.print_exc()

    return False

# ═══════════════════════════════════════════════════════════════════════════
# SETUP COMMAND (Register breakpoints)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_setup_monitoring(debugger, command, result, internal_dict):
    """Setup minimal monitoring (2 breakpoints only, NO watchpoints)"""
    global _target, _debugger, _process

    _debugger = debugger
    _target = debugger.GetSelectedTarget()
    _process = _target.GetProcess()

    print("\n" + "="*70)
    print("[KEYONLY] Dropbear Key Extraction Only - NO Watchpoints")
    print("[KEYONLY] Tests breakpoints + key extraction without watchpoints")
    print("="*70)

    # Set follow-fork-mode to CHILD initially (to follow fork #1)
    print("[KEYONLY] Setting initial follow-fork-mode: CHILD")
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")

    # Breakpoint 1: fork() - to detect forks and switch modes
    fork_bp = _target.BreakpointCreateByName("fork")
    if fork_bp.IsValid():
        fork_bp.SetScriptCallbackFunction("dropbear_callbacks_keyonly.fork_callback")
        print(f"[KEYONLY] ✓ Breakpoint on fork() (ID {fork_bp.GetID()})")
    else:
        print(f"[KEYONLY] ⚠️  Could not set breakpoint on fork()")

    # Breakpoint 2: gen_new_keys ENTRY - sets exit breakpoint for key extraction
    kex_bp = _target.BreakpointCreateByName("gen_new_keys")
    if kex_bp.IsValid():
        kex_bp.SetScriptCallbackFunction("dropbear_callbacks_keyonly.kex_derive_keys_entry")
        print(f"[KEYONLY] ✓ Breakpoint on gen_new_keys() ENTRY (ID {kex_bp.GetID()})")
    else:
        print(f"[KEYONLY] ⚠️  Could not set breakpoint on gen_new_keys()")

    print("[KEYONLY] Setup complete - ready for auto_continue")
    print("[KEYONLY] ⚠️  NO WATCHPOINTS will be created in this mode")
    print("="*70 + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# AUTO-CONTINUE COMMAND (Keep-alive loop with trace detection)
# ═══════════════════════════════════════════════════════════════════════════

def dropbear_auto_continue(debugger, command, result, internal_dict):
    """Auto-continue loop with trace mode detection (Test 3 pattern)"""
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    print("[KEYONLY_AUTO] Starting auto-continue loop")
    print("[KEYONLY_AUTO] Monitoring for trace mode (expecting ZERO)...")

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
                print(f"[KEYONLY_AUTO] ⚠️  TRACE MODE detected (iteration {iteration}, count {trace_count})")

                if trace_count > 10:
                    print("[KEYONLY_AUTO] ❌ EXCESSIVE TRACE MODE - Test FAILED")
                    print("[KEYONLY_AUTO] Stopping auto-continue")
                    break

            elif stop_reason == lldb.eStopReasonWatchpoint:
                print(f"[KEYONLY_AUTO] ⚠️  Unexpected watchpoint hit (iteration {iteration})")
                print(f"[KEYONLY_AUTO] This should not happen in KEYONLY mode!")

            elif stop_reason == lldb.eStopReasonBreakpoint:
                # Breakpoint hit, callbacks will handle it
                pass

            # Continue process
            process.Continue()

        time.sleep(0.05)  # Match Test 3 polling interval

    print("\n" + "="*70)
    print("[KEYONLY_AUTO] Process exited")
    print("="*70)
    print(f"[KEYONLY_AUTO] Total iterations: {iteration}")
    print(f"[KEYONLY_AUTO] Trace mode count: {trace_count}")
    print(f"[KEYONLY_AUTO] Key extracted: {_key_extracted}")

    if trace_count == 0:
        print("[KEYONLY_AUTO] ✅✅✅ SUCCESS - No trace mode!")
        print("[KEYONLY_AUTO] This proves breakpoints + key extraction work perfectly")
    elif trace_count <= 2:
        print("[KEYONLY_AUTO] ⚠️  Minimal trace mode (borderline)")
    else:
        print("[KEYONLY_AUTO] ❌❌❌ FAILURE - Trace mode detected")
        print("[KEYONLY_AUTO] This suggests breakpoints cause trace mode (unexpected!)")

    print("="*70)
