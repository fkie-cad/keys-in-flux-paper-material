#!/usr/bin/env python3
"""
OpenSSH Follow-Fork + Stop-On-Exec Monitoring with Auto-Continue
Based on successful Dropbear two-command pattern
"""

import lldb
import time
import struct
import os

# Global state
_debugger = None
_target = None


def kex_extract_callback(frame, bp_loc, internal_dict):
    """
    KEX extraction callback - called when kex_derive_keys() breakpoint hits
    """
    if not frame or not frame.IsValid():
        print("[KEX] ❌ Invalid frame")
        return False

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    arch = target.GetTriple().lower()

    is_arm64 = "arm64" in arch or "aarch64" in arch

    # Get function parameters from registers
    # kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen, const struct sshbuf *shared_secret)
    if is_arm64:
        hash_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
        hashlen = frame.FindRegister("x2").GetValueAsUnsigned()
        shared_secret_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
    else:
        hash_ptr = frame.FindRegister("rsi").GetValueAsUnsigned()
        hashlen = frame.FindRegister("rdx").GetValueAsUnsigned()
        shared_secret_ptr = frame.FindRegister("rcx").GetValueAsUnsigned()

    error = lldb.SBError()

    # Extract hash/cookie
    if hash_ptr and hashlen > 0 and hashlen < 1024:
        hash_data = process.ReadMemory(hash_ptr, min(hashlen, 64), error)
        if not error.Fail():
            cookie_hex = hash_data.hex()

            # Extract shared secret from sshbuf
            # struct sshbuf { u_char *d; size_t off; size_t size; ... }
            if shared_secret_ptr:
                data_ptr_bytes = process.ReadMemory(shared_secret_ptr, 8, error)
                if not error.Fail():
                    data_ptr = struct.unpack("<Q", data_ptr_bytes)[0]

                    off_bytes = process.ReadMemory(shared_secret_ptr + 8, 8, error)
                    off = struct.unpack("<Q", off_bytes)[0] if not error.Fail() else 0

                    size_bytes = process.ReadMemory(shared_secret_ptr + 16, 8, error)
                    size = struct.unpack("<Q", size_bytes)[0] if not error.Fail() else 0

                    if data_ptr and size > 0 and size < 4096:
                        secret_data = process.ReadMemory(data_ptr + off, size - off, error)
                        if not error.Fail():
                            secret_hex = secret_data.hex()

                            # Write keylog
                            keylog_path = os.getenv("LLDB_KEYLOG", "/data/keylogs/ssh_keylog.log")
                            with open(keylog_path, "a") as f:
                                f.write(f"{cookie_hex} SHARED_SECRET {secret_hex}\n")

                            print(f"[KEX] ✓ Keys extracted: cookie={cookie_hex[:32]}... secret={secret_hex[:32]}...")
                            return False  # Continue execution

    print("[KEX] ⚠️  Key extraction incomplete")
    return False  # Continue execution

def __lldb_init_module(debugger, internal_dict):
    """Called automatically when script is imported by LLDB"""
    global _debugger
    _debugger = debugger

    # Register commands
    debugger.HandleCommand(
        'command script add -f openssh_followfork_callbacks.openssh_setup_monitoring openssh_setup_monitoring'
    )
    debugger.HandleCommand(
        'command script add -f openssh_followfork_callbacks.openssh_auto_continue openssh_auto_continue'
    )
    print("[LLDB] Commands registered: openssh_setup_monitoring, openssh_auto_continue")


def openssh_setup_monitoring(debugger, command, result, internal_dict):
    """
    Setup monitoring: follow-fork, stop-on-exec, KEX breakpoint
    """
    global _target
    _target = debugger.GetSelectedTarget()

    print("[SETUP] Configuring follow-fork + stop-on-exec...")

    # Configure fork/exec handling
    debugger.HandleCommand("settings set target.process.follow-fork-mode child")
    debugger.HandleCommand("settings set target.process.stop-on-exec true")

    # Set KEX breakpoint
    print("[SETUP] Setting breakpoint on kex_derive_keys...")
    breakpoint = _target.BreakpointCreateByName("kex_derive_keys")

    if breakpoint and breakpoint.IsValid():
        print(f"[SETUP] ✓ Breakpoint created (ID {breakpoint.GetID()})")

        # Add Python function callback (not exec)
        breakpoint.SetScriptCallbackFunction("openssh_followfork_callbacks.kex_extract_callback")
        print(f"[SETUP] ✓ KEX extraction callback attached")
    else:
        print("[SETUP] ⚠️  Breakpoint pending (will resolve after exec)")

    print("[SETUP] ✓ Monitoring configured successfully")


def openssh_auto_continue(debugger, command, result, internal_dict):
    """
    Auto-continue loop: handles stop-on-exec and runs until process exits
    """
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    if not process or not process.IsValid():
        print("[AUTO-CONTINUE] ❌ No valid process")
        return

    print("[AUTO-CONTINUE] ✓ Starting auto-continue loop...")

    # Initial continue
    process.Continue()

    # Keep-alive loop
    while True:
        time.sleep(0.1)

        state = process.GetState()

        if state == lldb.eStateExited:
            exit_code = process.GetExitStatus()
            print(f"[AUTO-CONTINUE] Process exited with code {exit_code}")
            break

        elif state == lldb.eStateStopped:
            # Check stop reason
            thread = process.GetSelectedThread()
            if thread:
                stop_reason = thread.GetStopReason()

                if stop_reason == lldb.eStopReasonExec:
                    print("[AUTO-CONTINUE] ⚡ Stopped at exec boundary - continuing...")
                elif stop_reason == lldb.eStopReasonBreakpoint:
                    print("[AUTO-CONTINUE] 🎯 KEX breakpoint hit - continuing...")
                else:
                    stop_desc = thread.GetStopDescription(100)
                    print(f"[AUTO-CONTINUE] ⏸️  Stopped: {stop_desc} - continuing...")

            # Continue execution
            process.Continue()

        elif state == lldb.eStateCrashed:
            print("[AUTO-CONTINUE] ❌ Process crashed")
            break

        # Ignore other states (running, etc.)

    print("[AUTO-CONTINUE] ✓ Monitoring complete")
