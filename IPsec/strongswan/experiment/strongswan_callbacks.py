#!/usr/bin/env python3
"""
strongswan_callbacks.py

Callback functions for strongSwan/charon LLDB monitoring
Tracks IKE and ESP key material in userspace

Supported architectures: x86_64, aarch64

Key tracking targets:
- IKE handshake: SK_ai, SK_ar, SK_ei, SK_er (SK_pi, SK_pr optional)
- ESP: ENCR_i, INTEG_i, ENCR_r, INTEG_r
"""
import lldb
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from shared_ipsec import (
    ArchitectureHelper,
    ChunkReader,
    MemoryDumper,
    EventLogger,
    format_hex
)


# Global state for dumper, logger, and keylog writer (set by monitoring script)
_dumper = None
_logger = None
_keylog_writer = None
_timing_logger = None
_checkpoint_counter = {
    "init": True,
    "before_handshake": False, "after_handshake": False,
    "before_child_sa": False, "after_child_sa": False,
    "before_rekey": False, "after_rekey": False,
    "before_terminate": False, "after_terminate": False,
    "final": False
}

# Watchpoint tracking (max 4 hardware watchpoints)
# Track: sk_ei, sk_er (IKE SA), ENCR_i, ENCR_r (ESP)
_watchpoints = {}  # {key_name: {'wp_id': int, 'addr': int, 'value': bytes}}
_target = None     # LLDB target (set during init)
_debugger = None   # LLDB debugger (needed for command execution)

# PRF key counter for SKEYSEED tracking
_prf_key_counter = 0


def set_global_handlers(dumper: MemoryDumper, logger: EventLogger, keylog_writer=None, timing_logger=None):
    """Set global memory dumper, event logger, keylog writer, and timing logger"""
    global _dumper, _logger, _keylog_writer, _timing_logger
    _dumper = dumper
    _logger = logger
    _keylog_writer = keylog_writer
    _timing_logger = timing_logger


def set_target(target, debugger=None):
    """Set the LLDB target and debugger for watchpoint management

    Args:
        target: LLDB SBTarget object
        debugger: LLDB SBDebugger object (optional, needed for command-based watchpoints)
    """
    global _target, _debugger
    _target = target
    _debugger = debugger


#=============================================================================
# Watchpoint Callbacks (Track key overwrites/clearing)
#=============================================================================

def watchpoint_sk_ei_callback(frame, wp, internal_dict):
    """Called when sk_ei (IKE encryption key initiator) is overwritten"""
    global _watchpoints, _timing_logger

    try:
        print(f"\n[WATCHPOINT] sk_ei overwritten!")

        # Get address and read new value
        addr = wp.GetWatchAddress()
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()
        new_value = process.ReadMemory(addr, 16, error)

        if error.Success():
            print(f"[WATCHPOINT] sk_ei new value (first 16 bytes): {bytes(new_value).hex()}")

        # Log to timing CSV
        if _timing_logger:
            old_data = _watchpoints.get("sk_ei", {}).get("value", b'')
            _timing_logger.log_watchpoint_hit("sk_ei", addr, old_data, bytes(new_value) if error.Success() else None)

        # Remove watchpoint (key has been overwritten)
        _watchpoints.pop("sk_ei", None)

    except Exception as e:
        print(f"[WATCHPOINT] Error in sk_ei callback: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution


def watchpoint_sk_er_callback(frame, wp, internal_dict):
    """Called when sk_er (IKE encryption key responder) is overwritten"""
    global _watchpoints, _timing_logger

    try:
        print(f"\n[WATCHPOINT] sk_er overwritten!")

        addr = wp.GetWatchAddress()
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()
        new_value = process.ReadMemory(addr, 16, error)

        if error.Success():
            print(f"[WATCHPOINT] sk_er new value (first 16 bytes): {bytes(new_value).hex()}")

        if _timing_logger:
            old_data = _watchpoints.get("sk_er", {}).get("value", b'')
            _timing_logger.log_watchpoint_hit("sk_er", addr, old_data, bytes(new_value) if error.Success() else None)

        _watchpoints.pop("sk_er", None)

    except Exception as e:
        print(f"[WATCHPOINT] Error in sk_er callback: {e}")
        import traceback
        traceback.print_exc()

    return False


def watchpoint_ENCR_i_callback(frame, wp, internal_dict):
    """Called when ENCR_i (ESP encryption key initiator) is overwritten"""
    global _watchpoints, _timing_logger

    try:
        print(f"\n[WATCHPOINT] ENCR_i overwritten!")

        addr = wp.GetWatchAddress()
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()
        new_value = process.ReadMemory(addr, 16, error)

        if error.Success():
            print(f"[WATCHPOINT] ENCR_i new value (first 16 bytes): {bytes(new_value).hex()}")

        if _timing_logger:
            old_data = _watchpoints.get("ENCR_i", {}).get("value", b'')
            _timing_logger.log_watchpoint_hit("ENCR_i", addr, old_data, bytes(new_value) if error.Success() else None)

        _watchpoints.pop("ENCR_i", None)

    except Exception as e:
        print(f"[WATCHPOINT] Error in ENCR_i callback: {e}")
        import traceback
        traceback.print_exc()

    return False


def watchpoint_ENCR_r_callback(frame, wp, internal_dict):
    """Called when ENCR_r (ESP encryption key responder) is overwritten"""
    global _watchpoints, _timing_logger

    try:
        print(f"\n[WATCHPOINT] ENCR_r overwritten!")

        addr = wp.GetWatchAddress()
        process = frame.GetThread().GetProcess()
        error = lldb.SBError()
        new_value = process.ReadMemory(addr, 16, error)

        if error.Success():
            print(f"[WATCHPOINT] ENCR_r new value (first 16 bytes): {bytes(new_value).hex()}")

        if _timing_logger:
            old_data = _watchpoints.get("ENCR_r", {}).get("value", b'')
            _timing_logger.log_watchpoint_hit("ENCR_r", addr, old_data, bytes(new_value) if error.Success() else None)

        _watchpoints.pop("ENCR_r", None)

    except Exception as e:
        print(f"[WATCHPOINT] Error in ENCR_r callback: {e}")
        import traceback
        traceback.print_exc()

    return False


def _handle_watchpoint_hit(key_name: str, addr: int):
    """Called when a watchpoint is hit (via command line commands)

    This function is invoked by LLDB watchpoint commands, not as a direct callback.
    """
    global _watchpoints, _timing_logger

    try:
        print(f"\n[WATCHPOINT] {key_name} overwritten at 0x{addr:x}!")

        # Log to timing CSV
        if _timing_logger:
            old_data = _watchpoints.get(key_name, {}).get("value", b'')
            _timing_logger.log_watchpoint_hit(key_name, addr, old_data, None)

        # Remove watchpoint from tracking (key has been cleared)
        _watchpoints.pop(key_name, None)

    except Exception as e:
        print(f"[WATCHPOINT] Error handling {key_name}: {e}")
        import traceback
        traceback.print_exc()


def _set_watchpoint(key_name: str, base_addr: int, offset: int, key_data: bytes, callback_name: str):
    """Helper function to set a hardware watchpoint on a key

    Uses the proven TLS monitoring pattern: generate callback as f-string, inject with 'script',
    then attach with 'watchpoint command add -F'. LLDB automatically passes frame, bp_loc, internal_dict.

    Args:
        key_name: Name of key (e.g., "sk_ei", "ENCR_i")
        base_addr: Base address of the chunk_t data
        offset: Offset within chunk where this key starts
        key_data: Key bytes (for logging)
        callback_name: Python callback function name (unused, kept for API compatibility)
    """
    global _watchpoints, _target, _debugger, _timing_logger

    # Skip if already have a watchpoint for this key
    if key_name in _watchpoints:
        print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    # Calculate actual memory address
    addr = base_addr + offset

    # Check if we have debugger (needed for command-based approach)
    if not _debugger or not _target:
        print(f"[WATCHPOINT] No debugger/target available for {key_name}, skipping watchpoints")
        return

    try:
        error = lldb.SBError()

        # Set write watchpoint on 4 bytes
        watchpoint = _target.WatchAddress(addr, 4, False, True, error)

        if not error.Success() or not watchpoint.IsValid():
            print(f"[WATCHPOINT] Failed to set on {key_name}: {error.GetCString()}")
            return

        # Get watchpoint ID
        wp_id = watchpoint.GetID()

        # Generate unique callback name
        callback_func_name = f"watchpoint_callback_{wp_id}_{key_name}"

        # Capture fixed values (Python f-string will substitute these)
        fixed_addr = addr
        fixed_key_name = key_name

        # Generate callback code as string (TLS pattern)
        callback_code = f'''
def {callback_func_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_key_name}' at 0x{fixed_addr:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    new_data = process.ReadMemory({fixed_addr}, 16, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in new_data[:16])
        print(f"[WATCHPOINT] New value: {{data_hex}}")

        import strongswan_callbacks
        if strongswan_callbacks._timing_logger:
            strongswan_callbacks._timing_logger.log_watchpoint_hit("{fixed_key_name}", {fixed_addr}, None, bytes(new_data))

    import strongswan_callbacks
    strongswan_callbacks._watchpoints.pop("{fixed_key_name}", None)

    return False
'''

        # Inject the callback code (step 1: define the function)
        # Use triple-quoted string to avoid escaping issues
        escaped_code = callback_code.replace("'", "\\'")
        _debugger.HandleCommand(f"script {callback_code}")

        # Also inject into strongswan_callbacks module namespace as backup
        # This ensures the callback is available if LLDB looks in our module
        try:
            exec(callback_code, globals())
        except:
            pass  # Non-fatal if this fails

        # Attach callback to watchpoint (step 2: reference it by name with -F flag)
        _debugger.HandleCommand(f"watchpoint command add -F {callback_func_name} {wp_id}")

        # Store watchpoint info for tracking
        _watchpoints[key_name] = {
            'wp_id': wp_id,
            'addr': addr,
            'value': key_data
        }

        print(f"[WATCHPOINT] Set on {key_name} @ 0x{addr:x} (watchpoint ID: {wp_id})")

        # Log to timing CSV
        if _timing_logger:
            _timing_logger.log_watchpoint_set(key_name, addr, key_data)

    except Exception as e:
        print(f"[WATCHPOINT] Exception setting {key_name}: {e}")
        import traceback
        traceback.print_exc()


def _read_u64(process, addr: int):
    """Read a 64-bit little-endian value from memory (for stack-passed arguments)"""
    import struct
    if not addr or addr == 0:
        return None
    error = lldb.SBError()
    data = process.ReadMemory(addr, 8, error)
    if not error.Success() or not data or len(data) < 8:
        return None
    # Ensure bytes
    if isinstance(data, str):
        data = data.encode('latin-1')
    return struct.unpack("<Q", data)[0]


def debug_dump_arguments(frame, num_args=14):
    """Debug function to dump first N arguments (registers + stack) for both x86_64 and ARM64

    This helps verify calling conventions and parameter extraction.
    If argument value > 128, treats it as a pointer and dumps 64 bytes of memory.

    Args:
        frame: LLDB frame
        num_args: Number of arguments to dump (default: 14)
    """
    import os
    import struct

    # Only run in manual/interactive mode
    mode = os.environ.get("IPSEC_MODE", "")
    if mode not in ["interactive", "manual"]:
        return

    print("\n" + "="*70)
    print("[DEBUG] Argument Dump (Registers + Stack)")
    print("="*70)

    arch = ArchitectureHelper(frame)
    process = frame.GetThread().GetProcess()

    if arch.is_x86_64:
        # x86_64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
        registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        sp_reg = "rsp"
        stack_offset = 8  # Skip return address
        print("[DEBUG] Architecture: x86_64")
        print(f"[DEBUG] Dumping {num_args} arguments (6 registers + {max(0, num_args - 6)} stack):")
    elif arch.is_aarch64:
        # aarch64 AAPCS64: x0-x7, then stack
        registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        sp_reg = "sp"
        stack_offset = 0  # Stack args start at [sp+0]
        print("[DEBUG] Architecture: aarch64 (ARM64)")
        print(f"[DEBUG] Dumping {num_args} arguments (8 registers + {max(0, num_args - 8)} stack):")
    else:
        print(f"[DEBUG] Unknown architecture")
        return

    print()

    # Read stack pointer for stack arguments
    sp_value = arch.read_register(sp_reg)

    for i in range(num_args):
        try:
            # Get argument value from register or stack
            if i < len(registers):
                # Register argument
                reg_name = registers[i]
                value = arch.read_register(reg_name)
                location = f"{reg_name:3s}"
            else:
                # Stack argument
                if sp_value is None:
                    print(f"  Arg{i:2d} (stack): <stack pointer unavailable>")
                    continue

                stack_index = i - len(registers)
                stack_addr = sp_value + stack_offset + (stack_index * 8)

                # Debug: show stack read attempt
                # print(f"  [DEBUG] Reading stack arg {i} at 0x{stack_addr:x}")

                error = lldb.SBError()
                stack_data = process.ReadMemory(stack_addr, 8, error)
                if not error.Success():
                    print(f"  Arg{i:2d} (stk): <unable to read stack at 0x{stack_addr:x}: {error.GetCString()}>")
                    continue

                value = struct.unpack("<Q", bytes(stack_data))[0]
                location = f"stk"

            if value is None:
                print(f"  Arg{i:2d} ({location}): <unable to read>")
                continue

            print(f"  Arg{i:2d} ({location}): 0x{value:016x}  ({value})")

            # If value > 128, treat as pointer and dump 96 bytes
            if value > 128:
                try:
                    error = lldb.SBError()
                    mem_data = process.ReadMemory(value, 96, error)
                    if error.Success() and len(mem_data) > 0:
                        # Format as 96-byte hex dump (6 lines of 16 bytes each)
                        print(f"           -> Memory at 0x{value:x} (96 bytes):")
                        for offset in range(0, min(len(mem_data), 96), 16):
                            chunk = bytes(mem_data)[offset:offset+16]
                            hex_str = ' '.join(f'{b:02x}' for b in chunk)
                            # Also show ASCII representation
                            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                            print(f"           -> +{offset:02x}: {hex_str:<48s} | {ascii_str}")

                        # Try to interpret as chunk_t (ptr + len) - supplementary info
                        if len(mem_data) >= 16:
                            ptr, length = struct.unpack("<QQ", bytes(mem_data)[:16])
                            if ptr > 0x1000 and 0 < length < 65536:
                                print(f"           -> [Chunk_t detected: ptr=0x{ptr:x}, len={length}]")
                                # Read the chunk data
                                chunk_data = process.ReadMemory(ptr, min(length, 32), error)
                                if error.Success():
                                    chunk_hex = ' '.join(f'{b:02x}' for b in bytes(chunk_data)[:min(length, 32)])
                                    print(f"           -> [Chunk data: {chunk_hex}...]")
                    else:
                        print(f"           -> [Cannot read memory at 0x{value:x}: {error.GetCString()}]")
                except Exception as e:
                    print(f"           -> [Memory read error: {e}]")

        except Exception as e:
            location_str = registers[i] if i < len(registers) else "stack"
            print(f"  Arg{i:2d} ({location_str}): <error: {e}>")

    print("="*70)
    print()


def ike_derived_keys_callback(frame, bp_loc, internal_dict):
    """Callback for bus->ike_derived_keys(..., sk_ai, sk_ar, sk_ei, sk_er, ...)

    This function is called when IKE handshake derives the session keys.
    We track: SK_ai, SK_ar, SK_ei, SK_er (and optionally SK_pi, SK_pr)

    Function signature (from strongSwan source):
    void ike_derived_keys(ike_sa_t *ike_sa, chunk_t sk_ei, chunk_t sk_er,
                         chunk_t sk_ai, chunk_t sk_ar, chunk_t sk_pi, chunk_t sk_pr)
    """
    import sys
    import datetime
    global _checkpoint_counter

    timestamp = datetime.datetime.now().isoformat()
    print(f"\n[{timestamp}] [CALLBACK-START] ike_derived_keys")
    sys.stdout.flush()

    # DEBUG: Dump arguments in manual mode
    try:
        debug_dump_arguments(frame, num_args=14)
    except Exception as e:
        print(f"[DEBUG] Argument dump failed: {e}")

    try:
        arch = ArchitectureHelper(frame)
        chunk_reader = ChunkReader(frame)
        process = frame.GetThread().GetProcess()

        # Extract keys - try symbolic approach first, then registers
        keys = {}
        symbolic_ok = False

        # Try to get variables by name (requires debug symbols)
        for varname in ("sk_ai", "sk_ar", "sk_ei", "sk_er", "sk_pi", "sk_pr"):
            try:
                var = frame.EvaluateExpression(f"(&{varname})")
                if var.IsValid() and var.GetValueAsUnsigned() != 0:
                    symbolic_ok = True
                    addr = var.GetValueAsUnsigned()
                    ptr, length, data = chunk_reader.read_chunk_from_memory(addr)
                    if length > 0:
                        keys[varname] = {
                            "len": length,
                            "sample": data[:32].hex(),
                            "full_hex": data.hex()
                        }
            except Exception as e:
                pass

        # Fallback: read from registers (works without debug symbols)
        # Based on testing with strongSwan:
        # Function signature: void (*ike_derived_keys)(bus_t *this, chunk_t sk_d, chunk_t sk_ai,
        #                                               chunk_t sk_ar, chunk_t sk_ei, chunk_t sk_er,
        #                                               chunk_t sk_pi, chunk_t sk_pr)
        # Each chunk_t is passed as 2 values (ptr, len)
        if not symbolic_ok:
            print("[IKE keys] No debug symbols, using register fallback")

            if arch.is_x86_64:
                # x86_64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
                # Arg0 (rdi): this
                # Arg1-2 (rsi, rdx): sk_d
                # Arg3-4 (rcx, r8): sk_ai
                # Arg5-6 (r9, stack[0]): sk_ar
                # Arg7-8 (stack[8], stack[16]): sk_ei
                # Arg9-10 (stack[24], stack[32]): sk_er
                # Arg11-12 (stack[40], stack[48]): sk_pi
                # Arg13-14 (stack[56], stack[64]): sk_pr
                try:
                    import struct
                    sp = arch.read_register("rsp")

                    # sk_d: rsi, rdx
                    ptr, length, data = chunk_reader.read_chunk_from_args(1, 2)
                    if length > 0:
                        keys["sk_d"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}

                    # sk_ai: rcx, r8
                    ptr, length, data = chunk_reader.read_chunk_from_args(3, 4)
                    if length > 0:
                        keys["sk_ai"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}

                    # sk_ar: r9, stack[0] - need manual read since it spans register/stack
                    sk_ar_ptr = arch.read_register("r9")
                    sk_ar_len = 32  # Default to 32 bytes
                    if sk_ar_ptr:
                        error = lldb.SBError()
                        stack_data = process.ReadMemory(sp + 8, 8, error)
                        if error.Success():
                            try:
                                read_len = struct.unpack("<Q", bytes(stack_data))[0]
                                if 0 < read_len < 65536:
                                    sk_ar_len = read_len
                                else:
                                    print(f"[IKE keys] sk_ar length invalid ({read_len}), defaulting to 32")
                            except:
                                print(f"[IKE keys] sk_ar length read failed, defaulting to 32")
                        else:
                            print(f"[IKE keys] sk_ar stack read failed: {error.GetCString()}, defaulting to 32")

                        error = lldb.SBError()
                        data = process.ReadMemory(sk_ar_ptr, sk_ar_len, error)
                        if error.Success():
                            keys["sk_ar"] = {"len": sk_ar_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                        else:
                            print(f"[IKE keys] sk_ar data read failed: {error.GetCString()}")

                    # sk_ei: stack[8], stack[16]
                    sk_ei_ptr = None
                    sk_ei_len = 32  # Default to 32 bytes

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 16, 16, error)
                    if error.Success():
                        try:
                            sk_ei_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_ei_len = read_len
                            else:
                                print(f"[IKE keys] sk_ei length invalid ({read_len}), defaulting to 32")
                        except:
                            print(f"[IKE keys] sk_ei unpack failed, defaulting to 32")
                    else:
                        print(f"[IKE keys] sk_ei stack read failed: {error.GetCString()}, defaulting to 32")

                    if sk_ei_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_ei_ptr, sk_ei_len, error)
                        if error.Success():
                            keys["sk_ei"] = {"len": sk_ei_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                        else:
                            print(f"[IKE keys] sk_ei data read failed: {error.GetCString()}")

                    # sk_er: stack[24], stack[32]
                    sk_er_ptr = None
                    sk_er_len = 32  # Default to 32 bytes

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 32, 16, error)
                    if error.Success():
                        try:
                            sk_er_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_er_len = read_len
                            else:
                                print(f"[IKE keys] sk_er length invalid ({read_len}), defaulting to 32")
                        except:
                            print(f"[IKE keys] sk_er unpack failed, defaulting to 32")
                    else:
                        print(f"[IKE keys] sk_er stack read failed: {error.GetCString()}, defaulting to 32")

                    if sk_er_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_er_ptr, sk_er_len, error)
                        if error.Success():
                            keys["sk_er"] = {"len": sk_er_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                        else:
                            print(f"[IKE keys] sk_er data read failed: {error.GetCString()}")

                    # sk_pi: stack[40], stack[48]
                    sk_pi_ptr = None
                    sk_pi_len = 32

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 48, 16, error)
                    if error.Success():
                        try:
                            sk_pi_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_pi_len = read_len
                        except:
                            pass

                    if sk_pi_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_pi_ptr, sk_pi_len, error)
                        if error.Success():
                            keys["sk_pi"] = {"len": sk_pi_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}

                    # sk_pr: stack[56], stack[64]
                    sk_pr_ptr = None
                    sk_pr_len = 32

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 64, 16, error)
                    if error.Success():
                        try:
                            sk_pr_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_pr_len = read_len
                        except:
                            pass

                    if sk_pr_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_pr_ptr, sk_pr_len, error)
                        if error.Success():
                            keys["sk_pr"] = {"len": sk_pr_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}

                except Exception as e:
                    print(f"[IKE keys] Register read error: {e}")

            elif arch.is_aarch64:
                # aarch64 AAPCS64: x0-x7 for args, then stack
                # Arg0 (x0): this
                # Arg1-2 (x1, x2): sk_d
                # Arg3-4 (x3, x4): sk_ai ← CONFIRMED
                # Arg5-6 (x5, x6): sk_ar ← CONFIRMED
                # Arg7 (x7): ??? (unused or padding)
                # Arg8-9 (stack[0], stack[8]): sk_ei ← CONFIRMED
                # Arg10-11 (stack[16], stack[24]): sk_er ← CONFIRMED
                # Arg12-13 (stack[32], stack[40]): sk_pi
                # Arg14-15 (stack[48], stack[56]): sk_pr
                try:
                    import struct
                    sp = arch.read_register("sp")

                    # sk_d: x1, x2
                    ptr, length, data = chunk_reader.read_chunk_from_args(1, 2)
                    if length > 0:
                        keys["sk_d"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}

                    # sk_ai: x3, x4
                    ptr, length, data = chunk_reader.read_chunk_from_args(3, 4)
                    if length > 0:
                        keys["sk_ai"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}

                    # sk_ar: x5, x6
                    ptr, length, data = chunk_reader.read_chunk_from_args(5, 6)
                    if length > 0:
                        keys["sk_ar"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}

                    # sk_ei: stack[0], stack[8] (arg8, arg9)
                    sk_ei_ptr = None
                    sk_ei_len = 32  # Default to 32 bytes

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp, 16, error)  # Read arg8 and arg9
                    if error.Success():
                        try:
                            sk_ei_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_ei_len = read_len
                            else:
                                print(f"[IKE keys] sk_ei length invalid ({read_len}), defaulting to 32")
                        except:
                            print(f"[IKE keys] sk_ei unpack failed, defaulting to 32")
                    else:
                        print(f"[IKE keys] sk_ei stack read failed: {error.GetCString()}, defaulting to 32")

                    if sk_ei_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_ei_ptr, sk_ei_len, error)
                        if error.Success():
                            keys["sk_ei"] = {"len": sk_ei_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                        else:
                            print(f"[IKE keys] sk_ei data read failed: {error.GetCString()}")

                    # sk_er: stack[16], stack[24] (arg10, arg11)
                    sk_er_ptr = None
                    sk_er_len = 32  # Default to 32 bytes

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 16, 16, error)  # Read arg10 and arg11
                    if error.Success():
                        try:
                            sk_er_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_er_len = read_len
                            else:
                                print(f"[IKE keys] sk_er length invalid ({read_len}), defaulting to 32")
                        except:
                            print(f"[IKE keys] sk_er unpack failed, defaulting to 32")
                    else:
                        print(f"[IKE keys] sk_er stack read failed: {error.GetCString()}, defaulting to 32")

                    if sk_er_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_er_ptr, sk_er_len, error)
                        if error.Success():
                            keys["sk_er"] = {"len": sk_er_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                        else:
                            print(f"[IKE keys] sk_er data read failed: {error.GetCString()}")

                    # sk_pi: stack[32], stack[40]
                    sk_pi_ptr = None
                    sk_pi_len = 32

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 32, 16, error)
                    if error.Success():
                        try:
                            sk_pi_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_pi_len = read_len
                        except:
                            pass

                    if sk_pi_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_pi_ptr, sk_pi_len, error)
                        if error.Success():
                            keys["sk_pi"] = {"len": sk_pi_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}

                    # sk_pr: stack[48], stack[56]
                    sk_pr_ptr = None
                    sk_pr_len = 32

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(sp + 48, 16, error)
                    if error.Success():
                        try:
                            sk_pr_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                            if 0 < read_len < 65536:
                                sk_pr_len = read_len
                        except:
                            pass

                    if sk_pr_ptr:
                        error = lldb.SBError()
                        data = process.ReadMemory(sk_pr_ptr, sk_pr_len, error)
                        if error.Success():
                            keys["sk_pr"] = {"len": sk_pr_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}

                except Exception as e:
                    print(f"[IKE keys] Register read error: {e}")

        # Log extracted keys
        if keys:
            print(f"[IKE keys] Extracted {len(keys)} keys:")
            for name, info in keys.items():
                print(f"  {name}: len={info['len']}, sample={info['sample']}")

            if _logger:
                for name, info in keys.items():
                    _logger.log_key_derivation(
                        key_type=f"IKE_{name}",
                        length=info["len"],
                        sample_hex=info["sample"],
                        metadata={"function": "ike_derived_keys"}
                    )

            # Store keys in keylog writer for Wireshark decryption
            # Wrapped in try-catch to ensure memory dumps happen even if keylog fails
            try:
                if _keylog_writer:
                    for name, info in keys.items():
                        if 'full_hex' in info:
                            # Convert hex string back to bytes
                            key_bytes = bytes.fromhex(info['full_hex'])
                            _keylog_writer.add_ike_key(name, key_bytes)
                            print(f"[IKE keys] Added {name} to keylog ({len(key_bytes)} bytes)")

                    # TODO: Extract SPIs and algorithms from IKE_SA or packet capture
                    # For now, finalize with placeholder SPIs
                    print("[IKE keys] Finalizing IKE SA (SPIs will be extracted from pcap later)")
                    _keylog_writer.finalize_ike_sa(
                        encryption_alg="AES-CBC [RFC3602]",
                        integrity_alg="HMAC_SHA2_256_128 [RFC4868]"
                    )
            except Exception as e:
                print(f"[IKE keys] Keylog error (non-fatal): {e}")

            # Take memory dump at handshake if this is the first occurrence
            # Wrapped in try-catch to ensure callback completes even if dump fails
            try:
                if not _checkpoint_counter.get("after_handshake", False) and _dumper:
                    print("[IKE keys] First handshake - taking memory dump")
                    _dumper.dump_full_memory("handshake")
                    _checkpoint_counter["after_handshake"] = True
            except Exception as e:
                print(f"[IKE keys] Memory dump error (non-fatal): {e}")
        else:
            print("[IKE keys] No keys extracted (possible stripped binary + stack args)")

        # Success
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-SUCCESS] ike_derived_keys")
        sys.stdout.flush()

    except Exception as e:
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-ERROR] ike_derived_keys: {e}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()

    finally:
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-END] ike_derived_keys")
        sys.stdout.flush()

    return False  # Continue execution


def esp_key_install_callback(frame, bp_loc, internal_dict):
    """Callback for kernel_interface->add_sa (ESP key installation)

    This function is called when ESP keys are installed to kernel XFRM.
    Tracks: ENCR_i, INTEG_i, ENCR_r, INTEG_r

    Note: Exact function signature depends on strongSwan version
    """
    print("\n[CALLBACK] ESP key installation triggered")

    try:
        arch = ArchitectureHelper(frame)
        chunk_reader = ChunkReader(frame)

        # Try to extract ESP keys from function arguments
        # This is highly dependent on the specific function being hooked
        # May need adjustment based on actual strongSwan version

        print("[ESP] Key installation detected - consider adding specific extraction logic")

        # Log event
        if _logger:
            _logger.log_event("esp_key_install", {
                "message": "ESP keys installed to kernel",
                "function": "kernel_interface_add_sa"
            })

    except Exception as e:
        print(f"[ESP] Callback error: {e}")

    return False


def child_keys_callback(frame, bp_loc, internal_dict):
    """Callback for bus->child_keys(bus_t *this, child_sa_t *child_sa, bool initiator,
                                     array_t *kes, chunk_t nonce_i, chunk_t nonce_r)

    This function is called when CHILD_SA derives ESP/AH keys.
    We track: nonce_i, nonce_r (and later will extract ESP keys from child_sa)

    Function signature (from strongSwan source):
    void (*child_keys)(bus_t *this, child_sa_t *child_sa, bool initiator,
                       array_t *kes, chunk_t nonce_i, chunk_t nonce_r);
    """
    import sys
    import datetime

    timestamp = datetime.datetime.now().isoformat()
    print(f"\n[{timestamp}] [CALLBACK-START] child_keys")
    sys.stdout.flush()

    try:
        arch = ArchitectureHelper(frame)
        chunk_reader = ChunkReader(frame)
        process = frame.GetThread().GetProcess()

        # Extract parameters based on calling convention:
        # Arg0 (x0/rdi): this (bus_t*)
        # Arg1 (x1/rsi): child_sa (child_sa_t*)
        # Arg2 (x2/rdx): initiator (bool)
        # Arg3 (x3/rcx): kes (array_t*)
        # Arg4-5 (x4-x5 / r8-r9): nonce_i (chunk_t - ptr, len)
        # Arg6-7 (x6-x7 / stack): nonce_r (chunk_t - ptr, len)

        keys = {}

        # Read initiator flag
        initiator_val = arch.read_arg_register(2)
        initiator = bool(initiator_val) if initiator_val is not None else None
        print(f"[CHILD keys] Initiator: {initiator}")

        # Read nonce_i
        ptr, length, data = chunk_reader.read_chunk_from_args(4, 5)
        if length > 0:
            keys["nonce_i"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}
            print(f"[CHILD keys] nonce_i: len={length}, sample={data[:32].hex()}")

        # Read nonce_r
        ptr, length, data = chunk_reader.read_chunk_from_args(6, 7)
        if length > 0:
            keys["nonce_r"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}
            print(f"[CHILD keys] nonce_r: len={length}, sample={data[:32].hex()}")

        # Log extracted nonces
        if keys and _logger:
            for name, info in keys.items():
                _logger.log_key_derivation(
                    key_type=f"CHILD_{name}",
                    length=info["len"],
                    sample_hex=info["sample"],
                    metadata={"function": "child_keys", "initiator": initiator}
                )

        # Store nonces in keylog writer
        # These are CHILD_SA nonces used for ESP key derivation
        if keys and _keylog_writer:
            try:
                for name, info in keys.items():
                    if 'full_hex' in info:
                        nonce_bytes = bytes.fromhex(info['full_hex'])
                        # Add as IKE key with CHILD_SA context
                        _keylog_writer.add_ike_key(
                            key_name=f"child_{name}",
                            key_data=nonce_bytes,
                            context={
                                "type": "CHILD_SA_nonce",
                                "initiator": initiator,
                                "note": "Used for ESP key derivation"
                            }
                        )
                        print(f"[CHILD keys] Added {name} to keylog ({len(nonce_bytes)} bytes)")
            except Exception as e:
                print(f"[CHILD keys] Keylog write warning: {e}")

        # TODO: Extract ESP keys from child_sa structure
        # This requires parsing the child_sa_t structure to find keymat

    except Exception as e:
        print(f"[CHILD keys] Callback error: {e}")
        import traceback
        traceback.print_exc()

    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] [CALLBACK-END] child_keys")
    sys.stdout.flush()

    return False


def child_derived_keys_callback(frame, bp_loc, internal_dict):
    """Callback for bus->child_derived_keys(bus_t *this, child_sa_t *child_sa,
                                            bool initiator, chunk_t encr_i, chunk_t encr_r,
                                            chunk_t integ_i, chunk_t integ_r)

    This function is called when CHILD_SA derives the actual ESP/AH encryption and integrity keys.
    We track: encr_i, encr_r, integ_i, integ_r

    Function signature (from strongSwan source):
    void (*child_derived_keys)(bus_t *this, child_sa_t *child_sa,
                               bool initiator, chunk_t encr_i, chunk_t encr_r,
                               chunk_t integ_i, chunk_t integ_r);
    """
    import sys
    import datetime

    timestamp = datetime.datetime.now().isoformat()
    print(f"\n[{timestamp}] [CALLBACK-START] child_derived_keys")
    sys.stdout.flush()

    try:
        arch = ArchitectureHelper(frame)
        chunk_reader = ChunkReader(frame)
        process = frame.GetThread().GetProcess()

        # Extract parameters based on calling convention:
        # Based on ike_derived_keys pattern, arg7 seems to be skipped
        # Arg0 (x0/rdi): this (bus_t*)
        # Arg1 (x1/rsi): child_sa (child_sa_t*)
        # Arg2 (x2/rdx): initiator (bool)
        # Arg3-4 (x3-x4 / rcx-r8): encr_i (chunk_t - ptr, len)
        # Arg5-6 (x5-x6 / r9-stack): encr_r (chunk_t - ptr, len)
        # Arg7: ??? (skipped/padding)
        # Arg8-9 (stack[0]-stack[8]): integ_i (chunk_t - ptr, len)
        # Arg10-11 (stack[16]-stack[24]): integ_r (chunk_t - ptr, len)

        keys = {}

        # Read initiator flag
        initiator_val = arch.read_arg_register(2)
        initiator = bool(initiator_val) if initiator_val is not None else None
        print(f"[CHILD derived] Initiator: {initiator}")

        if arch.is_x86_64:
            import struct
            sp = arch.read_register("rsp")

            # encr_i: rcx, r8 (arg3, arg4)
            ptr, length, data = chunk_reader.read_chunk_from_args(3, 4)
            if length > 0:
                keys["encr_i"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}
                print(f"[CHILD derived] encr_i: len={length}, sample={data[:32].hex()}")

            # encr_r: r9, stack[0] (arg5, arg6)
            encr_r_ptr = arch.read_register("r9")
            encr_r_len = 32  # Default
            if encr_r_ptr:
                error = lldb.SBError()
                stack_data = process.ReadMemory(sp + 8, 8, error)
                if error.Success():
                    try:
                        read_len = struct.unpack("<Q", bytes(stack_data))[0]
                        if 0 < read_len < 65536:
                            encr_r_len = read_len
                    except:
                        pass
                error = lldb.SBError()
                data = process.ReadMemory(encr_r_ptr, encr_r_len, error)
                if error.Success():
                    keys["encr_r"] = {"len": encr_r_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                    print(f"[CHILD derived] encr_r: len={encr_r_len}, sample={bytes(data)[:32].hex()}")

            # integ_i: stack[8], stack[16] (arg7, arg8) - but arg7 might be skipped, so try stack[16], stack[24]
            # Based on pattern, likely: stack[8], stack[16]
            integ_i_ptr = None
            integ_i_len = 32
            error = lldb.SBError()
            stack_data = process.ReadMemory(sp + 16, 16, error)
            if error.Success():
                try:
                    integ_i_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                    if 0 < read_len < 65536:
                        integ_i_len = read_len
                except:
                    pass
            if integ_i_ptr:
                error = lldb.SBError()
                data = process.ReadMemory(integ_i_ptr, integ_i_len, error)
                if error.Success():
                    keys["integ_i"] = {"len": integ_i_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                    print(f"[CHILD derived] integ_i: len={integ_i_len}, sample={bytes(data)[:32].hex()}")

            # integ_r: stack[32], stack[40]
            integ_r_ptr = None
            integ_r_len = 32
            error = lldb.SBError()
            stack_data = process.ReadMemory(sp + 32, 16, error)
            if error.Success():
                try:
                    integ_r_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                    if 0 < read_len < 65536:
                        integ_r_len = read_len
                except:
                    pass
            if integ_r_ptr:
                error = lldb.SBError()
                data = process.ReadMemory(integ_r_ptr, integ_r_len, error)
                if error.Success():
                    keys["integ_r"] = {"len": integ_r_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                    print(f"[CHILD derived] integ_r: len={integ_r_len}, sample={bytes(data)[:32].hex()}")

        elif arch.is_aarch64:
            import struct
            sp = arch.read_register("sp")

            # encr_i: x3, x4 (arg3, arg4)
            ptr, length, data = chunk_reader.read_chunk_from_args(3, 4)
            if length > 0:
                keys["encr_i"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}
                print(f"[CHILD derived] encr_i: len={length}, sample={data[:32].hex()}")

            # encr_r: x5, x6 (arg5, arg6)
            ptr, length, data = chunk_reader.read_chunk_from_args(5, 6)
            if length > 0:
                keys["encr_r"] = {"len": length, "sample": data[:32].hex(), "full_hex": data.hex()}
                print(f"[CHILD derived] encr_r: len={length}, sample={data[:32].hex()}")

            # integ_i: stack[0], stack[8] (arg8, arg9) - x7 is skipped
            integ_i_ptr = None
            integ_i_len = 32
            error = lldb.SBError()
            stack_data = process.ReadMemory(sp, 16, error)
            if error.Success():
                try:
                    integ_i_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                    if 0 < read_len < 65536:
                        integ_i_len = read_len
                except:
                    pass
            if integ_i_ptr:
                error = lldb.SBError()
                data = process.ReadMemory(integ_i_ptr, integ_i_len, error)
                if error.Success():
                    keys["integ_i"] = {"len": integ_i_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                    print(f"[CHILD derived] integ_i: len={integ_i_len}, sample={bytes(data)[:32].hex()}")

            # integ_r: stack[16], stack[24] (arg10, arg11)
            integ_r_ptr = None
            integ_r_len = 32
            error = lldb.SBError()
            stack_data = process.ReadMemory(sp + 16, 16, error)
            if error.Success():
                try:
                    integ_r_ptr, read_len = struct.unpack("<QQ", bytes(stack_data))
                    if 0 < read_len < 65536:
                        integ_r_len = read_len
                except:
                    pass
            if integ_r_ptr:
                error = lldb.SBError()
                data = process.ReadMemory(integ_r_ptr, integ_r_len, error)
                if error.Success():
                    keys["integ_r"] = {"len": integ_r_len, "sample": bytes(data)[:32].hex(), "full_hex": bytes(data).hex()}
                    print(f"[CHILD derived] integ_r: len={integ_r_len}, sample={bytes(data)[:32].hex()}")

        # Log extracted keys
        if keys:
            print(f"[CHILD derived] Extracted {len(keys)} keys")
            if _logger:
                for name, info in keys.items():
                    _logger.log_key_derivation(
                        key_type=f"ESP_{name}",
                        length=info["len"],
                        sample_hex=info["sample"],
                        metadata={"function": "child_derived_keys", "initiator": initiator}
                    )

            # Store in keylog writer with placeholder SPI/IPs
            # These will be extracted from kernel XFRM or Wireshark pcap analysis
            if _keylog_writer and 'encr_i' in keys and 'encr_r' in keys:
                try:
                    # Use placeholder values - actual SPI and IPs extracted from XFRM/pcap
                    enc_i = bytes.fromhex(keys['encr_i']['full_hex'])
                    enc_r = bytes.fromhex(keys['encr_r']['full_hex'])
                    auth_i = bytes.fromhex(keys.get('integ_i', {}).get('full_hex', '')) if 'integ_i' in keys else None
                    auth_r = bytes.fromhex(keys.get('integ_r', {}).get('full_hex', '')) if 'integ_r' in keys else None

                    # Add both directions (initiator->responder and responder->initiator)
                    _keylog_writer.add_esp_key(
                        spi="XFRM_OUT",  # Placeholder - extract from kernel XFRM
                        src="XFRM_SRC",  # Placeholder - extract from kernel XFRM or pcap
                        dst="XFRM_DST",  # Placeholder - extract from kernel XFRM or pcap
                        enc_key=enc_i,
                        auth_key=auth_i,
                        cipher="AES-CBC [RFC3602]",  # Placeholder - extract from XFRM
                        auth_alg="HMAC-SHA-2-256 [RFC4868]"  # Placeholder - extract from XFRM
                    )

                    _keylog_writer.add_esp_key(
                        spi="XFRM_IN",  # Placeholder - extract from kernel XFRM
                        src="XFRM_DST",  # Placeholder - extract from kernel XFRM or pcap
                        dst="XFRM_SRC",  # Placeholder - extract from kernel XFRM or pcap
                        enc_key=enc_r,
                        auth_key=auth_r,
                        cipher="AES-CBC [RFC3602]",  # Placeholder - extract from XFRM
                        auth_alg="HMAC-SHA-2-256 [RFC4868]"  # Placeholder - extract from XFRM
                    )

                    print(f"[CHILD derived] Added ESP keys to keylog (SPI/IPs: extract from XFRM/pcap)")
                except Exception as e:
                    print(f"[CHILD derived] Keylog write warning: {e}")

    except Exception as e:
        print(f"[CHILD derived] Callback error: {e}")
        import traceback
        traceback.print_exc()

    timestamp = datetime.datetime.now().isoformat()
    print(f"[{timestamp}] [CALLBACK-END] child_derived_keys")
    sys.stdout.flush()

    return False


def prf_set_key_callback(frame, bp_loc, internal_dict):
    """Callback for prf->set_key(prf, chunk_t key)

    Tracks PRF key settings during IKE key derivation.
    The first PRF key set during IKE_SA_INIT phase is likely SKEYSEED.
    """
    global _keylog_writer, _prf_key_counter

    print("\n[CALLBACK] prf_set_key triggered")

    try:
        _prf_key_counter += 1
        chunk_reader = ChunkReader(frame)

        # Read key from args (arg0=prf*, arg1=key.ptr, arg2=key.len)
        ptr, length, data = chunk_reader.read_chunk_from_args(1, 2)

        if length > 0:
            print(f"[PRF] set_key #{_prf_key_counter}: len={length}, sample={format_hex(data, 32)}")

            # Heuristic: First PRF key is likely SKEYSEED during IKE_SA_INIT
            # Subsequent calls might be SK_d for CHILD SA derivation
            key_name = "SKEYSEED" if _prf_key_counter == 1 else f"PRF_key_{_prf_key_counter}"

            if _logger:
                _logger.log_key_derivation(
                    key_type=key_name,
                    length=length,
                    sample_hex=data[:32].hex(),
                    metadata={"function": "prf_set_key", "sequence": _prf_key_counter}
                )

            # Save to keylog for later dump analysis
            if _keylog_writer:
                try:
                    _keylog_writer.add_ike_key(key_name, data)
                    print(f"[PRF] Saved {key_name} to keylog ({length} bytes)")
                except Exception as e:
                    print(f"[PRF] Keylog write error: {e}")

    except Exception as e:
        print(f"[PRF] Callback error: {e}")

    return False


def prf_plus_create_callback(frame, bp_loc, internal_dict):
    """Callback for prf_plus_create(prf, chunk_t seed)

    Tracks PRF+ seed during IKE key expansion
    """
    print("\n[CALLBACK] prf_plus_create triggered")

    try:
        chunk_reader = ChunkReader(frame)

        # Read seed from args (arg0=prf*, arg1=seed.ptr, arg2=seed.len)
        ptr, length, data = chunk_reader.read_chunk_from_args(1, 2)

        if length > 0:
            print(f"[PRF+] seed: len={length}, sample={format_hex(data, 32)}")

            if _logger:
                _logger.log_key_derivation(
                    key_type="PRF+_seed",
                    length=length,
                    sample_hex=data[:32].hex(),
                    metadata={"function": "prf_plus_create"}
                )

    except Exception as e:
        print(f"[PRF+] Callback error: {e}")

    return False


def rekey_callback(frame, bp_loc, internal_dict):
    """Callback for IKE/CHILD SA rekey operations"""
    global _checkpoint_counter

    print("\n[CALLBACK] Rekey operation triggered")

    try:
        if _dumper and _checkpoint_counter["handshake"]:
            print("[Rekey] Taking memory dump")
            _dumper.dump_full_memory("rekey")
            _checkpoint_counter["rekey"] = True

        if _logger:
            _logger.log_event("rekey", {"message": "Rekey operation initiated"})

    except Exception as e:
        print(f"[Rekey] Callback error: {e}")

    return False


def terminate_callback(frame, bp_loc, internal_dict):
    """Callback for SA termination"""
    global _checkpoint_counter

    print("\n[CALLBACK] SA termination triggered")

    try:
        if _dumper:
            print("[Terminate] Taking memory dump")
            _dumper.dump_full_memory("terminate")
            _checkpoint_counter["terminate"] = True

        if _logger:
            _logger.log_event("terminate", {"message": "SA terminated"})

    except Exception as e:
        print(f"[Terminate] Callback error: {e}")

    return False


#=============================================================================
# Helper Functions
#=============================================================================

def read_c_string(process, addr, max_len=256):
    """Read null-terminated C string from memory

    Args:
        process: lldb.SBProcess
        addr: Memory address of string
        max_len: Maximum length to read

    Returns:
        str: The C string, or empty string on error
    """
    if not addr or addr == 0:
        return ""

    err = lldb.SBError()
    data = process.ReadMemory(addr, max_len, err)

    if not err.Success():
        return ""

    # Find null terminator
    if b'\x00' in data:
        data = data[:data.index(b'\x00')]

    # Decode to string
    try:
        return data.decode('utf-8', errors='replace')
    except:
        return str(data)


#=============================================================================
# chunk_split Callback
#=============================================================================

def chunk_split_callback(frame, bp_loc, internal_dict):
    """
    Hook chunk_split(chunk_t data, const char *mode)
    Extracts key material when strongSwan splits chunk_t structures

    strongSwan function signature:
        chunk_t chunk_split(chunk_t data, const char *mode)

    Architecture-specific:
    - ARM64 (aarch64): x0=chunk_t.ptr, x1=chunk_t.len, x2=mode
    - x86_64: rdi=chunk_t.ptr, rsi=chunk_t.len, rdx=mode

    The chunk_t is passed as two separate arguments (exploded struct):
    - arg0: u_int8_t *ptr
    - arg1: size_t len
    - arg2: const char *mode (split mode string)

    Key mode strings (from research):
    - "ammmmaa": IKE SA keys (SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr)
    - "aaaa": CHILD SA / ESP keys (ENCR_i, INTEG_i, ENCR_r, INTEG_r)
    - Also: len=0xE0 (224 bytes) typically indicates IKE SA for AES-256+SHA256
    """
    import sys
    import datetime
    global _checkpoint_counter

    timestamp = datetime.datetime.now().isoformat()
    print(f"\n[{timestamp}] [CALLBACK-START] chunk_split")
    sys.stdout.flush()

    try:
        # Get chunk reader (architecture is auto-detected inside)
        reader = ChunkReader(frame)
        arch = reader.arch  # Use the auto-detected architecture from reader
        process = frame.GetThread().GetProcess()

        # Read the chunk_t being split (exploded: arg0=ptr, arg1=len)
        # Returns: (ptr, len, data_bytes)
        data_ptr, data_len, data_bytes = reader.read_chunk_from_args(ptr_arg_idx=0, len_arg_idx=1)

        # Read mode string (arg2)
        mode_ptr = arch.read_arg_register(2)
        mode = read_c_string(process, mode_ptr, max_len=32) if mode_ptr else None

        # FILTER: Only process IKE SA and CHILD SA key splits
        # "ammmmaa" = IKE SA keys, "aaaa" = ESP keys, or len=0xE0 = likely IKE SA
        is_ike_sa = (mode == "ammmmaa") or (data_len == 0xE0)
        is_child_sa = (mode == "aaaa")

        if not (is_ike_sa or is_child_sa):
            # Skip non-key chunk_split operations (reduces noise)
            return False

        # Only log if we have meaningful data
        if data_ptr and data_len > 0 and data_len < 10000:  # Sanity check
            # Read the actual chunk data
            err = lldb.SBError()
            data = process.ReadMemory(data_ptr, data_len, err)

            if err.Success() and data:
                data_hex = format_hex(data)

                # Determine key type for logging
                if is_ike_sa:
                    key_type = "IKE_SA"
                    print(f"\n[chunk_split] **IKE SA KEYS** mode={mode!r}, len=0x{data_len:x} ({data_len} bytes)")

                    # Parse IKE SA keys from "ammmmaa" mode
                    # Based on lldb_chunk_split.py lines 379-416
                    if mode == "ammmmaa":
                        try:
                            sp = arch.read_register(arch.get_register_names()["sp"])

                            if arch.is_aarch64:
                                # ARM64: x3=prf_len, x5=ai_len, x7=ar_len, sp+0x08=ei_len, sp+0x18=er_len
                                prf_len = arch.read_arg_register(3) or 32
                                ai_len = arch.read_arg_register(5) or 32
                                ar_len = arch.read_arg_register(7) or 32
                                ei_len = _read_u64(process, sp + 0x08) if sp else 32
                                er_len = _read_u64(process, sp + 0x18) if sp else 32
                            else:
                                # x86_64: rcx=prf_len, r9=ai_len, sp+0x10=ar_len, sp+0x20=ei_len, sp+0x30=er_len
                                prf_len = arch.read_register("rcx") or 32
                                ai_len = arch.read_register("r9") or 32
                                ar_len = _read_u64(process, sp + 0x10) if sp else 32
                                ei_len = _read_u64(process, sp + 0x20) if sp else 32
                                er_len = _read_u64(process, sp + 0x30) if sp else 32

                            # Default to 32 bytes if couldn't read from stack
                            if ei_len is None: ei_len = 32
                            if er_len is None: er_len = 32

                            data_bytes = bytes(data) if not isinstance(data, bytes) else data

                            # Layout: SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
                            layout = [
                                ("SK_d", prf_len),
                                ("SK_ai", ai_len),
                                ("SK_ar", ar_len),
                                ("SK_ei", ei_len),
                                ("SK_er", er_len),
                                ("SK_pi", prf_len),
                                ("SK_pr", prf_len),
                            ]

                            print(f"[IKE SA keys] Extracted {len(layout)} keys:")
                            offset = 0
                            ike_keys = {}
                            for name, size in layout:
                                if offset + size <= len(data_bytes):
                                    key_data = data_bytes[offset:offset+size]
                                    ike_keys[name] = key_data
                                    full_hex = key_data.hex()
                                    print(f"  {name}: {full_hex}")

                                    # Set hardware watchpoint on sk_ei and sk_er (2 of 4 max watchpoints)
                                    if _target and name in ["SK_ei", "SK_er"]:
                                        callback_map = {
                                            "SK_ei": "watchpoint_sk_ei_callback",
                                            "SK_er": "watchpoint_sk_er_callback"
                                        }
                                        _set_watchpoint(name, data_ptr, offset, key_data, callback_map[name])

                                    offset += size

                                    # Add to keylog writer
                                    if _keylog_writer and name in ["SK_ei", "SK_er", "SK_ai", "SK_ar", "SK_pi", "SK_pr"]:
                                        try:
                                            _keylog_writer.add_ike_key(name, key_data)
                                        except Exception as e:
                                            print(f"[IKE SA keys] Keylog error for {name} (non-fatal): {e}")
                                else:
                                    print(f"[IKE SA keys] Warning: {name} extends beyond data (offset={offset}, size={size}, total={len(data_bytes)})")
                                    break

                            total_expected = sum(s for _, s in layout)
                            if total_expected != data_len:
                                print(f"[IKE SA keys] Warning: declared sum=0x{total_expected:x} != len=0x{data_len:x}")

                        except Exception as e:
                            print(f"[IKE SA keys] Parsing error (non-fatal): {e}")
                            import traceback
                            traceback.print_exc()
                            # Fall back to printing raw KEYMAT
                            if data_len <= 256:
                                print(f"  KEYMAT: {data_hex}")
                            else:
                                print(f"  KEYMAT: {data_hex[:512]}... (total {data_len} bytes)")
                    else:
                        # Not ammmmaa mode, just print raw KEYMAT
                        if data_len <= 256:
                            print(f"  KEYMAT: {data_hex}")
                        else:
                            print(f"  KEYMAT: {data_hex[:512]}... (total {data_len} bytes)")

                    # Finalize IKE SA after all keys have been extracted and added
                    if _keylog_writer:
                        try:
                            print("[IKE SA keys] Finalizing IKE SA keylog entry")
                            _keylog_writer.finalize_ike_sa(
                                encryption_alg="AES-CBC [RFC3602]",
                                integrity_alg="HMAC_SHA2_256_128 [RFC4868]"
                            )
                            # DON'T write here - file I/O in callbacks causes LLDB state corruption
                            # Keys will be written periodically by monitoring loop (every 30s)
                            print("[IKE SA keys] IKE SA finalized (will be written by periodic sync)")
                        except Exception as e:
                            print(f"[IKE SA keys] Keylog error (non-fatal): {e}")

                else:
                    key_type = "CHILD_SA"
                    print(f"\n[chunk_split] **ESP/CHILD SA KEYS** mode={mode!r}, len=0x{data_len:x} ({data_len} bytes)")

                    # Take before_child_sa dump on first ESP key detection
                    try:
                        if not _checkpoint_counter.get("before_child_sa"):
                            if _dumper:
                                print("[chunk_split] First ESP keys detected - taking BEFORE child_sa dump")
                                _dumper.dump_full_memory("before_child_sa")
                                _checkpoint_counter["before_child_sa"] = True
                    except Exception as e:
                        print(f"[chunk_split] Memory dump error (non-fatal): {e}")

                    # Parse ESP keys from "aaaa" mode (4 keys of equal size typically)
                    # ENCR_i, INTEG_i, ENCR_r, INTEG_r
                    if mode == "aaaa" and data_len >= 16:
                        try:
                            # Read the actual key sizes from registers/stack
                            # Based on lldb_chunk_split.py lines 423-436
                            sp = arch.read_register(arch.get_register_names()["sp"])

                            if arch.is_aarch64:
                                # ARM64: x3, x5, x7, sp+0x08
                                enc_i_len = arch.read_arg_register(3) or 0
                                integ_i_len = arch.read_arg_register(5) or 0
                                enc_r_len = arch.read_arg_register(7) or 0
                                integ_r_len = _read_u64(process, sp + 0x08) if sp else None
                            else:
                                # x86_64: rcx, r8, r9, sp+0x08
                                enc_i_len = arch.read_register("rcx") or 0
                                integ_i_len = arch.read_register("r8") or 0
                                enc_r_len = arch.read_register("r9") or 0
                                integ_r_len = _read_u64(process, sp + 0x08) if sp else None

                            if integ_r_len is None:
                                # Fallback to equal-sized keys
                                print(f"[ESP keys] Could not read integ_r_len from stack, using equal split")
                                key_size = data_len // 4
                                enc_i_len = integ_i_len = enc_r_len = integ_r_len = key_size

                            data_bytes = bytes(data) if not isinstance(data, bytes) else data

                            # Split based on actual sizes
                            offset = 0
                            esp_keys = {}
                            key_offsets = {}  # Track offsets for watchpoints
                            for name, size in [("ENCR_i", enc_i_len), ("INTEG_i", integ_i_len),
                                              ("ENCR_r", enc_r_len), ("INTEG_r", integ_r_len)]:
                                if offset + size <= len(data_bytes):
                                    esp_keys[name] = data_bytes[offset:offset+size]
                                    key_offsets[name] = offset
                                    offset += size
                                else:
                                    print(f"[ESP keys] Warning: {name} extends beyond data")
                                    break

                            print(f"[ESP keys] Extracted {len(esp_keys)} keys:")
                            for name, key_data in esp_keys.items():
                                full_hex = key_data.hex()
                                print(f"  {name}: {full_hex}")

                                # Set hardware watchpoint on ENCR_i and ENCR_r (2 of 4 max watchpoints)
                                if _target and name in ["ENCR_i", "ENCR_r"]:
                                    callback_map = {
                                        "ENCR_i": "watchpoint_ENCR_i_callback",
                                        "ENCR_r": "watchpoint_ENCR_r_callback"
                                    }
                                    _set_watchpoint(name, data_ptr, key_offsets[name], key_data, callback_map[name])

                            # Note: add_esp_key() requires SPI/IP metadata we don't have here
                            # Kernel monitoring will capture full ESP SA with metadata

                        except Exception as e:
                            print(f"[ESP keys] Parsing error (non-fatal): {e}")
                            import traceback
                            traceback.print_exc()
                            # Fall back to printing raw KEYMAT
                            if data_len <= 256:
                                print(f"  KEYMAT: {data_hex}")
                            else:
                                print(f"  KEYMAT: {data_hex[:512]}... (total {data_len} bytes)")
                    else:
                        # Unknown mode or too small, just print raw
                        if data_len <= 256:
                            print(f"  KEYMAT: {data_hex}")
                        else:
                            print(f"  KEYMAT: {data_hex[:512]}... (total {data_len} bytes)")

                # Log to event logger
                if _logger:
                    _logger.log_event("chunk_split", {
                        "key_type": key_type,
                        "mode": mode,
                        "length": data_len,
                        "length_hex": f"0x{data_len:x}",
                        "data_hex": data_hex,
                    })

                # Trigger memory dumps for first IKE handshake: before and after
                # Wrapped in try-catch to ensure key extraction completes even if dump fails
                try:
                    if is_ike_sa and not _checkpoint_counter.get("before_handshake"):
                        if _dumper:
                            print("[chunk_split] First IKE SA keys detected - taking BEFORE handshake dump")
                            _dumper.dump_full_memory("before_handshake")
                            _checkpoint_counter["before_handshake"] = True
                except Exception as e:
                    print(f"[chunk_split] Memory dump error (non-fatal): {e}")

        # Success
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-SUCCESS] chunk_split")
        sys.stdout.flush()

    except Exception as e:
        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-ERROR] chunk_split: {e}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()

    finally:
        # Take AFTER dumps at the end of callback
        try:
            # After handshake dump (if before was taken)
            if _checkpoint_counter.get("before_handshake") and not _checkpoint_counter.get("after_handshake"):
                if _dumper:
                    print("[chunk_split] Taking AFTER handshake dump")
                    _dumper.dump_full_memory("after_handshake")
                    _checkpoint_counter["after_handshake"] = True

            # After CHILD_SA dump (if before was taken)
            if _checkpoint_counter.get("before_child_sa") and not _checkpoint_counter.get("after_child_sa"):
                if _dumper:
                    print("[chunk_split] Taking AFTER child_sa dump")
                    _dumper.dump_full_memory("after_child_sa")
                    _checkpoint_counter["after_child_sa"] = True

        except Exception as e:
            print(f"[chunk_split] After-dump error (non-fatal): {e}")

        timestamp = datetime.datetime.now().isoformat()
        print(f"[{timestamp}] [CALLBACK-END] chunk_split")
        sys.stdout.flush()

    # Return False to let LLDB automatically continue the process
    # DON'T manually call process.Continue() - it causes race conditions with watchpoint setup
    return False


#=============================================================================
# Lifecycle Callbacks - Terminate Operations
#=============================================================================

def terminate_child_execute_callback(frame, bp_loc, internal_dict):
    """Callback for terminate_child_execute function entry

    This function is called when a Child SA is being terminated.
    Take memory dumps before and after termination to track key cleanup.
    """
    global _checkpoint_counter

    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] terminate_child_execute - ENTRY")
        print("=" * 70)

        # Get function arguments if available
        args = []
        for i in range(3):  # Try to get first few arguments
            try:
                arg_val = frame.FindVariable(f"arg{i}")
                if arg_val.IsValid():
                    args.append(str(arg_val))
            except:
                pass

        if args:
            print(f"[terminate_child] Arguments: {', '.join(args)}")

        # Take BEFORE terminate dump
        if _dumper and not _checkpoint_counter.get("before_terminate"):
            print("[terminate_child] Taking BEFORE terminate dump...")
            _dumper.dump_full_memory("before_terminate")
            _checkpoint_counter["before_terminate"] = True

        # Log event
        if _logger:
            _logger.log_event("terminate_child_execute", {
                "event": "Child SA termination started",
                "args": args
            })

        # Trigger kernel checkpoint
        print("[terminate_child] Triggering kernel checkpoint...")
        trigger_kernel_checkpoint("terminate_child")

        print("[terminate_child] Callback complete - continuing execution")

    except Exception as e:
        print(f"[terminate_child] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Take AFTER terminate dump
        try:
            if _checkpoint_counter.get("before_terminate") and not _checkpoint_counter.get("after_terminate"):
                if _dumper:
                    print("[terminate_child] Taking AFTER terminate dump...")
                    _dumper.dump_full_memory("after_terminate")
                    _checkpoint_counter["after_terminate"] = True
        except Exception as e:
            print(f"[terminate_child] After-dump error (non-fatal): {e}")

    return False  # Continue execution


def terminate_ike_execute_callback(frame, bp_loc, internal_dict):
    """Callback for terminate_ike_execute function entry

    This function is called when an IKE SA is being terminated.
    Sets a one-shot breakpoint on return address to capture state AFTER termination.
    """
    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] terminate_ike_execute - ENTRY")
        print("=" * 70)

        # Take userspace memory dump BEFORE termination
        if _dumper:
            print("[terminate_ike] Taking userspace memory dump (before termination)...")
            _dumper.dump_full_memory("terminate_ike_entry")

        # Log event
        if _logger:
            _logger.log_event("terminate_ike_execute", {
                "event": "IKE SA termination started"
            })

        # Trigger kernel checkpoint
        print("[terminate_ike] Triggering kernel checkpoint...")
        trigger_kernel_checkpoint("terminate_ike")

        # Set one-shot breakpoint on return address to capture state AFTER termination
        try:
            arch = ArchitectureHelper(frame)
            return_addr = arch.get_return_address()

            if return_addr and _target:
                ret_bp = _target.BreakpointCreateByAddress(return_addr)
                if ret_bp and ret_bp.IsValid():
                    ret_bp.SetOneShot(True)
                    ret_bp.SetScriptCallbackFunction("strongswan_callbacks.terminate_ike_exit_callback")
                    ret_bp.SetAutoContinue(True)  # Auto-continue after callback (like all other breakpoints)
                    print(f"[terminate_ike] Set one-shot breakpoint on return @ 0x{return_addr:x}")
                else:
                    print(f"[terminate_ike] Warning: Failed to set return breakpoint")
            else:
                print(f"[terminate_ike] Warning: Could not get return address (target={_target is not None})")
        except Exception as e:
            print(f"[terminate_ike] Warning: Could not set return breakpoint: {e}")

        print("[terminate_ike] Callback complete - continuing execution")

    except Exception as e:
        print(f"[terminate_ike] Error: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution


def terminate_ike_exit_callback(frame, bp_loc, internal_dict):
    """Callback for terminate_ike_execute function EXIT

    This function is called AFTER IKE SA termination completes.
    Captures the final state to see if keys were cleared.
    """
    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] terminate_ike_execute - EXIT")
        print("=" * 70)

        # Take userspace memory dump AFTER termination
        if _dumper:
            print("[terminate_ike] Taking userspace memory dump (after termination)...")
            _dumper.dump_full_memory("terminate_ike_exit")

        # Trigger kernel checkpoint
        print("[terminate_ike] Triggering kernel checkpoint after exit...")
        trigger_kernel_checkpoint("terminate_ike_exit")

        print("[terminate_ike] Exit callback complete")

    except Exception as e:
        print(f"[terminate_ike] Exit callback error: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution


#=============================================================================
# Lifecycle Callbacks - State Change Operations
#=============================================================================

def ike_state_change_terminate_callback(frame, bp_loc, internal_dict):
    """Callback for ike_state_change_terminate function entry

    This function is called when IKE SA state changes to terminate.
    """
    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] ike_state_change_terminate - ENTRY")
        print("=" * 70)

        # Take userspace memory dump
        if _dumper:
            print("[ike_state_terminate] Taking userspace memory dump...")
            _dumper.dump_full_memory("ike_state_terminate_entry")

        # Log event
        if _logger:
            _logger.log_event("ike_state_change_terminate", {
                "event": "IKE SA state changed to terminate"
            })

        # Trigger kernel checkpoint
        trigger_kernel_checkpoint("ike_state_terminate")

    except Exception as e:
        print(f"[ike_state_terminate] Error: {e}")
        import traceback
        traceback.print_exc()

    return False


def child_state_change_terminate_callback(frame, bp_loc, internal_dict):
    """Callback for child_state_change_terminate function entry

    This function is called when Child SA state changes to terminate.
    """
    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] child_state_change_terminate - ENTRY")
        print("=" * 70)

        # Take userspace memory dump
        if _dumper:
            print("[child_state_terminate] Taking userspace memory dump...")
            _dumper.dump_full_memory("child_state_terminate_entry")

        # Log event
        if _logger:
            _logger.log_event("child_state_change_terminate", {
                "event": "Child SA state changed to terminate"
            })

        # Trigger kernel checkpoint
        trigger_kernel_checkpoint("child_state_terminate")

    except Exception as e:
        print(f"[child_state_terminate] Error: {e}")
        import traceback
        traceback.print_exc()

    return False


#=============================================================================
# Lifecycle Callbacks - Rekey Operations
#=============================================================================

def ike_rekey_callback(frame, bp_loc, internal_dict):
    """Callback for ike_rekey function entry

    This function is called when IKE SA rekey is initiated.
    """
    global _checkpoint_counter

    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] ike_rekey - ENTRY")
        print("=" * 70)

        # Take BEFORE rekey dump
        if _dumper and not _checkpoint_counter.get("before_rekey"):
            print("[ike_rekey] Taking BEFORE rekey dump...")
            _dumper.dump_full_memory("before_rekey")
            _checkpoint_counter["before_rekey"] = True

        # Log event
        if _logger:
            _logger.log_event("ike_rekey", {
                "event": "IKE SA rekey initiated"
            })

        # Trigger kernel checkpoint
        trigger_kernel_checkpoint("ike_rekey")

    except Exception as e:
        print(f"[ike_rekey] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Take AFTER rekey dump
        try:
            if _checkpoint_counter.get("before_rekey") and not _checkpoint_counter.get("after_rekey"):
                if _dumper:
                    print("[ike_rekey] Taking AFTER rekey dump...")
                    _dumper.dump_full_memory("after_rekey")
                    _checkpoint_counter["after_rekey"] = True
        except Exception as e:
            print(f"[ike_rekey] After-dump error (non-fatal): {e}")

    return False


def child_rekey_callback(frame, bp_loc, internal_dict):
    """Callback for child_rekey function entry

    This function is called when Child SA rekey is initiated.
    """
    global _checkpoint_counter

    try:
        print("\n" + "=" * 70)
        print("[LIFECYCLE] child_rekey - ENTRY")
        print("=" * 70)

        # Take BEFORE rekey dump (shared with IKE rekey)
        if _dumper and not _checkpoint_counter.get("before_rekey"):
            print("[child_rekey] Taking BEFORE rekey dump...")
            _dumper.dump_full_memory("before_rekey")
            _checkpoint_counter["before_rekey"] = True

        # Log event
        if _logger:
            _logger.log_event("child_rekey", {
                "event": "Child SA rekey initiated"
            })

        # Trigger kernel checkpoint
        trigger_kernel_checkpoint("child_rekey")

    except Exception as e:
        print(f"[child_rekey] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Take AFTER rekey dump (shared with IKE rekey)
        try:
            if _checkpoint_counter.get("before_rekey") and not _checkpoint_counter.get("after_rekey"):
                if _dumper:
                    print("[child_rekey] Taking AFTER rekey dump...")
                    _dumper.dump_full_memory("after_rekey")
                    _checkpoint_counter["after_rekey"] = True
        except Exception as e:
            print(f"[child_rekey] After-dump error (non-fatal): {e}")

    return False


def trigger_kernel_checkpoint(checkpoint_name: str):
    """Trigger a kernel checkpoint by running monitor_kernel_xfrm.py

    This is a best-effort operation - failures are logged but don't stop execution.
    """
    try:
        import subprocess
        import os

        # Get environment variables
        netns = os.environ.get("IPSEC_NETNS", "")
        output_dir = os.environ.get("IPSEC_OUTPUT_DIR", "")

        if not netns or not output_dir:
            print(f"[kernel_checkpoint] Skipping - IPSEC_NETNS or IPSEC_OUTPUT_DIR not set")
            return

        # Find the monitor script (should be in same directory)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        monitor_script = os.path.join(script_dir, "monitor_kernel_xfrm.py")

        if not os.path.exists(monitor_script):
            print(f"[kernel_checkpoint] Warning: {monitor_script} not found")
            return

        # Construct kernel output directory
        kernel_dir = os.path.join(output_dir, "..", "kernel", netns)
        os.makedirs(kernel_dir, exist_ok=True)

        # Run kernel monitor as subprocess (don't wait for completion)
        cmd = ["python3", monitor_script, "--netns", netns, "--output", kernel_dir, "--checkpoint", checkpoint_name]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"[kernel_checkpoint] Triggered for {checkpoint_name}")

    except Exception as e:
        print(f"[kernel_checkpoint] Error: {e} (non-fatal)")
        # Don't propagate the error - this is best effort


def manual_dump(checkpoint_name: str):
    """Manually trigger a userspace memory dump

    This function is called from the monitoring loop when a dump request marker
    file is detected. It's separate from the callback flow to avoid affecting
    the working solution.

    Args:
        checkpoint_name: Name for the checkpoint (e.g., "manual", "debug")
    """
    global _dumper

    if not _dumper:
        print(f"[manual_dump] Error: MemoryDumper not initialized")
        return

    try:
        print(f"\n{'='*70}")
        print(f"[MANUAL DUMP] Triggering userspace memory dump: {checkpoint_name}")
        print(f"{'='*70}")

        _dumper.dump_full_memory(checkpoint_name)

        print(f"[manual_dump] Dump complete: {checkpoint_name}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"[manual_dump] Error: {e}")
        import traceback
        traceback.print_exc()
