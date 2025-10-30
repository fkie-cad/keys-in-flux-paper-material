#!/usr/bin/env python3
"""
libreswan_callbacks.py

Callback functions for libreswan/pluto LLDB monitoring with DUAL HOOKS
- Entry hooks: Capture arguments going IN
- Exit hooks: Capture return values coming OUT

Tracks IKE and ESP key material in userspace via NSS symkey operations

Supported architectures: x86_64, aarch64

Key tracking targets:
- create_symkey: NSS symmetric key creation (entry only)
- chunk_from_symkey: Extract key material (entry + exit with return value)
- ikev2_child_sa_keymat: Child SA key derivation (entry + exit with return PK11SymKey*)

Return value capture strategy:
- Entry callback sets one-shot breakpoint at return address
- Exit callback captures return value from registers
- Works for both PK11SymKey* and chunk_t returns
"""
import lldb
import sys
import os
import struct
import json
from datetime import datetime
from typing import Optional, Dict, TypedDict, Iterable, Tuple, Union

class SecItem(TypedDict):
    len: int
    hex: str  # hex-encoded bytes
    bytes: bytes  # raw bytes

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from shared_ipsec import (
    ArchitectureHelper,
    ChunkReader,
    MemoryDumper,
    EventLogger,
    KeylogWriter,
    format_hex
)


# ============================================================================
# Dual Output Logger (console + file)
# ============================================================================

class DualOutputLogger:
    """Captures all print output to both console and file"""

    def __init__(self, log_file_path: str = None):
        self.log_file_path = log_file_path
        self.log_file = None
        self.enabled = log_file_path is not None

        if self.enabled:
            try:
                log_dir = os.path.dirname(log_file_path)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                self.log_file = open(log_file_path, 'a', buffering=1)
                self._write_header()
            except Exception as e:
                import builtins
                builtins.print(f"[WARN] Failed to open log file {log_file_path}: {e}")
                self.enabled = False

    def _write_header(self):
        if self.log_file:
            self.log_file.write(f"\n{'='*80}\n")
            self.log_file.write(f"LLDB Callback Log Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.write(f"{'='*80}\n\n")
            self.log_file.flush()

    def print(self, message: str, end: str = '\n'):
        import builtins
        builtins.print(message, end=end)
        if self.enabled and self.log_file:
            try:
                self.log_file.write(message + end)
                self.log_file.flush()
            except:
                pass

    def close(self):
        if self.log_file:
            try:
                self.log_file.write(f"\n{'='*80}\n")
                self.log_file.write(f"Session Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.write(f"{'='*80}\n\n")
                self.log_file.close()
            except:
                pass
            finally:
                self.log_file = None


# Global state
_dumper = None
_logger = None
_keylog_writer = None
_timing_logger = None
_dual_logger = None
_target = None  # LLDB target for setting return breakpoints
_debugger = None  # LLDB debugger for watchpoint commands
_symkey_ptr_arg1 = None  # For chunk_from_symkey arg1 tracking
_sk_d_ptr = None  # For ikev2_child_sa_keymat arg1 tracking
DEBUG_RUN = False # Set to True to enable debug prints (e.g. parsing PK11SymKey)
SEC_DEBUG_RUN = True  # Set to True to enable encrypt_key_* function debugging hooks (default: True)
HexLike = Union[str, bytes, bytearray, memoryview]

# Call counters
_call_counters = {}

# Return breakpoint tracking
_return_breakpoints = {}  # Maps breakpoint ID to context data

# Watchpoint tracking (for hardware watchpoints on keys)
_watchpoints = {}  # Maps key_name to {wp_id, addr, value}

ENCR_SPEC: Dict[str, Tuple[int, int]] = {
    # non-AEAD (ESP)
    "AES-CBC-128": (16, 0),
    "AES-CBC-192": (24, 0),
    "AES-CBC-256": (32, 0),
    "3DES":        (24, 0),
    # AEAD (ESP/IKEv2)
    "AES-GCM-128": (16, 4),  # RFC 4106 §8.1 / RFC 5282 §7.1
    "AES-GCM-192": (24, 4),
    "AES-GCM-256": (32, 4),
    "AES-CCM-128": (16, 3),  # RFC 4309 §7.1
    "AES-CCM-256": (32, 3),
    "CHACHA20-POLY1305": (32, 4),  # RFC 7634 §3
}

# Integrity key lengths for ESP/AH (HMAC key sizes = hash output size)
INTEG_LEN: Dict[str, int] = {
    "NONE": 0,  # for AEAD suites
    "HMAC-SHA1-96":        20,
    "HMAC-SHA2-256-128":   32,
    "HMAC-SHA2-384-192":   48,
    "HMAC-SHA2-512-256":   64,
}

def set_global_handlers(dumper: MemoryDumper, logger: EventLogger, keylog_writer=None, timing_logger=None, dual_logger=None):
    """Set global handlers"""
    global _dumper, _logger, _keylog_writer, _timing_logger, _dual_logger
    _dumper = dumper
    _logger = logger
    _keylog_writer = keylog_writer
    _timing_logger = timing_logger
    _dual_logger = dual_logger


def set_target(target):
    """Set LLDB target for return breakpoint management"""
    global _target
    _target = target


def set_debugger(debugger):
    """Set LLDB debugger for watchpoint management"""
    global _debugger
    _debugger = debugger


def _print(message: str, end: str = '\n'):
    """Print to both console and file"""
    if _dual_logger:
        _dual_logger.print(message, end=end)
    else:
        print(message, end=end)


def _get_call_counter(func_name: str) -> int:
    """Get and increment call counter"""
    global _call_counters
    count = _call_counters.get(func_name, 0) + 1
    _call_counters[func_name] = count
    return count


def _read_u64(process, addr: int):
    """Read a 64-bit little-endian value from memory"""
    error = lldb.SBError()
    data = process.ReadMemory(addr, 8, error)
    if not error.Success():
        return None
    return struct.unpack("<Q", bytes(data))[0]


# ============================================================================
# Return Address Breakpoint Mechanism
# ============================================================================

def _get_return_address(frame) -> int:
    """Get the return address for current function

    ARM64: Read from LR (x30) register
    x86_64: Read from stack[0]
    """
    arch = ArchitectureHelper(frame)

    if arch.is_aarch64:
        # ARM64: Return address in LR (x30)
        return_addr = arch.read_register("lr")
        if return_addr and return_addr > 0x1000:
            return return_addr
    else:  # x86_64
        # x86_64: Return address at [rsp]
        sp = arch.read_register("rsp")
        if sp and sp > 0x1000:
            process = frame.GetThread().GetProcess()
            return_addr = _read_u64(process, sp)
            if return_addr and return_addr > 0x1000:
                return return_addr

    return None


def _set_return_breakpoint(frame, callback_function_name: str, context: dict):
    """Set a one-shot breakpoint at return address

    Args:
        frame: Current LLDB frame
        callback_function_name: Name of callback function to invoke (must be in this module)
        context: Dict with context data to pass to callback

    Returns:
        Breakpoint ID or None
    """
    global _target, _return_breakpoints

    if not _target:
        _print(f"[!] Cannot set return breakpoint: target not set")
        return None

    return_addr = _get_return_address(frame)
    if not return_addr:
        _print(f"[!] Could not determine return address")
        return None

    # Create one-shot breakpoint
    bp = _target.BreakpointCreateByAddress(return_addr)
    if not bp or not bp.IsValid():
        _print(f"[!] Failed to create return breakpoint at 0x{return_addr:x}")
        return None

    bp.SetOneShot(True)  # Auto-delete after first hit
    bp.SetAutoContinue(True)  # Auto-continue after callback

    # Store context
    bp_id = bp.GetID()
    _return_breakpoints[bp_id] = context

    # Set callback using Python command
    callback_code = f"""
def _return_bp_{bp_id}_callback(frame, bp_loc, internal_dict):
    import sys
    sys.path.insert(0, '{os.path.dirname(__file__)}')
    import libreswan_callbacks
    return libreswan_callbacks.{callback_function_name}(frame, bp_loc, internal_dict, bp_id={bp_id})
"""

    # Inject callback into Python namespace
    debugger = _target.GetDebugger()
    debugger.HandleCommand(f"script {callback_code}")
    debugger.HandleCommand(f"breakpoint command add -F _return_bp_{bp_id}_callback {bp_id}")

    _print(f"[*] Set return breakpoint at 0x{return_addr:x} (ID: {bp_id})")
    return bp_id


def _get_return_context(bp_id: int) -> dict:
    """Retrieve context for return breakpoint"""
    return _return_breakpoints.get(bp_id, {})


def _cleanup_return_context(bp_id: int):
    """Clean up context after return breakpoint fires"""
    if bp_id in _return_breakpoints:
        del _return_breakpoints[bp_id]


# ============================================================================
# Hardware Watchpoint Mechanism
# ============================================================================

def _set_watchpoint(key_name: str, base_addr: int, offset: int, key_data: bytes, callback_name: str):
    """Set a hardware watchpoint on a key

    Uses the proven TLS monitoring pattern: generate callback as f-string, inject with 'script',
    then attach with 'watchpoint command add -F'. LLDB automatically passes frame, bp_loc, internal_dict.

    Args:
        key_name: Name of key (e.g., "SK_ei", "ENCR_i")
        base_addr: Base address of the PK11SymKey data
        offset: Offset within data where this key starts
        key_data: Key bytes (for logging)
        callback_name: Python callback function name (unused, kept for API compatibility)
    """
    global _watchpoints, _target, _debugger, _timing_logger

    # Skip if already have a watchpoint for this key
    if key_name in _watchpoints:
        _print(f"[WATCHPOINT] {key_name} already tracked, skipping")
        return

    # Calculate actual memory address
    addr = base_addr + offset

    # Check if we have debugger (needed for command-based approach)
    if not _debugger or not _target:
        _print(f"[WATCHPOINT] No debugger/target available for {key_name}, skipping watchpoints")
        return

    try:
        error = lldb.SBError()

        # Set write watchpoint on 4 bytes
        watchpoint = _target.WatchAddress(addr, 4, False, True, error)

        if not error.Success() or not watchpoint.IsValid():
            _print(f"[WATCHPOINT] Failed to set on {key_name}: {error.GetCString()}")
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

        import libreswan_callbacks
        if libreswan_callbacks._timing_logger:
            libreswan_callbacks._timing_logger.log_watchpoint_hit("{fixed_key_name}", {fixed_addr}, None, bytes(new_data))

    import libreswan_callbacks
    libreswan_callbacks._watchpoints.pop("{fixed_key_name}", None)

    return False
'''

        # Inject the callback code (step 1: define the function)
        _debugger.HandleCommand(f"script {callback_code}")

        # Also inject into libreswan_callbacks module namespace as backup
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

        _print(f"[WATCHPOINT] Set on {key_name} @ 0x{addr:x} (watchpoint ID: {wp_id})")

        # Log to timing CSV
        if _timing_logger:
            _timing_logger.log_watchpoint_set(key_name, addr, key_data)

    except Exception as e:
        _print(f"[WATCHPOINT] Exception setting {key_name}: {e}")
        import traceback
        traceback.print_exc()


def parse_child_sa_keymat(
    keymat: bytes,
    *,
    encr: str,
    integ: Optional[str] = None,
    # You can override sizes if needed:
    override_encr: Optional[Tuple[int, int]] = None,  # (key_len, salt_len)
    override_integ_len: Optional[int] = None,
) -> Dict[str, bytes]:
    """
    Slice CHILD SA KEYMAT per RFC 7296 §2.17:
      initiator->responder first, then responder->initiator; within each SA:
      ENCR key first, then INTEG key (if any). For AEAD: no INTEG; ENCR = key||salt.

    Returns dict with:
      - non-AEAD:  ESP_ei, ESP_ai, ESP_er, ESP_ar
      - AEAD:      ESP_ei, ESP_er, plus ESP_ei_key/salt and ESP_er_key/salt
    """
    if override_encr is not None:
        key_len, salt_len = override_encr
    else:
        if encr not in ENCR_SPEC:
            raise ValueError(f"Unknown encr '{encr}'. Provide override_encr=(key_len, salt_len).")
        key_len, salt_len = ENCR_SPEC[encr]

    if override_integ_len is not None:
        a_len = override_integ_len
    else:
        name = "NONE" if (integ is None) else integ
        if name not in INTEG_LEN:
            raise ValueError(f"Unknown integ '{name}'. Provide override_integ_len.")
        a_len = INTEG_LEN[name]

    # per-direction lengths
    enc_total = key_len + salt_len
    per_dir = enc_total + (0 if salt_len > 0 else a_len)  # AEAD => no integrity key
    need = per_dir * 2  # i->r then r->i
    if len(keymat) < need:
        raise ValueError(f"KEYMAT too short: have {len(keymat)}, need {need} for {encr}/{integ or 'NONE'}")

    off = 0
    out: Dict[str, bytes] = {}

    # Initiator -> Responder
    out["ESP_ei"] = keymat[off:off+enc_total]; off += enc_total
    if salt_len == 0 and a_len:
        out["ESP_ai"] = keymat[off:off+a_len]; off += a_len

    # Responder -> Initiator
    out["ESP_er"] = keymat[off:off+enc_total]; off += enc_total
    if salt_len == 0 and a_len:
        out["ESP_ar"] = keymat[off:off+a_len]; off += a_len

    # If AEAD, expose key/salt splits for convenience
    if salt_len > 0:
        out["ESP_ei_key"], out["ESP_ei_salt"] = out["ESP_ei"][:key_len], out["ESP_ei"][key_len:]
        out["ESP_er_key"], out["ESP_er_salt"] = out["ESP_er"][:key_len], out["ESP_er"][key_len:]

    return out

# --- simple pretty-printer (hex, offsets increasing in RFC order) ---
def _to_hex_child(x: HexLike) -> str:
    if isinstance(x, (bytes, bytearray, memoryview)): return bytes(x).hex()
    if isinstance(x, str): return x.lower().replace(" ", "").replace("\n", "")
    raise TypeError(type(x))

def _hex_lines_child(hx: str, width: int = 16, base_off: int = 0) -> Iterable[str]:
    step = width * 2
    for i in range(0, len(hx), step):
        chunk = hx[i:i+step]
        groups = " ".join(chunk[j:j+2] for j in range(0, len(chunk), 2))
        yield f"{base_off + i//2:04x}: {groups}"

def print_child_sa_keymat(parts: Dict[str, HexLike], *, width: int = 16) -> None:
    order = ["ESP_ei","ESP_ai","ESP_er","ESP_ar","ESP_ei_key","ESP_ei_salt","ESP_er_key","ESP_er_salt"]
    off = 0
    for name in order:
        if name not in parts: continue
        hx = _to_hex_child(parts[name]); n = len(hx)//2
        print(f"{name} ({n} bytes)")
        for line in _hex_lines_child(hx, width, base_off=off):
            print("  " + line)
        print()
        off += n


def parse_chunk_t(process, chunk_addr: int) -> dict:
    """Parse chunk_t structure (16 bytes: ptr + len)"""
    if not chunk_addr or chunk_addr == 0:
        return None

    try:
        error = lldb.SBError()
        chunk_buf = process.ReadMemory(chunk_addr, 16, error)
        if not error.Success() or len(chunk_buf) < 16:
            _print(f"  [!] Failed to read chunk_t at 0x{chunk_addr:x}")
            return None

        ptr, length = struct.unpack("<QQ", bytes(chunk_buf))

        _print(f"  ptr: 0x{ptr:x}")
        _print(f"  len: {length}")

        if ptr > 0x1000 and 0 < length < 65536:
            error = lldb.SBError()
            data = process.ReadMemory(ptr, length, error)
            if not error.Success():
                _print(f"  [!] Failed to read data at 0x{ptr:x}")
                data = b""
            else:
                data = bytes(data)
                _print(f"  data (hex): {data.hex()}")
        else:
            data = b""

        return {
            'ptr': ptr,
            'len': length,
            'data': data,
            'hex': data.hex() if data else ""
        }

    except Exception as e:
        _print(f"  [!] Failed to parse chunk_t: {e}")
        return None





def _to_hex(s: HexLike) -> str:
    """Normalize input to a compact lowercase hex string (no spaces)."""
    if isinstance(s, (bytes, bytearray, memoryview)):
        return bytes(s).hex()
    if isinstance(s, str):
        h = s.lower().replace(" ", "").replace("\n", "")
        # keep only hex chars
        h = "".join(ch for ch in h if ch in "0123456789abcdef")
        if len(h) % 2:  # pad if odd length
            h = h[:-1]
        return h
    raise TypeError(f"Unsupported type for hex data: {type(s)}")

def _hex_lines(hx: str, bytes_per_line: int = 16, group: int = 2,
               with_offsets: bool = True, base_offset: int = 0) -> Iterable[str]:
    """Yield pretty hex lines, optionally with offsets."""
    step = bytes_per_line * 2
    for i in range(0, len(hx), step):
        chunk = hx[i:i+step]
        grouped = " ".join(chunk[j:j+group*2] for j in range(0, len(chunk), group*2))
        if with_offsets:
            off = base_offset + (i // 2)
            yield f"{off:04x}: {grouped}"
        else:
            yield grouped

def print_keymat(out: Dict[str, HexLike],
                 *,
                 bytes_per_line: int = 16,
                 group: int = 2,
                 with_offsets: bool = True,
                 color: bool = True) -> None:
    """
    Pretty-print KEYMAT pieces (hex) to the terminal.
    Accepts hex strings or bytes as dict values.
    """
    order = ["SK_d", "SK_ai", "SK_ar", "SK_ei", "SK_er", "SK_pi", "SK_pr",
             "SK_ei_key", "SK_ei_salt", "SK_er_key", "SK_er_salt"]

    def c(s: str, code: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if color else s

    printed_any = False
    offset = 0
    for name in order:
        if name not in out:
            continue
        hx = _to_hex(out[name])
        nbytes = len(hx) // 2
        header = f"{name} ({nbytes} bytes)"
        print(c(header, "1;36"))
        for line in _hex_lines(hx, bytes_per_line, group, with_offsets, base_offset=offset):
            print("  " + line)
        print()
        printed_any = True
        offset += nbytes  # advance running offset to mirror RFC order

    # Print any extra keys that weren't in the standard order
    extras = [k for k in out.keys() if k not in order]
    for name in extras:
        hx = _to_hex(out[name])
        nbytes = len(hx) // 2
        print(c(f"{name} ({nbytes} bytes)", "1;36"))
        for line in _hex_lines(hx, bytes_per_line, group, with_offsets, base_offset=0):
            print("  " + line)
        print()

    if not printed_any and not extras:
        print(c("[print_keymat] nothing to print (dict is empty)", "33"))

    

def split_keymat_224(keymat: bytes) -> Dict[str, str]:
    if len(keymat) != 224:
        raise ValueError(f"expected 224 bytes, got {len(keymat)}")
    off = 0
    def take(n):
        nonlocal off
        chunk = keymat[off:off+n]
        off += n
        return chunk
    out = {}
    out["SK_d"]  = take(32).hex()
    out["SK_ai"] = take(32).hex()
    out["SK_ar"] = take(32).hex()
    out["SK_ei"] = take(32).hex()
    out["SK_er"] = take(32).hex()
    out["SK_pi"] = take(32).hex()
    out["SK_pr"] = take(32).hex()
    return out


# ============================================================================
# NSS PK11SymKey Parser (DWARF way)
# ============================================================================

# helper function to check if an address is in a mapped memory region
def _mem_region_ok(proc: lldb.SBProcess, addr: int) -> bool:
    """True if LLDB says this address lies in a mapped region (or we can’t tell)."""
    ri = lldb.SBMemoryRegionInfo()
    err = proc.GetMemoryRegionInfo(addr, ri)  # returns SBError
    if err and hasattr(err, "Success") and err.Success():
        return bool(ri.IsMapped())
    # If the target/remote stub can’t report regions, don’t hard-fail; treat as unknown-but-ok.
    return True

def parse_pk11symkey_struct(process: lldb.SBProcess, symkey_addr: int,
                            try_extract: bool = True, max_dump: int = 256) -> Optional[SecItem]:
    target = process.GetTarget()
    error = lldb.SBError()
    parsed_secItem: Optional[SecItem] = None

    # --- utils ---
    def _frame() -> Optional[lldb.SBFrame]:
        dbg = lldb.debugger
        if not dbg: return None
        t = dbg.GetSelectedTarget()
        if not t or not t.IsValid(): return None
        th = t.GetProcess().GetSelectedThread()
        return th.GetSelectedFrame() if th and th.IsValid() else None

    def _bo() -> str:
        return "little" if target.GetByteOrder() == lldb.eByteOrderLittle else "big"

    def _ps() -> int:
        return target.GetAddressByteSize()

    def _read(addr: int, size: int) -> bytes:
        b = process.ReadMemory(addr, size, error)
        if not error.Success():
            raise RuntimeError(f"ReadMemory(0x{addr:x}, {size}) failed: {error}")
        if isinstance(b, str):
            b = b.encode("latin1", "ignore")
        return bytes(b)

    def _hexdump(buf: bytes, base: int, width: int = 16):
        def pr(b): return 32 <= b < 127
        print(f"\n[hexdump] {len(buf)} bytes @ 0x{base:016x}")
        for off in range(0, len(buf), width):
            chunk = buf[off:off+width]
            hexs = " ".join(f"{c:02x}" for c in chunk)
            asci = "".join(chr(c) if pr(c) else "." for c in chunk)
            print(f"0x{base+off:016x}: {hexs:<{width*3}}  {asci}")

    def _u(b: bytes, off: int, n: int, signed=False) -> int:
        return int.from_bytes(b[off:off+n], _bo(), signed=signed)

    def _align(off: int, align: int) -> int:
        return (off + (align-1)) & ~(align-1)

    def _eval(expr: str) -> Optional[lldb.SBValue]:
        fr = _frame()
        v = (fr.EvaluateExpression(expr) if fr and fr.IsValid()
             else target.EvaluateExpression(expr))
        return v if v and v.IsValid() else None

    # --- resolve by name/addr/dlsym and call ---
    def _find_symbol_addr(name: str) -> int:
        for mod in target.module_iter():
            sym = mod.FindSymbol(name)
            if sym and sym.IsValid():
                la = sym.GetStartAddress().GetLoadAddress(target)
                if la != lldb.LLDB_INVALID_ADDRESS:
                    return la
        return 0

    def _dlsym(name: str) -> int:
        v = _eval(f"""(unsigned long long)({{ extern void* dlsym(void*, const char*); (unsigned long long)dlsym((void*)0,"{name}"); }})""")
        return int(v.GetValue(), 0) if (v and v.GetValue()) else 0

    def _call_int_fn_ptr(addr: int, arg_ptr: int) -> Optional[int]:
        call = _eval(f"((int(*)(void*)){addr:#x})((void*){arg_ptr:#x})")
        if call and call.GetValue(): return int(call.GetValue(), 0)
        return None

    def _call_ptr_fn_ptr(addr: int, arg_ptr: int) -> Optional[int]:
        call = _eval(f"((void*(*)(void*)){addr:#x})((void*){arg_ptr:#x})")
        return call.GetValueAsUnsigned() if call else 0

    # --- SECItem offsets helper (correct padding on LP64) ---
    def _secitem_offsets(psize: int):
        type_off = 0
        ptr_off  = _align(4, psize)  # **padding after type**
        len_off  = ptr_off + psize
        total    = _align(len_off + 4, psize)
        return type_off, ptr_off, len_off, total

    # --- extract via NSS, even without symbols ---
    def _try_extract_and_dump_any(addr_symkey: int, cap: int):
        global parsed_secItem
        ok = None
        rv = _eval(f"(int)PK11_ExtractKeyValue((void*){addr_symkey:#x})")
        if rv and rv.GetValue():
            try: ok = int(rv.GetValue(), 0)
            except: ok = None
        if ok not in (0, 1):
            ext = _find_symbol_addr("PK11_ExtractKeyValue") or _dlsym("PK11_ExtractKeyValue")
            if ext: ok = _call_int_fn_ptr(ext, addr_symkey)
        if ok != 0:
            print("\n[extract] PK11_ExtractKeyValue failed/unavailable (non-extractable token or symbol not found).")
            return

        item_ptr = 0
        gv = _eval(f"(void*)PK11_GetKeyData((void*){addr_symkey:#x})")
        if gv: item_ptr = gv.GetValueAsUnsigned()
        if not item_ptr:
            gk = _find_symbol_addr("PK11_GetKeyData") or _dlsym("PK11_GetKeyData")
            if gk: item_ptr = _call_ptr_fn_ptr(gk, addr_symkey) or 0
        if not item_ptr:
            print("\n[extract] PK11_GetKeyData() not available or returned NULL.")
            return

        psize = _ps()
        type_off, ptr_off, len_off, total = _secitem_offsets(psize)
        print(f"[secitem] type={type_off}, ptr={ptr_off}, len={len_off}, total={total}")
        try:
            item_raw = _read(item_ptr, total)
        except Exception as ex:
            print(f"\n[extract] Unable to read SECItem @ 0x{item_ptr:x}: {ex}")
            return

        d_type = _u(item_raw, type_off, 4)
        d_ptr  = _u(item_raw, ptr_off,  psize)
        d_len  = _u(item_raw, len_off,  4)
        print(f"\n[extract] SECItem @ 0x{item_ptr:x}  type={d_type}  data=0x{d_ptr:x}  len={d_len}")
        if d_ptr and d_len:
            show = min(d_len, cap)
            try:
                buf = _read(d_ptr, show)
                print(f"[extract] Raw key bytes (len={d_len}, showing {show}):")
                parsed_secItem = {"len": d_len, "hex": buf.hex(), "bytes": buf, "data_ptr": d_ptr}
                _hexdump(buf, d_ptr)
            except Exception as ex:
                print(f"[extract] Could not read key bytes: {ex}")

            _print(f"[extract] Key extraction successful via manual NSS parsing.")
            return parsed_secItem
        else:
            print("[extract] SECItem empty (no raw key attached).")

    # --- symbolic parse first ---
    def _try_symbolic_parse() -> bool:
        for name in ("PK11SymKeyStr", "PK11SymKey"):
            t = target.FindFirstType(name)
            if not (t and t.IsValid()): continue
            if t.IsTypedefType():
                u = t.GetTypedefedType()
                if u and u.IsValid(): t = u
            if t.GetTypeClass() not in (lldb.eTypeClassStruct, lldb.eTypeClassClass):
                continue
            sbaddr = lldb.SBAddress(symkey_addr, target)
            sval = target.CreateValueFromAddress("PK11SymKey", sbaddr, t)
            if not (sval and sval.IsValid()): return False

            raw = _read(symkey_addr, t.GetByteSize())
            _hexdump(raw, symkey_addr)
            print("\n[parse] via symbols (DWARF)")

            secitem_ptr = 0
            secitem_len = 0
            for i in range(sval.GetNumChildren()):
                c = sval.GetChildAtIndex(i)
                if not c or not c.IsValid(): continue
                name = c.GetName() or f"field[{i}]"
                ctype = c.GetType()
                size  = ctype.GetByteSize()
                off   = c.AddressOf().GetValueAsUnsigned() - symkey_addr
                val   = c.GetValue() or c.GetSummary() or ""
                print(f"  +{off:4d}  {name:<16} : {ctype.GetName()}  size={size}  value={val}")

                if name == "data" and c.GetNumChildren() >= 3:
                    t_child = c.GetChildAtIndex(0)
                    p_child = c.GetChildAtIndex(1)
                    l_child = c.GetChildAtIndex(2)
                    t_str   = t_child.GetValue() or t_child.GetSummary() or ""
                    secitem_ptr = p_child.GetValueAsUnsigned()
                    try: secitem_len = int(l_child.GetValue() or "0")
                    except: secitem_len = 0
                    print(f"           SECItem {{ type={t_str}, data=0x{secitem_ptr:x}, len={secitem_len} }}")
                    if secitem_ptr and secitem_len:
                        try:
                            _hexdump(_read(secitem_ptr, min(secitem_len, max_dump)), secitem_ptr)
                        except Exception as ex:
                            print(f"           (SECItem.data read failed: {ex})")

            if try_extract and not secitem_ptr:
                parsed_secItem = _try_extract_and_dump_any(symkey_addr, max_dump)
            return parsed_secItem
        return False

    # --- manual layout (with correct SECItem alignment) ---
    def _manual_parse():
        global parsed_secItem
        psize = _ps()
        raw = _read(symkey_addr, 8*psize + 64)
        #_hexdump(raw, symkey_addr) #uncommend that in order to see what we are parsing

        # CK_ULONG size: LP64->8, LLP64->4; try both as needed
        cku_candidates = [psize, 4] if psize == 8 else [4]

        def build(cku: int):
            off = 0; L={}
            L["type"]         = (off, cku);  off += cku
            L["objectID"]     = (off, cku);  off += cku
            L["slot"]         = (off, psize);off += psize
            L["cx"]           = (off, psize);off += psize
            L["next"]         = (off, psize);off += psize
            L["owner"]        = (off, 4);    off += 4
            off               = _align(off, psize)     # **align SECItem start**
            L["data.type"]    = (off, 4);    off += 4
            off               = _align(off, psize)     # **align 'data' pointer**
            L["data.ptr"]     = (off, psize);off += psize
            L["data.len"]     = (off, 4);    off += 4
            L["session"]      = (off, cku);  off += cku
            L["sessionOwner"] = (off, 4);    off += 4
            L["refCount"]     = (off, 4);    off += 4
            L["size"]         = (off, 4);    off += 4
            L["origin"]       = (off, 4);    off += 4
            off               = _align(off, psize)     # align before parent
            L["parent"]       = (off, psize);off += psize
            L["series"]       = (off, 2);    off += 2
            off               = _align(off, psize)     # align before tail ptrs
            L["userData"]     = (off, psize);off += psize
            L["freeFunc"]     = (off, psize);off += psize
            L["_total"]       = off
            return L

        layout = None; ckusize = None
        for cand in cku_candidates:
            L = build(cand)
            slot_off,_ = L["slot"]
            slot_ptr = _u(raw, slot_off, _ps())
            #if slot_ptr == 0 or process.GetMemoryRegionInfo(slot_ptr, lldb.SBMemoryRegionInfo()).IsMapped():
            if slot_ptr == 0 or _mem_region_ok(process, slot_ptr):
                layout = L; ckusize = cand; break
        if not layout:
            print("\n[parse] manual: could not infer CK_ULONG; aborting parsed view.")
            return

        if len(raw) < layout["_total"]:
            raw = _read(symkey_addr, layout["_total"])

        origin_map = {0:"PK11_OriginNULL",1:"PK11_OriginDerive",2:"PK11_OriginGenerated",
                      3:"PK11_OriginFortezzaHack",4:"PK11_OriginUnwrap"}

        print("\n[parse] manual fallback (structure sizes inferred)")
        print(f"  pointer size = {psize}, CK_ULONG size = {ckusize}, endianness = {_bo()}")

        def show(name, ty, meaning=""):
            off,sz = layout[name]
            v = _u(raw, off, sz)
            m = f"  // {meaning}" if meaning else ""
            print(f"  +{off:4d}  {name:<12} : {ty:<22} size={sz:<2}  value=0x{v:x}{m}")
        
        if DEBUG_RUN:
            show("type",        "CK_MECHANISM_TYPE",      "mechanism used to create key")
            show("objectID",    "CK_OBJECT_HANDLE",       "object handle in slot")
            show("slot",        "PK11SlotInfo *",         "slot owning the key object")
            show("cx",          "void *",                 "UI/window context if needed")
            show("next",        "PK11SymKey *",           "intrusive list")
            show("owner",       "PRBool",                 "true if we own/free key data")

        dto,_ = layout["data.type"]; dpo,_ = layout["data.ptr"]; dlo,_ = layout["data.len"]
        
        if DEBUG_RUN:
            print(f"  +{dto:4d}  data.type    : SECItemType            size=4   value={_u(raw,dto,4)}")
            print(f"  +{dpo:4d}  data.ptr     : unsigned char *         size={psize} value=0x{_u(raw,dpo,psize):x}")
            print(f"  +{dlo:4d}  data.len     : unsigned int             size=4   value={_u(raw,dlo,4)}")

            show("session",     "CK_SESSION_HANDLE",      "session if key is on token")
            show("sessionOwner","PRBool")
            show("refCount",    "PRInt32",                "reference count")
            show("size",        "int",                    "key size in bytes")

        org_off,_ = layout["origin"]; org_val = _u(raw, org_off, 4)
        
        if DEBUG_RUN:
            print(f"  +{org_off:4d}  origin       : PK11Origin              size=4   value={org_val} ({origin_map.get(org_val,'?')})")
            show("parent",      "PK11SymKey *",           "parent (owner) key")
        ser_off,_ = layout["series"]
        
        if DEBUG_RUN:
            print(f"  +{ser_off:4d}  series       : PRUint16                size=2   value={_u(raw,ser_off,2)}")
            show("userData",    "void *",                 "app-attached data")
            show("freeFunc",    "PK11FreeDataFunc",       "free fn for userData")

        # dump inline data or try extractor
        dptr = _u(raw, dpo, _ps()); dlen = _u(raw, dlo, 4)
        if dptr and dlen:
            try:
                _hexdump(_read(dptr, min(dlen, max_dump)), dptr)
            except Exception as ex:
                print(f"  (couldn't read SECItem.data: {ex})")
        elif try_extract:
            parsed_secItem = _try_extract_and_dump_any(symkey_addr, max_dump)
        
        # _print(f"[parse] Manual parsing completed: {parsed_secItem}") # uncommend for debug info
        if parsed_secItem is None:
            _print(f"[parse] No key data extracted.")

        return parsed_secItem

    try:
        if _try_symbolic_parse():
            return parsed_secItem
    except Exception as ex:
        print(f"[warn] symbolic parse failed unexpectedly: {ex}  -> falling back")
    parsed_secItem = _manual_parse()
    return parsed_secItem

# ============================================================================
# Argument Dump Helper
# ============================================================================

def debug_dump_arguments(frame, func_name: str, num_args: int = 14):
    """Dump first N function arguments with memory hexdumps"""
    _print(f"[DEBUG] Function: {func_name}")
    _print(f"[DEBUG] Arguments:")

    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)

        if arch.is_x86_64:
            registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            sp_reg = "rsp"
            stack_offset = 8
            _print("[DEBUG] Architecture: x86_64")
            _print(f"[DEBUG] Dumping {num_args} arguments (6 registers + {max(0, num_args - 6)} stack):")
        elif arch.is_aarch64:
            registers = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
            sp_reg = "sp"
            stack_offset = 0
            _print("[DEBUG] Architecture: aarch64 (ARM64)")
            _print(f"[DEBUG] Dumping {num_args} arguments (8 registers + {max(0, num_args - 8)} stack):")
        else:
            _print(f"[DEBUG] Unknown architecture")
            return

        _print("")

        sp_value = arch.read_register(sp_reg)

        for i in range(num_args):
            try:
                if i < len(registers):
                    reg_name = registers[i]
                    value = arch.read_register(reg_name)
                    location = f"{reg_name:3s}"
                else:
                    if sp_value is None:
                        _print(f"  Arg{i:2d} (stack): <stack pointer unavailable>")
                        continue

                    stack_index = i - len(registers)
                    stack_addr = sp_value + stack_offset + (stack_index * 8)

                    error = lldb.SBError()
                    stack_data = process.ReadMemory(stack_addr, 8, error)
                    if not error.Success():
                        _print(f"  Arg{i:2d} (stk): <unable to read stack at 0x{stack_addr:x}>")
                        continue

                    value = struct.unpack("<Q", bytes(stack_data))[0]
                    location = f"stk"

                if value is None:
                    _print(f"  Arg{i:2d} ({location}): <unable to read>")
                    continue

                _print(f"  Arg{i:2d} ({location}): 0x{value:016x}  ({value})")

                if value > 128:
                    try:
                        error = lldb.SBError()
                        mem_data = process.ReadMemory(value, 128, error)
                        if error.Success() and len(mem_data) > 0:
                            _print(f"           -> Memory at 0x{value:x} (128 bytes):")
                            for offset in range(0, min(len(mem_data), 128), 16):
                                chunk = bytes(mem_data)[offset:offset+16]
                                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                                _print(f"           -> +{offset:02x}: {hex_str:<48s} | {ascii_str}")

                            if len(mem_data) >= 16:
                                ptr, length = struct.unpack("<QQ", bytes(mem_data)[:16])
                                if ptr > 0x1000 and 0 < length < 65536:
                                    _print(f"           -> [Chunk_t detected: ptr=0x{ptr:x}, len={length}]")
                                    error2 = lldb.SBError()
                                    chunk_data = process.ReadMemory(ptr, min(length, 128), error2)
                                    if error2.Success():
                                        chunk_hex = ' '.join(f'{b:02x}' for b in bytes(chunk_data)[:min(length, 128)])
                                        _print(f"           -> [Chunk data: {chunk_hex}...]")
                        else:
                            _print(f"           -> [Cannot read memory at 0x{value:x}]")
                    except Exception as e:
                        _print(f"           -> [Memory read error: {e}]")

            except Exception as e:
                location_str = registers[i] if i < len(registers) else "stack"
                _print(f"  Arg{i:2d} ({location_str}): <error: {e}>")

        _print("="*70)
        _print("")

    except Exception as e:
        _print(f"[DEBUG] Argument dump failed: {e}")


# ============================================================================
# CALLBACK: create_symkey() - Entry Only
# ============================================================================

def create_symkey_callback(frame, bp_loc, internal_dict):
    """Callback for create_symkey() - NSS symmetric key creation (ENTRY)

    chunk_t create_symkey(const char *name, const char *name2,
                          const chunk_t *scratch, struct logger *logger)
    """
    global _dumper, _logger

    call_num = _get_call_counter("create_symkey")

    timestamp = datetime.now().isoformat()
    _print(f"\n[{timestamp}] [CALLBACK] create_symkey (call #{call_num}) [ENTRY]")
    sys.stdout.flush()

    try:
        # ENTRY DUMP
        if _dumper:
            dump_name = f"create_symkey_{call_num:03d}_entry"
            _print(f"[*] Taking entry dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        # DEBUG: Dump arguments
        try:
            debug_dump_arguments(frame, func_name="create_symkey", num_args=14)
        except Exception as e:
            _print(f"[DEBUG] Argument dump failed: {e}")

        # Extract parameters
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # Param 0: name (const char*)
        name_ptr = arch.read_arg_register(0)
        # Param 1: name2 (const char*)
        name2_ptr = arch.read_arg_register(1)
        # Param 2: scratch (const chunk_t*)
        scratch_ptr = arch.read_arg_register(2)

        # Read key name
        if name_ptr and name_ptr > 0:
            error = lldb.SBError()
            name_data = process.ReadCStringFromMemory(name_ptr, 256, error)
            if error.Success():
                key_name = name_data
            else:
                key_name = "<unable to read>"
        else:
            key_name = "<null>"

        _print(f"[*] Key name: '{key_name}'")
        _print(f"[*] Scratch chunk*: 0x{scratch_ptr:x}")

        # Parse scratch chunk_t if available
        key_data = None
        key_len = 0

        if scratch_ptr and scratch_ptr > 0:
            _print(f"[*] Parsing scratch chunk_t...")
            chunk_data = parse_chunk_t(process, scratch_ptr)

            if chunk_data and chunk_data.get('data'):
                key_data = chunk_data['data']
                key_len = chunk_data['len']
                _print(f"[✓] Successfully parsed chunk_t!")
                _print(f"    Pointer: 0x{chunk_data['ptr']:x}")
                _print(f"    Length: {key_len} bytes")
                _print(f"    Data (hex): {chunk_data['hex']}")
            else:
                _print(f"[!] Failed to parse chunk_t structure")
        else:
            _print(f"[!] No scratch chunk provided (NULL pointer)")

        # Log event
        if _logger:
            _logger.log_event("create_symkey", {
                "call_num": call_num,
                "name": key_name,
                "scratch_ptr": f"0x{scratch_ptr:x}",
                "length": key_len,
                "sample": key_data[:min(32, key_len)].hex() if key_data else None
            })

        # Export to keylog
        if _keylog_writer and key_data:
            try:
                key_bytes = key_data if isinstance(key_data, bytes) else bytes.fromhex(key_data)
                _keylog_writer.add_ike_key(key_name, key_bytes)
            except Exception as e:
                _print(f"[!] Keylog write failed: {e}")

        # EXIT DUMP
        if _dumper:
            dump_name = f"create_symkey_{call_num:03d}_exit"
            _print(f"[*] Taking exit dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        _print(f"[✓] create_symkey callback complete (call #{call_num})")

    except Exception as e:
        _print(f"[ERROR] create_symkey callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


# ============================================================================
# CALLBACK: chunk_from_symkey() - Entry + Exit with Return Value
# ============================================================================

def chunk_from_symkey_entry_callback(frame, bp_loc, internal_dict):
    """Callback for chunk_from_symkey() ENTRY

    chunk_t chunk_from_symkey(const char *name, PK11SymKey *symkey,
                              struct logger *logger)
    """
    global _dumper, _logger, _symkey_ptr_arg1

    call_num = _get_call_counter("chunk_from_symkey")

    timestamp = datetime.now().isoformat()
    _print(f"\n[{timestamp}] [CALLBACK] chunk_from_symkey (call #{call_num}) [ENTRY]")
    sys.stdout.flush()

    try:
        # ENTRY DUMP
        if _dumper:
            dump_name = f"chunk_from_symkey_{call_num:03d}_entry"
            _print(f"[*] Taking entry dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        # DEBUG: Dump arguments
        if DEBUG_RUN:
            try:
                debug_dump_arguments(frame, func_name="chunk_from_symkey", num_args=14)
            except Exception as e:
                _print(f"[DEBUG] Argument dump failed: {e}")

        # Extract parameters
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # Param 0: name (const char*)
        name_ptr = arch.read_arg_register(0)
        # Param 1: symkey (PK11SymKey*)
        symkey_ptr = arch.read_arg_register(1)
        _symkey_ptr_arg1 = symkey_ptr  # Store for use in exit callback

        # Read key name
        if name_ptr and name_ptr > 0:
            error = lldb.SBError()
            name_data = process.ReadCStringFromMemory(name_ptr, 256, error)
            if error.Success():
                key_name = name_data
            else:
                key_name = "<unable to read>"
        else:
            key_name = "<null>"

        _print("[*] Function Argument parsing from chunk_from_symkey_")
        _print(f"[*] Key name: '{key_name}'")
        _print(f"[*] PK11SymKey*: 0x{symkey_ptr:x}")


        if symkey_ptr and symkey_ptr > 0:
            _print(f"[*] Attempting to parse PK11SymKey structure (DWARF)...")
            symkey_result = parse_pk11symkey_struct(process, symkey_ptr)
            #_print(f"[*] Attempting to parse PK11SymKey structure (multi strategy)...")
            #symkey_result = parse_pk11symkey(process, symkey_ptr)

            if symkey_result:
                _print(f"[✓] Successfully extracted key from PK11SymKey!")
                _print(f"    Length: {symkey_result['len']} bytes")
                _print(f"    Data (hex): {symkey_result['hex']}")

                # Log extracted key
                if _logger:
                    _logger.log_event("chunk_from_symkey_key_extracted", {
                        "call_num": call_num,
                        "name": key_name,
                        "key_len": symkey_result['len'],
                        "key_hex": symkey_result['hex']
                    })

                # Write to keylog
                if _keylog_writer and symkey_result['hex']:
                    try:
                        key_bytes = bytes.fromhex(symkey_result['hex'])
                        _keylog_writer.add_ike_key(key_name, key_bytes)
                    except Exception as e:
                        _print(f"[!] Keylog write failed: {e}")
            else:
                _print(f"[!] Failed to extract key from PK11SymKey (structure parsing failed)")
                _print(f"[!] This is expected if NSS version differs from assumptions")
                _print(f"[!] Tip: Set DEBUG_NSS=1 for detailed structure dump")

        # Set return breakpoint to capture chunk_t return value
        context = {
            'function': 'chunk_from_symkey',
            'call_num': call_num,
            'key_name': key_name,
            'symkey_ptr': symkey_ptr
        }

        _set_return_breakpoint(frame, 'chunk_from_symkey_exit_callback', context)

        _print(f"[✓] chunk_from_symkey entry callback complete (call #{call_num})")

    except Exception as e:
        _print(f"[ERROR] chunk_from_symkey entry callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


def chunk_from_symkey_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Callback for chunk_from_symkey() EXIT (return breakpoint)

    Captures chunk_t return value from registers:
    - ARM64: x0 = ptr, x1 = len
    - x86_64: rax = ptr, rdx = len
    """
    global _dumper, _logger

    try:
        # Retrieve context from entry callback
        context = _get_return_context(bp_id)
        call_num = context.get('call_num', 0)
        key_name = context.get('key_name', '<unknown>')
        #symkey_best_match = context.get('symkey_best_match')

        timestamp = datetime.now().isoformat()
        _print(f"\n[{timestamp}] [CALLBACK] chunk_from_symkey (call #{call_num}) [EXIT]")

        # Capture return value from registers
        arch = ArchitectureHelper(frame)

        if arch.is_aarch64:
            ptr = arch.read_register("x0")
            length = arch.read_register("x1")
        else:  # x86_64
            ptr = arch.read_register("rax")
            length = arch.read_register("rdx")

        _print(f"[RETURN] chunk_t returned:")
        _print(f"  ptr: 0x{ptr:x}")
        _print(f"  len: {length}")

        # Read actual data from pointer
        process = frame.GetThread().GetProcess()
        #_print(f"[*] Attempting to parse real returned PK11SymKey (DWARF)...")
        #parse_pk11symkey_struct(process, _symkey_ptr_arg1)
        return_hex = ""

        if ptr > 0x1000 and 0 < length < 65536:
            error = lldb.SBError()
            data = process.ReadMemory(ptr, length, error)
            if error.Success():
                data_bytes = bytes(data)
                return_hex = data_bytes.hex()
                _print(f"  data (hex): {return_hex}")

                # === ESP KEY DETECTION AND PARSING ===
                # Check if this is an ESP key (64 bytes: 32 enc + 32 auth)
                if length == 64 and key_name:
                    is_responder_to_initiator = key_name.startswith("responder to initiator keys")
                    is_initiator_to_responder = key_name.startswith("initiator to responder keys")

                    if is_responder_to_initiator or is_initiator_to_responder:
                        # Parse ESP keys: first 32 bytes = encryption, second 32 bytes = auth
                        enc_key = data_bytes[0:32]
                        auth_key = data_bytes[32:64]

                        direction = "responder->initiator" if is_responder_to_initiator else "initiator->responder"

                        _print(f"\n[ESP KEY DETECTED] {direction}")
                        _print(f"=" * 70)
                        _print(f"  Encryption Key ({len(enc_key)} bytes): {enc_key.hex()}")
                        _print(f"  Auth Key       ({len(auth_key)} bytes): {auth_key.hex()}")
                        _print(f"=" * 70)

                        # Save ESP keys via keylog writer
                        if _keylog_writer:
                            try:
                                # Determine IPs based on direction
                                # Responder = 10.0.0.1 (right), Initiator = 10.0.0.2 (left) in libreswan config
                                if is_responder_to_initiator:
                                    src_ip = "10.0.0.1"  # responder (right)
                                    dst_ip = "10.0.0.2"  # initiator (left)
                                else:  # initiator_to_responder
                                    src_ip = "10.0.0.2"  # initiator (left)
                                    dst_ip = "10.0.0.1"  # responder (right)

                                # Use placeholder SPI (we don't have real SPI in this callback)
                                spi_placeholder = f"esp_{call_num:04d}"

                                _keylog_writer.add_esp_key(
                                    spi=spi_placeholder,
                                    src=src_ip,
                                    dst=dst_ip,
                                    enc_key=enc_key,
                                    auth_key=auth_key,
                                    cipher="AES-CBC-256",
                                    auth_alg="HMAC-SHA2-256"
                                )

                                _print(f"[✓] ESP keys saved to keylog: {spi_placeholder} {src_ip}->{dst_ip}")

                            except Exception as e:
                                _print(f"[!] Failed to save ESP keys: {e}")
                                import traceback
                                traceback.print_exc()
                        else:
                            _print(f"[!] WARNING: Keylog writer not initialized - ESP keys not saved!")

                # Log return value
                if _logger:
                    _logger.log_event("chunk_from_symkey_return", {
                        "call_num": call_num,
                        "name": key_name,
                        "return_ptr": f"0x{ptr:x}",
                        "return_len": length,
                        "return_hex": return_hex
                    })

                # Write return value to keylog (most reliable source)
                if _keylog_writer and return_hex:
                    try:
                        key_bytes = bytes.fromhex(return_hex)
                        _keylog_writer.add_ike_key(f"{key_name}_return", key_bytes)
                    except Exception as e:
                        _print(f"[!] Keylog write failed: {e}")
            else:
                _print(f"  [!] Failed to read data at 0x{ptr:x}")
        else:
            _print(f"  [!] Invalid pointer or length")

        # EXIT DUMP
        if _dumper:
            dump_name = f"chunk_from_symkey_{call_num:03d}_exit"
            _print(f"[*] Taking exit dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        _print(f"[✓] chunk_from_symkey exit callback complete (call #{call_num})")

        # Cleanup context
        _cleanup_return_context(bp_id)

    except Exception as e:
        _print(f"[ERROR] chunk_from_symkey exit callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


# ============================================================================
# CALLBACK: ikev2_child_sa_keymat() - Entry + Exit with PK11SymKey* Return
# ============================================================================

def ikev2_child_sa_keymat_entry_callback(frame, bp_loc, internal_dict):
    """Callback for ikev2_child_sa_keymat() ENTRY

    PK11SymKey *ikev2_child_sa_keymat(const struct prf_desc *prf_desc,
                                      PK11SymKey *SK_d,
                                      PK11SymKey *new_ke_secret,
                                      const chunk_t Ni, const chunk_t Nr,
                                      size_t required_bytes,
                                      struct logger *logger)
    """
    global _dumper, _logger, _sk_d_ptr

    call_num = _get_call_counter("ikev2_child_sa_keymat")

    timestamp = datetime.now().isoformat()
    _print(f"\n[{timestamp}] [CALLBACK] ikev2_child_sa_keymat (call #{call_num}) [ENTRY]")
    sys.stdout.flush()

    try:
        # ENTRY DUMP
        if _dumper:
            dump_name = f"ikev2_child_sa_keymat_{call_num:03d}_entry"
            _print(f"[*] Taking entry dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        # DEBUG: Dump arguments
        if DEBUG_RUN:
            try:
                debug_dump_arguments(frame, func_name="ikev2_child_sa_keymat", num_args=14)
            except Exception as e:
                _print(f"[DEBUG] Argument dump failed: {e}")

        # Extract parameters
        arch = ArchitectureHelper(frame)

        # Param 1: SK_d (PK11SymKey*)
        sk_d_ptr = arch.read_arg_register(1)
        _sk_d_ptr = sk_d_ptr  # Store for use in exit callback
        # Param 5: required_bytes (size_t)
        required_bytes = arch.read_arg_register(5)

        _print(f"[*] SK_d PK11SymKey*: 0x{sk_d_ptr:x}")
        _print(f"[*] Required bytes: {required_bytes}")

        # Set return breakpoint to capture PK11SymKey* return value
        context = {
            'function': 'ikev2_child_sa_keymat',
            'call_num': call_num,
            'sk_d_ptr': sk_d_ptr,
            'required_bytes': required_bytes
        }

        _set_return_breakpoint(frame, 'ikev2_child_sa_keymat_exit_callback', context)

        _print(f"[✓] ikev2_child_sa_keymat entry callback complete (call #{call_num})")

    except Exception as e:
        _print(f"[ERROR] ikev2_child_sa_keymat entry callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


def ikev2_child_sa_keymat_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Callback for ikev2_child_sa_keymat() EXIT (return breakpoint)

    Captures PK11SymKey* return value from register:
    - ARM64: x0 contains pointer
    - x86_64: rax contains pointer
    """
    global _dumper, _logger

    try:
        # Retrieve context
        context = _get_return_context(bp_id)
        call_num = context.get('call_num', 0)
        required_bytes = context.get('required_bytes', 0)

        timestamp = datetime.now().isoformat()
        _print(f"\n[{timestamp}] [CALLBACK] ikev2_child_sa_keymat (call #{call_num}) [EXIT]")

        # Capture return value (PK11SymKey* pointer)
        arch = ArchitectureHelper(frame)

        if arch.is_aarch64:
            result_ptr = arch.read_register("x0")
        else:  # x86_64
            result_ptr = arch.read_register("rax")

        _print(f"[RETURN] PK11SymKey* returned: 0x{result_ptr:x}")

        # Try to parse returned PK11SymKey
        if result_ptr and result_ptr > 0:
            process = frame.GetThread().GetProcess()
            #_print(f"[*] Attempting to parse returned PK11SymKey (DWARF)...")
            #parse_pk11symkey_struct(process, _sk_d_ptr)
            _print(f"[*] Attempting to parse returned PK11SymKey from >>ikev2_child_sa_keymat<<...")
            symkey_result = parse_pk11symkey_struct(process, result_ptr)
            #_print(f"[*] Attempting to parse returned PK11SymKey...")
            #symkey_result = parse_pk11symkey(process, result_ptr)
            if symkey_result is None:
                _print(f"[!] parse_pk11symkey_struct returned None, trying manual parse...")
            
            # Save raw PK11SymKey data to chunk_t_keys.json debug file
            if _dumper and symkey_result:
                try:
                    chunk_t_debug_file = os.path.join(_dumper.output_dir, 'chunk_t_keys.json')

                    chunk_t_data = {
                        'timestamp': datetime.now().isoformat(),
                        'function': 'ikev2_child_sa_keymat',
                        'call_num': call_num,
                        'pk11symkey_ptr': f"0x{result_ptr:x}",
                        'raw_length': symkey_result['len'],
                        'raw_hex': symkey_result['hex'],
                        'raw_bytes_preview': symkey_result['hex'][:128],  # First 64 bytes
                        'key_type': 'CHILD_SA/ESP'
                    }

                    # Append to JSON file (or create if not exists)
                    if os.path.exists(chunk_t_debug_file):
                        with open(chunk_t_debug_file, 'r') as f:
                            existing = json.load(f)
                    else:
                        existing = {'chunk_t_extractions': []}

                    existing['chunk_t_extractions'].append(chunk_t_data)

                    with open(chunk_t_debug_file, 'w') as f:
                        json.dump(existing, f, indent=2)

                    _print(f"\n[*] Raw PK11SymKey data saved to chunk_t_keys.json")

                except Exception as e:
                    _print(f"[!] chunk_t debug file write error (non-fatal): {e}")

            parts = parse_child_sa_keymat(
                symkey_result['bytes'],
                encr="AES-CBC-256",
                integ="HMAC-SHA2-256-128",
            )
            print_child_sa_keymat(parts)

            # Write ESP keys via keylog writer with proper metadata
            if parts and 'ESP_ei' in parts and 'ESP_er' in parts and _keylog_writer:
                _print(f"\n[*] Writing ESP keys to keylog...")
                try:
                    # Add ESP keys with placeholder SPI/IPs (will be extracted from kernel XFRM)
                    _keylog_writer.add_esp_key(
                        spi="XFRM_OUT",  # Placeholder - extract from kernel XFRM
                        src="XFRM_SRC",  # Placeholder - extract from kernel XFRM or pcap
                        dst="XFRM_DST",  # Placeholder - extract from kernel XFRM or pcap
                        enc_key=parts['ESP_ei'],
                        auth_key=parts.get('ESP_ai', b''),
                        cipher="AES-CBC-256 [RFC3602]",
                        auth_alg="HMAC-SHA2-256-128 [RFC4868]"
                    )

                    _keylog_writer.add_esp_key(
                        spi="XFRM_IN",  # Placeholder - extract from kernel XFRM
                        src="XFRM_DST",  # Reversed for inbound
                        dst="XFRM_SRC",  # Reversed for inbound
                        enc_key=parts['ESP_er'],
                        auth_key=parts.get('ESP_ar', b''),
                        cipher="AES-CBC-256 [RFC3602]",
                        auth_alg="HMAC-SHA2-256-128 [RFC4868]"
                    )

                    _print(f"    [✓] ESP keys written (SPI/IPs from XFRM)")
                except Exception as e:
                    _print(f"    [!] ESP keylog write error (non-fatal): {e}")

            # Set hardware watchpoints on ENCR_i and ENCR_r (2 of 4 available watchpoints)
            if parts and 'ESP_ei' in parts and 'ESP_er' in parts and _target and _debugger and symkey_result:
                _print(f"\n[*] Setting hardware watchpoints on ESP keys...")
                try:
                    # Calculate offsets within the ESP keymat
                    # Layout: ESP_ei, ESP_ai, ESP_er, ESP_ar
                    # Assuming AES-CBC-256 (32 bytes) + HMAC-SHA2-256 (32 bytes)
                    encr_i_offset = 0
                    encr_r_offset = len(parts['ESP_ei']) + len(parts.get('ESP_ai', b''))

                    encr_i_bytes = parts['ESP_ei']
                    encr_r_bytes = parts['ESP_er']

                    # Use data_ptr directly from symkey_result (extracted from SECItem)
                    if 'data_ptr' in symkey_result:
                        data_ptr = symkey_result['data_ptr']
                        _print(f"    [*] Using SECItem data pointer: 0x{data_ptr:x}")
                        _print(f"    [*] ENCR_i offset: {encr_i_offset}, ENCR_r offset: {encr_r_offset}")

                        _set_watchpoint("ENCR_i", data_ptr, encr_i_offset, encr_i_bytes, "watchpoint_ENCR_i_callback")
                        _set_watchpoint("ENCR_r", data_ptr, encr_r_offset, encr_r_bytes, "watchpoint_ENCR_r_callback")
                    else:
                        _print(f"    [!] Could not locate ESP key data pointer in PK11SymKey")

                except Exception as e:
                    _print(f"    [!] ESP watchpoint setup error (non-fatal): {e}")
                    import traceback
                    traceback.print_exc()

            if symkey_result:
                _print(f"[✓] Successfully extracted key from returned PK11SymKey!")
                _print(f"    Length: {symkey_result['len']} bytes")
                _print(f"    Data (hex): {symkey_result['hex']}")

                # Log key
                if _logger:
                    _logger.log_event("ikev2_child_sa_keymat_return", {
                        "call_num": call_num,
                        "result_ptr": f"0x{result_ptr:x}",
                        "key_len": symkey_result['len'],
                        "key_hex": symkey_result['hex'],
                        "required_bytes": required_bytes
                    })

                # Write to keylog
                if _keylog_writer:
                    try:
                        key_bytes = bytes.fromhex(symkey_result['hex'])
                        _keylog_writer.add_ike_key(f"child_sa_keymat_{call_num}", key_bytes)
                    except Exception as e:
                        _print(f"[!] Keylog write failed: {e}")
            else:
                _print(f"[!] Failed to extract key from returned PK11SymKey")
        else:
            _print(f"[!] Returned NULL PK11SymKey")

        # EXIT DUMP
        if _dumper:
            dump_name = f"ikev2_child_sa_keymat_{call_num:03d}_exit"
            _print(f"[*] Taking exit dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        _print(f"[✓] ikev2_child_sa_keymat exit callback complete (call #{call_num})")

        # Cleanup
        _cleanup_return_context(bp_id)

    except Exception as e:
        _print(f"[ERROR] ikev2_child_sa_keymat exit callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


# ============================================================================
# CALLBACK: ikev2_ike_sa_keymat() - Entry + Exit with PK11SymKey* Return
# ============================================================================

def ikev2_ike_sa_keymat_entry_callback(frame, bp_loc, internal_dict):
    """Callback for ikev2_ike_sa_keymat() ENTRY

    PK11SymKey *ikev2_ike_sa_keymat(...)

    Returns concatenated IKE SA keys (SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr)
    as a single PK11SymKey* containing all derived parent SA key material.
    """
    global _dumper, _logger

    call_num = _get_call_counter("ikev2_ike_sa_keymat")

    timestamp = datetime.now().isoformat()
    _print(f"\n[{timestamp}] [CALLBACK] ikev2_ike_sa_keymat (call #{call_num}) [ENTRY]")
    sys.stdout.flush()

    try:
        # ENTRY DUMP
        if _dumper:
            dump_name = f"ikev2_ike_sa_keymat_{call_num:03d}_entry"
            _print(f"[*] Taking entry dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        # DEBUG: Dump arguments
        if DEBUG_RUN:
            try:
                debug_dump_arguments(frame, func_name="ikev2_ike_sa_keymat", num_args=14)
            except Exception as e:
                _print(f"[DEBUG] Argument dump failed: {e}")

        _print(f"[*] ikev2_ike_sa_keymat called - deriving IKE SA key material")
        _print(f"[*] This function returns all parent SA keys concatenated in a PK11SymKey*")

        # Set return breakpoint to capture PK11SymKey* return value
        context = {
            'function': 'ikev2_ike_sa_keymat',
            'call_num': call_num
        }

        _set_return_breakpoint(frame, 'ikev2_ike_sa_keymat_exit_callback', context)

        _print(f"[✓] ikev2_ike_sa_keymat entry callback complete (call #{call_num})")

    except Exception as e:
        _print(f"[ERROR] ikev2_ike_sa_keymat entry callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


def ikev2_ike_sa_keymat_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Callback for ikev2_ike_sa_keymat() EXIT (return breakpoint)

    Captures PK11SymKey* return value from register and parses it with
    parse_pk11symkey_struct to extract the concatenated IKE SA key material.

    Return value location:
    - ARM64: x0 contains PK11SymKey* pointer
    - x86_64: rax contains PK11SymKey* pointer
    """
    global _dumper, _logger, _keylog_writer

    try:
        # Retrieve context
        context = _get_return_context(bp_id)
        call_num = context.get('call_num', 0)

        timestamp = datetime.now().isoformat()
        _print(f"\n[{timestamp}] [CALLBACK] ikev2_ike_sa_keymat (call #{call_num}) [EXIT]")

        # Capture return value (PK11SymKey* pointer)
        arch = ArchitectureHelper(frame)

        if arch.is_aarch64:
            result_ptr = arch.read_register("x0")
        else:  # x86_64
            result_ptr = arch.read_register("rax")

        _print(f"[RETURN] PK11SymKey* returned: 0x{result_ptr:x}")
        _print(f"[*] This contains concatenated IKE SA keys (SK_ai||SK_ar||SK_ei||SK_er||...)")

        # Try to parse returned PK11SymKey
        if result_ptr and result_ptr > 0:
            process = frame.GetThread().GetProcess()
            _print(f"[*] Parsing returned PK11SymKey structure...")

            symkey_result = parse_pk11symkey_struct(process, result_ptr)
            _print(f"[*] Attempting to parse returned PK11SymKey from >>ikev2_ike_sa_keymat<<...")

            if symkey_result is None:
                _print(f"[!] parse_pk11symkey_struct returned None")
            else:
                _print(f"\n[✓] Successfully extracted IKE SA key material from PK11SymKey!")
                _print(f"=" * 70)
                _print(f"  Total Length: {symkey_result['len']} bytes")
                _print(f"  Key Data (hex): {symkey_result['hex']}")
                _print(f"=" * 70)

                # Save raw PK11SymKey data to chunk_t_keys.json debug file
                if _dumper:
                    try:
                        chunk_t_debug_file = os.path.join(_dumper.output_dir, 'chunk_t_keys.json')

                        chunk_t_data = {
                            'timestamp': datetime.now().isoformat(),
                            'function': 'ikev2_ike_sa_keymat',
                            'call_num': call_num,
                            'pk11symkey_ptr': f"0x{result_ptr:x}",
                            'raw_length': symkey_result['len'],
                            'raw_hex': symkey_result['hex'],
                            'raw_bytes_preview': symkey_result['hex'][:128],  # First 64 bytes
                            'key_type': 'IKE_SA'
                        }

                        # Append to JSON file (or create if not exists)
                        if os.path.exists(chunk_t_debug_file):
                            with open(chunk_t_debug_file, 'r') as f:
                                existing = json.load(f)
                        else:
                            existing = {'chunk_t_extractions': []}

                        existing['chunk_t_extractions'].append(chunk_t_data)

                        with open(chunk_t_debug_file, 'w') as f:
                            json.dump(existing, f, indent=2)

                        _print(f"\n[*] Raw PK11SymKey data saved to chunk_t_keys.json")

                    except Exception as e:
                        _print(f"[!] chunk_t debug file write error (non-fatal): {e}")

                # Try to split into individual keys (assuming 224 bytes = 7 keys)
                try:
                    parts = split_keymat_224(symkey_result['bytes'])
                    _print(f"\n[✓] Successfully split keymat into individual keys:")
                    print_keymat(parts)  # pretty hex with offsets

                    # Write individual keys to keylog writer
                    if _keylog_writer:
                        _print(f"\n[*] Writing individual keys to keylog...")

                        # Add each key individually
                        for key_name, key_hex in parts.items():
                            key_bytes = bytes.fromhex(key_hex)
                            _keylog_writer.add_ike_key(key_name, key_bytes)
                            _print(f"    [+] {key_name}: {len(key_bytes)} bytes")

                    # Set hardware watchpoints on SK_ei and SK_er (2 of 4 available watchpoints)
                    if _target and _debugger and 'SK_ei' in parts and 'SK_er' in parts and symkey_result:
                        _print(f"\n[*] Setting hardware watchpoints on IKE keys...")
                        try:
                            # Calculate offsets within the 224-byte keymat
                            # Layout: SK_d(32), SK_ai(32), SK_ar(32), SK_ei(32), SK_er(32), SK_pi(32), SK_pr(32)
                            sk_ei_offset = 32 + 32 + 32  # After SK_d, SK_ai, SK_ar = 96
                            sk_er_offset = 32 + 32 + 32 + 32  # After SK_d, SK_ai, SK_ar, SK_ei = 128

                            sk_ei_bytes = bytes.fromhex(parts['SK_ei'])
                            sk_er_bytes = bytes.fromhex(parts['SK_er'])

                            # Use data_ptr directly from symkey_result (extracted from SECItem)
                            if 'data_ptr' in symkey_result:
                                data_ptr = symkey_result['data_ptr']
                                _print(f"    [*] Using SECItem data pointer: 0x{data_ptr:x}")
                                _print(f"    [*] SK_ei offset: {sk_ei_offset}, SK_er offset: {sk_er_offset}")

                                _set_watchpoint("SK_ei", data_ptr, sk_ei_offset, sk_ei_bytes, "watchpoint_sk_ei_callback")
                                _set_watchpoint("SK_er", data_ptr, sk_er_offset, sk_er_bytes, "watchpoint_sk_er_callback")
                            else:
                                _print(f"    [!] Could not locate key data pointer in PK11SymKey")

                        except Exception as e:
                            _print(f"    [!] Watchpoint setup error (non-fatal): {e}")
                            import traceback
                            traceback.print_exc()

                    # Finalize IKE SA (use placeholder SPIs since we don't have them yet)
                    # SPIs will be extracted from packet capture or pluto logs later
                    if _keylog_writer:
                        _keylog_writer.finalize_ike_sa(
                            initiator_spi="0" * 16,  # Placeholder - extract from pcap
                            responder_spi="0" * 16,  # Placeholder - extract from pcap
                            encryption_alg="AES-CBC-256 [RFC3602]",
                            integrity_alg="HMAC_SHA2_256_128 [RFC4868]"
                        )

                        _print(f"[✓] Individual keys written to keylog")
                        _print(f"[*] Keys will be saved to:")
                        _print(f"    - ikev2_decryption_table (Wireshark format)")
                        _print(f"    - keys.json (JSON backup)")
                        _print(f"[*] Note: SPIs are placeholders (0x00...) - extract from pcap if needed")

                except ValueError as e:
                    _print(f"[!] split_keymat_224 failed: {e}")
                    _print(f"[*] Key length is {symkey_result['len']}, expected 224 bytes")
                    _print(f"[*] Falling back to storing complete keymat blob")

                    # Fallback: Store the complete keymat as a single entry
                    if _keylog_writer:
                        key_bytes = bytes.fromhex(symkey_result['hex'])
                        key_name = f"ike_sa_keymat_{call_num:03d}_complete"
                        _keylog_writer.add_ike_key(key_name, key_bytes)
                        _print(f"[✓] Complete keymat saved: {key_name}")

                # Log key with full metadata for analysis
                if _logger:
                    _logger.log_event("ikev2_ike_sa_keymat_return", {
                        "call_num": call_num,
                        "result_ptr": f"0x{result_ptr:x}",
                        "total_key_len": symkey_result['len'],
                        "concatenated_key_hex": symkey_result['hex'],
                        "note": "Parsed into individual keys: SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr"
                    })

            if symkey_result is None:
                _print(f"[!] Failed to extract key material from returned PK11SymKey")
                _print(f"[!] Check if NSS version matches expected structure layout")
        else:
            _print(f"[!] Returned NULL PK11SymKey")

        # EXIT DUMP
        if _dumper:
            dump_name = f"ikev2_ike_sa_keymat_{call_num:03d}_exit"
            _print(f"[*] Taking exit dump: {dump_name}")
            _dumper.dump_full_memory(dump_name)

        _print(f"[✓] ikev2_ike_sa_keymat exit callback complete (call #{call_num})")

        # Cleanup
        _cleanup_return_context(bp_id)

    except Exception as e:
        _print(f"[ERROR] ikev2_ike_sa_keymat exit callback failed: {e}")
        import traceback
        traceback.print_exc()

    return False


#==============================================================================
# Manual dump trigger (for external scripts)
#==============================================================================

def manual_dump(checkpoint_name: str):
    """Manually trigger a userspace memory dump

    This function is called from the monitoring loop when a dump request marker
    file is detected. It's separate from the callback flow to avoid affecting
    the working solution.

    Args:
        checkpoint_name: Name for the checkpoint (e.g., "before_initiate", "after_rekey")
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
        import sys
        sys.stdout.flush()

    except Exception as e:
        print(f"[ERROR] Manual dump failed: {e}")
        import traceback
        traceback.print_exc()
# ============================================================================
# encrypt_key_from_bytes() and encrypt_key_from_symkey_bytes() Callbacks
# Debug hooks for encryption key functions (controlled by SEC_DEBUG_RUN)
# ============================================================================

def encrypt_key_from_bytes_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for encrypt_key_from_bytes()

    Dumps all function arguments when SEC_DEBUG_RUN is True.

    Expected signature (inferred):
        encrypt_key_from_bytes(const char* key_name,
                               cipher,
                               next_byte,
                               key_size,
                               const uint8_t* key_bytes,
                               HERE,
                               logger)
    """
    global _call_counters, SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        return False

    # Increment call counter
    _call_counters['encrypt_key_from_bytes'] = _call_counters.get('encrypt_key_from_bytes', 0) + 1
    call_num = _call_counters['encrypt_key_from_bytes']

    _print(f"\n{'='*70}")
    _print(f"[encrypt_key_from_bytes_entry] Call #{call_num}")
    _print(f"{'='*70}")

    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)
        error = lldb.SBError()

        # Argument 0: const char* key_name
        key_name_ptr = arch.read_arg_register(0)
        if key_name_ptr:
            key_name_str = process.ReadCStringFromMemory(key_name_ptr, 256, error)
            if error.Success():
                _print(f"  Arg0 (key_name): \"{key_name_str}\"")
            else:
                _print(f"  Arg0 (key_name): 0x{key_name_ptr:x} (read failed)")

        # Argument 1: cipher descriptor (pointer)
        cipher_ptr = arch.read_arg_register(1)
        _print(f"  Arg1 (cipher): 0x{cipher_ptr:x}")

        # Argument 2: next_byte (offset/pointer)
        next_byte = arch.read_arg_register(2)
        _print(f"  Arg2 (next_byte): 0x{next_byte:x}")

        # Argument 3: key_size
        key_size = arch.read_arg_register(3)
        _print(f"  Arg3 (key_size): {key_size}")

        # Argument 4: const uint8_t* key_bytes
        key_bytes_ptr = arch.read_arg_register(4)
        if key_bytes_ptr and key_size > 0:
            key_bytes = process.ReadMemory(key_bytes_ptr, min(key_size, 64), error)
            if error.Success():
                _print(f"  Arg4 (key_bytes): 0x{key_bytes_ptr:x}")
                _print(f"    hex (first {min(key_size, 64)} bytes): {bytes(key_bytes).hex()}")
            else:
                _print(f"  Arg4 (key_bytes): 0x{key_bytes_ptr:x} (read failed)")

        # Argument 5: HERE (debug location macro)
        here_val = arch.read_arg_register(5)
        _print(f"  Arg5 (HERE): 0x{here_val:x}")

        # Argument 6: logger
        logger_ptr = arch.read_arg_register(6)
        _print(f"  Arg6 (logger): 0x{logger_ptr:x}")

        # Set up exit callback using return breakpoint helper
        context = {
            'call_num': call_num,
            'function': 'encrypt_key_from_bytes'
        }
        _set_return_breakpoint(frame, 'encrypt_key_from_bytes_exit_callback', context)

    except Exception as e:
        _print(f"  [!] Error in encrypt_key_from_bytes_entry_callback: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution


def encrypt_key_from_bytes_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for encrypt_key_from_bytes() - captures return value"""
    global SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        _cleanup_return_context(bp_id)
        return False

    # Retrieve context from entry callback
    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')

    _print(f"\n[encrypt_key_from_bytes_exit] Call #{call_num}")

    try:
        arch = ArchitectureHelper(frame)

        # Read return value from architecture-specific register
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:  # x86_64
            return_value = arch.read_register("rax")

        _print(f"  Return value: 0x{return_value:x}")

    except Exception as e:
        _print(f"  [!] Error in encrypt_key_from_bytes_exit_callback: {e}")

    _print(f"{'='*70}\n")

    # Cleanup context
    _cleanup_return_context(bp_id)
    return False


def encrypt_key_from_symkey_bytes_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for encrypt_key_from_symkey_bytes()

    Dumps all function arguments when SEC_DEBUG_RUN is True.
    Special handling for PK11SymKey* argument with SECItem hexdump.

    Expected signature (from user example):
        encrypt_key_from_symkey_bytes(const char* key_name,
                                       cipher,
                                       next_byte,
                                       key_size,
                                       PK11SymKey* keymat,
                                       HERE,
                                       logger)
    """
    global _call_counters, SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        return False

    # Increment call counter
    _call_counters['encrypt_key_from_symkey_bytes'] = _call_counters.get('encrypt_key_from_symkey_bytes', 0) + 1
    call_num = _call_counters['encrypt_key_from_symkey_bytes']

    _print(f"\n{'='*70}")
    _print(f"[encrypt_key_from_symkey_bytes_entry] Call #{call_num}")
    _print(f"{'='*70}")

    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)
        error = lldb.SBError()

        # Argument 0: const char* key_name
        key_name_ptr = arch.read_arg_register(0)
        if key_name_ptr:
            key_name_str = process.ReadCStringFromMemory(key_name_ptr, 256, error)
            if error.Success():
                _print(f"  Arg0 (key_name): \"{key_name_str}\"")
            else:
                _print(f"  Arg0 (key_name): 0x{key_name_ptr:x} (read failed)")

        # Argument 1: cipher descriptor (pointer)
        cipher_ptr = arch.read_arg_register(1)
        _print(f"  Arg1 (cipher): 0x{cipher_ptr:x}")

        # Argument 2: next_byte (offset/pointer)
        next_byte = arch.read_arg_register(2)
        _print(f"  Arg2 (next_byte): 0x{next_byte:x}")

        # Argument 3: key_size
        key_size = arch.read_arg_register(3)
        _print(f"  Arg3 (key_size): {key_size}")

        # Argument 4: PK11SymKey* keymat - SPECIAL HANDLING
        keymat_ptr = arch.read_arg_register(4)
        _print(f"  Arg4 (keymat): 0x{keymat_ptr:x} (PK11SymKey*)")

        if keymat_ptr and keymat_ptr > 0:
            _print(f"    [*] Parsing PK11SymKey structure to extract SECItem...")
            symkey_result = parse_pk11symkey_struct(process, keymat_ptr)

            if symkey_result:
                _print(f"    [✓] Successfully extracted SECItem from PK11SymKey!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [!] Failed to parse PK11SymKey")

        # Argument 5: HERE (debug location macro)
        here_val = arch.read_arg_register(5)
        _print(f"  Arg5 (HERE): 0x{here_val:x}")

        # Argument 6: logger
        logger_ptr = arch.read_arg_register(6)
        _print(f"  Arg6 (logger): 0x{logger_ptr:x}")

        # Set up exit callback using return breakpoint helper
        context = {
            'call_num': call_num,
            'function': 'encrypt_key_from_symkey_bytes'
        }
        _set_return_breakpoint(frame, 'encrypt_key_from_symkey_bytes_exit_callback', context)

    except Exception as e:
        _print(f"  [!] Error in encrypt_key_from_symkey_bytes_entry_callback: {e}")
        import traceback
        traceback.print_exc()

    return False  # Continue execution


def encrypt_key_from_symkey_bytes_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for encrypt_key_from_symkey_bytes() - captures return value"""
    global SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        _cleanup_return_context(bp_id)
        return False

    # Retrieve context from entry callback
    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')

    _print(f"\n[encrypt_key_from_symkey_bytes_exit] Call #{call_num}")

    try:
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # Read return value from architecture-specific register
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:  # x86_64
            return_value = arch.read_register("rax")

        _print(f"  Return value (PK11SymKey*): 0x{return_value:x}")

        # Parse returned PK11SymKey to extract SECItem
        if return_value and return_value > 0:
            _print(f"    [*] Parsing returned PK11SymKey structure to extract SECItem...")
            symkey_result = parse_pk11symkey_struct(process, return_value)

            if symkey_result:
                _print(f"    [✓] Successfully extracted SECItem from returned PK11SymKey!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [!] Failed to parse returned PK11SymKey")

    except Exception as e:
        _print(f"  [!] Error in encrypt_key_from_symkey_bytes_exit_callback: {e}")

    _print(f"{'='*70}\n")

    # Cleanup context
    _cleanup_return_context(bp_id)
    return False


def key_from_symkey_bytes_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for key_from_symkey_bytes()

    Minimal debug hook - only dumps arg0 (key name string) when SEC_DEBUG_RUN is True.
    Return value parsing handled in exit callback.

    Expected signature (similar to encrypt_key_from_symkey_bytes):
        key_from_symkey_bytes(const char* key_name,
                              cipher,
                              next_byte,
                              key_size,
                              PK11SymKey* keymat,
                              HERE,
                              logger)
    """
    global _call_counters, SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        return False

    # Increment call counter
    _call_counters['key_from_symkey_bytes'] = _call_counters.get('key_from_symkey_bytes', 0) + 1
    call_num = _call_counters['key_from_symkey_bytes']

    _print(f"\n{'='*70}")
    _print(f"[key_from_symkey_bytes_entry] Call #{call_num}")
    _print(f"{'='*70}")

    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)
        error = lldb.SBError()

        # Argument 0: const char* key_name - ONLY argument we dump
        key_name_ptr = arch.read_arg_register(0)
        if key_name_ptr:
            key_name_str = process.ReadCStringFromMemory(key_name_ptr, 256, error)
            if error.Success():
                _print(f"  Arg0 (key_name): \"{key_name_str}\"")
            else:
                _print(f"  Arg0 (key_name): 0x{key_name_ptr:x} (read failed)")

        # Set up exit callback using return breakpoint helper
        context = {
            'call_num': call_num,
            'function': 'key_from_symkey_bytes'
        }
        _set_return_breakpoint(frame, 'key_from_symkey_bytes_exit_callback', context)

    except Exception as e:
        _print(f"  [!] Error in key_from_symkey_bytes_entry_callback: {e}")
        import traceback
        traceback.print_exc()

    return False


def key_from_symkey_bytes_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for key_from_symkey_bytes() - captures and parses PK11SymKey* return value"""
    global SEC_DEBUG_RUN

    if not SEC_DEBUG_RUN:
        _cleanup_return_context(bp_id)
        return False

    # Retrieve context from entry callback
    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')

    _print(f"\n[key_from_symkey_bytes_exit] Call #{call_num}")

    try:
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # Read return value from architecture-specific register
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:  # x86_64
            return_value = arch.read_register("rax")

        _print(f"  Return value (PK11SymKey*): 0x{return_value:x}")

        # Parse returned PK11SymKey to extract SECItem
        if return_value and return_value > 0:
            _print(f"    [*] Parsing returned PK11SymKey structure to extract SECItem...")
            symkey_result = parse_pk11symkey_struct(process, return_value)

            if symkey_result:
                _print(f"    [✓] Successfully extracted SECItem from returned PK11SymKey!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [!] Failed to parse returned PK11SymKey")

    except Exception as e:
        _print(f"  [!] Error in key_from_symkey_bytes_exit_callback: {e}")

    _print(f"{'='*70}\n")

    # Cleanup context
    _cleanup_return_context(bp_id)
    return False


# ============================================================================
# ike_sa_keymat(), psk_auth(), and crypt_derive() Callbacks
# Debug hooks for key derivation functions (controlled by SEC_DEBUG_RUN)
# ============================================================================

def ike_sa_keymat_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for ike_sa_keymat()

    Extracts SKEYSEED from argument 1 and sets up exit callback for return value parsing.

    Signature:
        PK11SymKey *ike_sa_keymat(const struct prf_desc *prf_desc,
                                  PK11SymKey *skeyseed,
                                  const chunk_t Ni, const chunk_t Nr,
                                  shunk_t SPIi, shunk_t SPIr,
                                  size_t required_bytes,
                                  struct logger *logger)
    """
    global _call_counters, SEC_DEBUG_RUN, _keylog_writer

    if not SEC_DEBUG_RUN:
        return False

    _call_counters['ike_sa_keymat'] = _call_counters.get('ike_sa_keymat', 0) + 1
    call_num = _call_counters['ike_sa_keymat']

    _print(f"\n{'='*70}")
    _print(f"[ike_sa_keymat_entry] Call #{call_num}")
    _print(f"{'='*70}")

    try:
        # Extract SKEYSEED from argument 1
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # arg 1 is PK11SymKey *skeyseed
        if arch.is_x86_64:
            skeyseed_ptr = arch.read_register("rsi")
        elif arch.is_aarch64:
            skeyseed_ptr = arch.read_register("x1")
        else:
            skeyseed_ptr = None

        if skeyseed_ptr and skeyseed_ptr > 0x1000:
            _print(f"  SKEYSEED PK11SymKey*: 0x{skeyseed_ptr:x}")
            symkey_result = parse_pk11symkey_struct(process, skeyseed_ptr)

            if symkey_result:
                _print(f"  [✓] Successfully extracted SKEYSEED from PK11SymKey!")
                _print(f"      Length: {symkey_result['len']} bytes")
                _print(f"      Hex (first 64 bytes): {symkey_result['hex'][:128]}")

                # Save to keylog
                if _keylog_writer and 'bytes' in symkey_result:
                    try:
                        _keylog_writer.add_ike_key("SKEYSEED", symkey_result['bytes'])
                        _print(f"  [+] SKEYSEED saved to keylog")
                    except Exception as e:
                        _print(f"  [!] Keylog write failed: {e}")
            else:
                _print(f"  [!] Failed to parse SKEYSEED PK11SymKey")

        context = {'call_num': call_num, 'function': 'ike_sa_keymat'}
        _set_return_breakpoint(frame, 'ike_sa_keymat_exit_callback', context)
    except Exception as e:
        _print(f"  [!] Error: {e}")
        import traceback
        traceback.print_exc()

    return False


def ike_sa_keymat_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for ike_sa_keymat() - parses PK11SymKey* return value"""
    global SEC_DEBUG_RUN
    
    if not SEC_DEBUG_RUN:
        _cleanup_return_context(bp_id)
        return False
    
    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')
    
    _print(f"\n[ike_sa_keymat_exit] Call #{call_num}")
    
    try:
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()
        
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:
            return_value = arch.read_register("rax")
        
        _print(f"  Return value (PK11SymKey*): 0x{return_value:x}")
        
        if return_value and return_value > 0:
            _print(f"    [ike_sa_keymat] Parsing returned PK11SymKey structure...")
            symkey_result = parse_pk11symkey_struct(process, return_value)
            
            if symkey_result:
                _print(f"    [ike_sa_keymat] ✓ Successfully extracted SECItem from returned PK11SymKey!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [ike_sa_keymat] ! Failed to parse returned PK11SymKey")
    
    except Exception as e:
        _print(f"  [!] Error: {e}")
    
    _print(f"{'='*70}\n")
    _cleanup_return_context(bp_id)
    return False


def psk_auth_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for psk_auth()
    
    Raw hexdump of first 5 arguments + parse arg1 (PK11SymKey *psk).
    No exit callback (return value not parsed).
    
    Signature:
        struct crypt_mac psk_auth(const struct prf_desc *prf_desc,
                                  PK11SymKey *psk,
                                  shunk_t first_packet,
                                  ...)
    """
    global _call_counters, SEC_DEBUG_RUN
    
    if not SEC_DEBUG_RUN:
        return False
    
    _call_counters['psk_auth'] = _call_counters.get('psk_auth', 0) + 1
    call_num = _call_counters['psk_auth']
    
    _print(f"\n{'='*70}")
    _print(f"[psk_auth_entry] Call #{call_num}")
    _print(f"{'='*70}")
    
    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)
        error = lldb.SBError()
        
        # Raw hexdump of first 5 arguments (memory at each argument address)
        _print(f"  Raw argument hexdump (first 5 args):")
        for i in range(5):
            arg_val = arch.read_arg_register(i)
            if arg_val:
                # Read 32 bytes of memory at argument address
                mem = process.ReadMemory(arg_val, 32, error)
                if error.Success():
                    _print(f"    Arg{i} @ 0x{arg_val:x}: {bytes(mem).hex()[:64]}...")
                else:
                    _print(f"    Arg{i} @ 0x{arg_val:x}: (read failed)")
        
        # Special handling: Parse arg1 (PK11SymKey *psk)
        psk_ptr = arch.read_arg_register(1)
        if psk_ptr and psk_ptr > 0:
            _print(f"\n  Arg1 (PK11SymKey *psk): 0x{psk_ptr:x}")
            _print(f"    [psk_auth] Parsing PK11SymKey structure...")
            symkey_result = parse_pk11symkey_struct(process, psk_ptr)
            
            if symkey_result:
                _print(f"    [psk_auth] ✓ Successfully extracted SECItem from PK11SymKey *psk!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [psk_auth] ! Failed to parse PK11SymKey")
    
    except Exception as e:
        _print(f"  [!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    _print(f"{'='*70}\n")
    return False


def crypt_derive_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for crypt_derive()
    
    Dumps all specified arguments, parses PK11SymKey* and SECItem* arguments.
    
    Signature:
        PK11SymKey *crypt_derive(PK11SymKey *base_key,
                                 CK_MECHANISM_TYPE derive,
                                 SECItem *params,
                                 const char *target_name,
                                 CK_MECHANISM_TYPE target_mechanism,
                                 CK_ATTRIBUTE_TYPE operation,
                                 int key_size,
                                 CK_FLAGS flags,
                                 ...)
    """
    global _call_counters, SEC_DEBUG_RUN
    
    if not SEC_DEBUG_RUN:
        return False
    
    _call_counters['crypt_derive'] = _call_counters.get('crypt_derive', 0) + 1
    call_num = _call_counters['crypt_derive']
    
    _print(f"\n{'='*70}")
    _print(f"[crypt_derive_entry] Call #{call_num}")
    _print(f"{'='*70}")
    
    try:
        process = frame.GetThread().GetProcess()
        arch = ArchitectureHelper(frame)
        error = lldb.SBError()
        
        # Arg0: PK11SymKey *base_key - PARSE
        base_key_ptr = arch.read_arg_register(0)
        _print(f"  Arg0 (PK11SymKey *base_key): 0x{base_key_ptr:x}")
        if base_key_ptr and base_key_ptr > 0:
            _print(f"    [crypt_derive] Parsing base_key PK11SymKey structure...")
            symkey_result = parse_pk11symkey_struct(process, base_key_ptr)
            if symkey_result:
                _print(f"    [crypt_derive] ✓ Successfully extracted SECItem from base_key!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
        
        # Arg1: CK_MECHANISM_TYPE derive
        derive = arch.read_arg_register(1)
        _print(f"  Arg1 (CK_MECHANISM_TYPE derive): 0x{derive:x}")
        
        # Arg2: SECItem *params - PARSE
        params_ptr = arch.read_arg_register(2)
        _print(f"  Arg2 (SECItem *params): 0x{params_ptr:x}")
        if params_ptr and params_ptr > 0:
            # Read SECItem structure (type, data, len)
            psize = arch.ptr_size
            type_off = 0
            ptr_off = (4 + (psize - 1)) & ~(psize - 1)  # Align
            len_off = ptr_off + psize
            total = ((len_off + 4) + (psize - 1)) & ~(psize - 1)
            
            secitem_raw = process.ReadMemory(params_ptr, total, error)
            if error.Success():
                d_type = struct.unpack("<I", bytes(secitem_raw[type_off:type_off+4]))[0]
                d_ptr = struct.unpack("<Q" if psize == 8 else "<I", bytes(secitem_raw[ptr_off:ptr_off+psize]))[0]
                d_len = struct.unpack("<I", bytes(secitem_raw[len_off:len_off+4]))[0]
                
                _print(f"    [crypt_derive] SECItem: type={d_type}, data=0x{d_ptr:x}, len={d_len}")
                if d_ptr and d_len:
                    data = process.ReadMemory(d_ptr, min(d_len, 64), error)
                    if error.Success():
                        _print(f"        hex (first {min(d_len, 64)} bytes): {bytes(data).hex()}")
        
        # Arg3: const char *target_name
        target_name_ptr = arch.read_arg_register(3)
        if target_name_ptr:
            target_name = process.ReadCStringFromMemory(target_name_ptr, 256, error)
            if error.Success():
                _print(f"  Arg3 (target_name): \"{target_name}\"")
            else:
                _print(f"  Arg3 (target_name): 0x{target_name_ptr:x}")
        
        # Arg4: CK_MECHANISM_TYPE target_mechanism
        target_mech = arch.read_arg_register(4)
        _print(f"  Arg4 (target_mechanism): 0x{target_mech:x}")
        
        # Arg5: CK_ATTRIBUTE_TYPE operation
        operation = arch.read_arg_register(5)
        _print(f"  Arg5 (operation): 0x{operation:x}")
        
        # Arg6: int key_size
        key_size = arch.read_arg_register(6)
        _print(f"  Arg6 (key_size): {key_size}")
        
        # Arg7: CK_FLAGS flags
        flags = arch.read_arg_register(7)
        _print(f"  Arg7 (flags): 0x{flags:x}")
        
        # Set up exit callback
        context = {'call_num': call_num, 'function': 'crypt_derive'}
        _set_return_breakpoint(frame, 'crypt_derive_exit_callback', context)
    
    except Exception as e:
        _print(f"  [!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    return False


def crypt_derive_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for crypt_derive() - parses PK11SymKey* return value"""
    global SEC_DEBUG_RUN
    
    if not SEC_DEBUG_RUN:
        _cleanup_return_context(bp_id)
        return False
    
    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')
    
    _print(f"\n[crypt_derive_exit] Call #{call_num}")
    
    try:
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()
        
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:
            return_value = arch.read_register("rax")
        
        _print(f"  Return value (PK11SymKey*): 0x{return_value:x}")
        
        if return_value and return_value > 0:
            _print(f"    [crypt_derive] Parsing returned PK11SymKey structure...")
            symkey_result = parse_pk11symkey_struct(process, return_value)
            
            if symkey_result:
                _print(f"    [crypt_derive] ✓ Successfully extracted SECItem from returned PK11SymKey!")
                _print(f"        data_ptr: 0x{symkey_result['data_ptr']:x}")
                _print(f"        length: {symkey_result['len']} bytes")
                _print(f"        hex (first 64 bytes): {symkey_result['hex'][:128]}")
            else:
                _print(f"    [crypt_derive] ! Failed to parse returned PK11SymKey")
    
    except Exception as e:
        _print(f"  [!] Error: {e}")
    
    _print(f"{'='*70}\n")
    _cleanup_return_context(bp_id)
    return False


# ============================================================================
# Memory Dump Hooks - Always Active
# Simple hooks that trigger memory dumps at key lifecycle events
# ============================================================================

def iketcp_cleanup_entry_callback(frame, bp_loc, internal_dict):
    """Entry callback for iketcp_cleanup() - triggers memory dump"""
    global _dumper
    
    _print(f"[iketcp_cleanup] Triggering memory dump...")
    
    if _dumper:
        _dumper.dump_full_memory("iketcp_cleanup")
    
    return False


def cleanup_dh_shared_secret_entry_callback(frame, bp_loc, internal_dict):
    """Entry callback for cleanup_dh_shared_secret() - triggers memory dump"""
    global _dumper
    
    _print(f"[cleanup_dh_shared_secret] Triggering memory dump...")
    
    if _dumper:
        _dumper.dump_full_memory("cleanup_dh_shared_secret")
    
    return False


def terminate_a_connection_entry_callback(frame, bp_loc, internal_dict):
    """Entry callback for terminate_a_connection() - triggers memory dump"""
    global _dumper
    
    _print(f"[terminate_a_connection] Triggering memory dump...")
    
    if _dumper:
        _dumper.dump_full_memory("terminate_a_connection")
    
    return False


def rekey_connection_now_entry_callback(frame, bp_loc, internal_dict):
    """Entry callback for rekey_connection_now() - triggers memory dump"""
    global _dumper
    
    _print(f"[rekey_connection_now] Triggering memory dump...")
    
    if _dumper:
        _dumper.dump_full_memory("rekey_connection_now")
    
    return False


def ike_sa_rekey_skeyseed_entry_callback(frame, bp_loc, internal_dict):
    """
    Entry callback for ike_sa_rekey_skeyseed()

    Sets up exit callback to capture the new SKEYSEED (return value).

    Signature (inferred):
        PK11SymKey *ike_sa_rekey_skeyseed(...)
    """
    global _dumper, _call_counters

    _call_counters['ike_sa_rekey_skeyseed'] = _call_counters.get('ike_sa_rekey_skeyseed', 0) + 1
    call_num = _call_counters['ike_sa_rekey_skeyseed']

    _print(f"\n{'='*70}")
    _print(f"[ike_sa_rekey_skeyseed_entry] Call #{call_num}")
    _print(f"{'='*70}")
    _print(f"  Triggering memory dump...")

    if _dumper:
        _dumper.dump_full_memory("ike_sa_rekey_skeyseed")

    try:
        context = {'call_num': call_num, 'function': 'ike_sa_rekey_skeyseed'}
        _set_return_breakpoint(frame, 'ike_sa_rekey_skeyseed_exit_callback', context)
    except Exception as e:
        _print(f"  [!] Error setting return breakpoint: {e}")
        import traceback
        traceback.print_exc()

    return False


def ike_sa_rekey_skeyseed_exit_callback(frame, bp_loc, internal_dict, bp_id: int):
    """Exit callback for ike_sa_rekey_skeyseed() - extracts new SKEYSEED from return value"""
    global _keylog_writer

    context = _get_return_context(bp_id)
    call_num = context.get('call_num', '?')

    _print(f"\n[ike_sa_rekey_skeyseed_exit] Call #{call_num}")

    try:
        arch = ArchitectureHelper(frame)
        process = frame.GetThread().GetProcess()

        # Return value is PK11SymKey* containing new SKEYSEED
        if arch.is_aarch64:
            return_value = arch.read_register("x0")
        else:
            return_value = arch.read_register("rax")

        _print(f"  Return value (PK11SymKey*): 0x{return_value:x}")

        if return_value and return_value > 0x1000:
            _print(f"    [ike_sa_rekey_skeyseed] Parsing returned PK11SymKey...")
            symkey_result = parse_pk11symkey_struct(process, return_value)

            if symkey_result:
                _print(f"    [✓] Successfully extracted new SKEYSEED from PK11SymKey!")
                _print(f"        Length: {symkey_result['len']} bytes")
                _print(f"        Hex (first 64 bytes): {symkey_result['hex'][:128]}")

                # Save to keylog with "rekey" suffix
                if _keylog_writer and 'bytes' in symkey_result:
                    try:
                        _keylog_writer.add_ike_key("SKEYSEED_rekey", symkey_result['bytes'])
                        _print(f"    [+] SKEYSEED_rekey saved to keylog")
                    except Exception as e:
                        _print(f"    [!] Keylog write failed: {e}")
            else:
                _print(f"    [!] Failed to parse returned PK11SymKey")

    except Exception as e:
        _print(f"  [!] Error: {e}")
        import traceback
        traceback.print_exc()

    _print(f"{'='*70}\n")
    _cleanup_return_context(bp_id)
    return False


def rekey_now_entry_callback(frame, bp_loc, internal_dict):
    """Entry callback for rekey_now() - triggers memory dump"""
    global _dumper
    
    _print(f"[rekey_now] Triggering memory dump...")
    
    if _dumper:
        _dumper.dump_full_memory("rekey_now")
    
    return False
