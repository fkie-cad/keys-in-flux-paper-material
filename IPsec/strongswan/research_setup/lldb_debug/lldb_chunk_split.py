# lldb_chunk_split.py
# Hook strongSwan chunk_split() and dump KEYMAT/content intelligently.
# - Reads x0 (KEYMAT ptr), length from x1 (fallback 0x80 if missing)
# - Recognizes format strings:
#       "ammmmaa" (IKE SA): split as SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
#       "aaaa"    (CHILD SA): split as ENCR_i | INTEG_i | ENCR_r | INTEG_r
# - Only reads memory from known-pointer args.
# - Installs entry breakpoint and (best-effort) one-shot return breakpoint.
#
# Usage in LLDB:
#   (lldb) command script import /path/to/lldb_chunk_split.py
#   (lldb) process attach -p <PID>
#   (lldb) install_chunk_split_bp
#   (lldb) continue
#
import lldb, os, time, struct


FALLBACK_PREVIEW = 0x80     # when x1 (len) is unavailable
PAGE = 4096

_cb_names = {}  # bp_id -> generated global callback name

NAME_TAG = "chunk_split"  # label we give our entry BPs
LOG_TMPL = "/tmp/chunk_split_{pid}_{time}.log"   # supports {pid} and {time}
DEFAULT_LOG_FALLBACK = "/tmp/chunk_split.log"
_ACTIVE_PID = None



# ------------------------ log utilities ------------------------
def _resolve_log_path():
    """
    Resolve the effective log path by formatting LOG_TMPL with:
      {pid}  -> current process id (or 'nopid' if unknown)
      {time} -> current epoch seconds (int)
    Falls back to DEFAULT_LOG_FALLBACK if formatting fails.
    """
    pid = None
    try:
        if _ACTIVE_PID:
            pid = _ACTIVE_PID
        else:
            dbg = lldb.debugger
            if dbg:
                proc = dbg.GetSelectedTarget().GetProcess()
                if proc and proc.IsValid():
                    pid = proc.GetProcessID()
    except Exception:
        pass

    pid_str = str(pid) if pid else "nopid"
    now_secs = int(time.time())

    try:
        return LOG_TMPL.format(pid=pid_str, time=now_secs)
    except Exception:
        # Last-ditch fallback
        return DEFAULT_LOG_FALLBACK


def _log_write(s: str):
    try:
        path = _resolve_log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(s)
    except Exception:
        pass


# ---------- ABI detection ----------
ARCH_DEFAULT = "arm64"  # fallback if detection fails

def _detect_abi(target=None, process=None) -> str:
    try:
        tgt = target or (lldb.debugger and lldb.debugger.GetSelectedTarget())
        if tgt:
            tri = (tgt.GetTriple() or "").lower()
            if "x86_64" in tri or "amd64" in tri:
                return "x86_64"
            if "aarch64" in tri or "arm64" in tri:
                return "arm64"
        proc = process or (tgt and tgt.GetProcess())
        if proc and proc.IsValid() and proc.GetAddressByteSize() == 8:
            return ARCH_DEFAULT
    except Exception:
        pass
    return ARCH_DEFAULT

def _sp_name(abi):   return "sp"  if abi == "arm64"  else "rsp"

def _retaddr(frame, abi, proc):
    if abi == "arm64":
        return _get_reg_int(frame, "x30")
    # x86-64: return address sits at [rsp] on entry
    rsp = _get_reg_int(frame, "rsp")
    return _read_u64(proc, rsp) if rsp else None


# ------------------------ Breakpoint naming + cleanup helpers ---
# --- Breakpoint/stop-hook sanitation helpers ---
NAME_TAG = "chunk_split"  # our entry BP label

def _bp_has_name(bp, name: str) -> bool:
    try:
        if hasattr(bp, "HasName") and callable(getattr(bp, "HasName")):
            return bp.HasName(name)
        sl = lldb.SBStringList()
        bp.GetNames(sl)
        for i in range(sl.GetSize()):
            if sl.GetStringAtIndex(i) == name:
                return True
    except Exception:
        pass
    return False

def _bp_has_commands(bp) -> bool:
    try:
        sl = lldb.SBStringList()
        bp.GetCommandLineCommands(sl)
        return sl.GetSize() > 0
    except Exception:
        return False

def _clear_bp_commands(bp):
    """CLI is the most portable way to drop command-line python (which creates autogen wrappers)."""
    try:
        lldb.debugger.HandleCommand(f"breakpoint command delete {bp.GetID()}")
    except Exception:
        pass

def _is_autogen_script_callback(bp) -> bool:
    # Script callback name path
    try:
        if hasattr(bp, "GetScriptCallbackFunctionName"):
            fn = bp.GetScriptCallbackFunctionName() or ""
            if fn.startswith("lldb_autogen_python_bp_callback_func__"):
                return True
    except Exception:
        pass
    # Command-line commands containing autogen markers
    try:
        sl = lldb.SBStringList()
        bp.GetCommandLineCommands(sl)
        for i in range(sl.GetSize()):
            s = sl.GetStringAtIndex(i) or ""
            if "lldb_autogen_python_bp_callback_func__" in s:
                return True
            # treat any Python function invocation as suspicious (will cause autogen)
            if "frame, bp_loc" in s or s.strip().startswith("script "):
                return True
    except Exception:
        pass
    return False

def _sanitize_breakpoints(target):
    """Remove/convert any breakpoints that could spawn autogen callbacks."""
    removed, cleaned = [], []
    for i in range(target.GetNumBreakpoints()):
        bp = target.GetBreakpointAtIndex(i)
        if not (bp and bp.IsValid()):
            continue
        if _bp_has_commands(bp) or _is_autogen_script_callback(bp):
            if _bp_has_name(bp, NAME_TAG):
                # keep our entry BP, but strip commands; we'll set a stable callback later
                _clear_bp_commands(bp)
                cleaned.append(bp.GetID())
            else:
                # old return BPs or foreign BPs: delete entirely
                removed.append(bp.GetID())
    for bid in removed:
        target.BreakpointDelete(bid)
    if removed:
        _pr(f"[sanitize] deleted breakpoints with autogen/commands: {removed}")
    if cleaned:
        _pr(f"[sanitize] stripped command-line handlers from BPs: {cleaned}")

def _delete_autogen_stop_hooks(target):
    """Brutally remove all stop-hooks; autogen python often hides here."""
    try:
        lldb.debugger.HandleCommand("target stop-hook delete -1")
        _pr("[sanitize] deleted all target stop-hooks")
    except Exception:
        pass

def dump_bp_callbacks(debugger, command, result, _):
    """Debug helper: list all BPs, their script callback names and command lines."""
    target = debugger.GetSelectedTarget()
    if not target:
        print("No target."); return
    out = []
    for i in range(target.GetNumBreakpoints()):
        bp = target.GetBreakpointAtIndex(i)
        if not (bp and bp.IsValid()):
            continue
        try:
            scb = bp.GetScriptCallbackFunctionName() if hasattr(bp, "GetScriptCallbackFunctionName") else ""
        except Exception:
            scb = ""
        sl = lldb.SBStringList()
        try:
            bp.GetCommandLineCommands(sl)
            cmds = [sl.GetStringAtIndex(j) for j in range(sl.GetSize())]
        except Exception:
            cmds = []
        out.append(f"BP id={bp.GetID()} enabled={bp.IsEnabled()} autogen={_is_autogen_script_callback(bp)} "
                   f"script_cb='{scb}' cmds={cmds}")
    print("\n".join(out) if out else "(no breakpoints)")

# ------------------------ general utilities ------------------------
def _pr(s: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    out = f"[{ts}] {s}\n"
    print(out, end="")
    _log_write(out)

def _get_reg_int(frame, name: str):
    r = frame.FindRegister(name)
    if not r.IsValid():
        return None
    v = r.GetValue()
    if v is None:
        return None
    try:
        return int(v, 0)  # handles "0x.."
    except Exception:
        try:
            return int(v, 16)
        except Exception:
            return None

def _read_mem(process, addr: int, size: int):
    if not addr or size <= 0:
        return b""
    err = lldb.SBError()
    data = process.ReadMemory(addr, size, err)
    if not err.Success() or data is None:
        return None
    if isinstance(data, str):
        data = data.encode("latin-1", errors="ignore")
    return data

def _read_cstr(process, addr: int, maxlen: int = 64) -> str:
    if not addr:
        return ""
    s = bytearray()
    cur = addr
    budget = maxlen
    while budget > 0:
        b = _read_mem(process, cur, 1)
        if not b:
            break
        if b[0] == 0:
            break
        s.append(b[0])
        cur += 1
        budget -= 1
    try:
        return s.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _hexdump_block(data: bytes, base: int, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off+width]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'0x{base+off:016x}  {hexs:<{width*3-1}}  |{asci}|')
    return "\n".join(lines) if lines else "(empty)"

def _read_u64(process, addr: int):
    """Read a 64-bit little-endian scalar from memory (for stack-passed scalars)."""
    raw = _read_mem(process, addr, 8)
    if not raw or len(raw) < 8:
        return None
    return struct.unpack("<Q", raw)[0]

def _looks_ptr(v: int) -> bool:
    return v is not None and v >= 0x10000  # cheap heuristic for user VA


# ------------------------ argument dumpers ------------------------

def _dump_basic_args(frame, abi):
    """Print x0..x7, sp, with pointer-safe previews only for known pointer args."""
    if abi == "arm64":
        reg_list = ["x0","x1","x2","x3","x4","x5","x6","x7"]
        ptr_peek = {"x0","x2","x4","x6"}  # keymat.ptr, fmt, &skd, &sk_ai
    else:  # x86_64 SysV; first arg (struct) consumes rdi+rsi
        reg_list = ["rdi","rsi","rdx","rcx","r8","r9"]
        ptr_peek = {"rdi","rdx","r8"}     # keymat.ptr, fmt, &skd

    vals = { r: _get_reg_int(frame, r) for r in reg_list }
    sp   = _get_reg_int(frame, _sp_name(abi))

    proc = frame.GetThread().GetProcess()
    #regs = { f"x{i}": _get_reg_int(frame, f"x{i}") for i in range(8) }


    lines = []
    lines.append("=== register args ===")
    for r in reg_list:
        v = vals[r]
        lines.append(f"{r:>4} = {hex(v) if v is not None else v}")
        if r in ptr_peek and _looks_ptr(v):
            peek = _read_mem(proc, v, 64)
            if peek is None:
                lines.append(f"      -> {hex(v)} : (mem read failed)")
            else:
                hexd = ' '.join(f"{b:02x}" for b in peek)
                asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in peek)
                lines.append(f"      -> {hex(v)} : {hexd}  |{asci}|")
    lines.append(f"{_sp_name(abi):>4} = {hex(sp) if sp is not None else sp}")
    _pr("\n".join(lines))
    """
    lines.append("=== register args (x0..x7) ===")
    for name in ( "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7" ):
        val = regs[name]
        lines.append(f"{name:>3} = {hex(val) if val is not None else val}")
        # Only preview memory for the known pointer arguments:
        # x0 = keymat ptr, x2 = fmt ptr, x4 = out chunk ptr, x6 = out chunk ptr
        if name in ("x0", "x2", "x4", "x6") and _looks_ptr(val):
            peek = _read_mem(proc, val, 64)
            if peek is None:
                lines.append(f"    -> {hex(val)} : (mem read failed)")
            else:
                ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in peek)
                hexd  = ' '.join(f"{b:02x}" for b in peek)
                lines.append(f"    -> {hex(val)} : {hexd}  |{ascii}|")
    lines.append(f"sp  = {hex(sp) if sp else sp}")

    _pr("\n".join(lines))
    """
    return vals, sp


def _dump_keymat_and_maybe_split(frame, abi):
    """
    Read KEYMAT at x0 (ptr) for x1 (len) bytes, with fallback to 0x80 if x1 missing.
    Then split based on fmt string ("ammmmaa" or "aaaa") if possible.
    """
    thread = frame.GetThread()
    proc   = thread.GetProcess()
    tgt    = proc.GetTarget()

    # old way only valid for ARM64
    #x0 = _get_reg_int(frame, "x0")  # keymat.ptr
    #x1 = _get_reg_int(frame, "x1")  # keymat.len
    #x2 = _get_reg_int(frame, "x2")  # fmt ptr
    if abi == "arm64":
        key_ptr = _get_reg_int(frame, "x0")
        key_len = _get_reg_int(frame, "x1")
        fmt_ptr = _get_reg_int(frame, "x2")
    else:  # x86_64 SysV (struct-by-value consumes rdi+rsi)
        key_ptr = _get_reg_int(frame, "rdi")
        key_len = _get_reg_int(frame, "rsi")
        fmt_ptr = _get_reg_int(frame, "rdx")


    fmt = _read_cstr(proc, fmt_ptr, 32) if _looks_ptr(fmt_ptr) else ""
    size = key_len if (key_len is not None and key_len > 0) else FALLBACK_PREVIEW

    if not _looks_ptr(key_ptr):
        _pr("[KEYMAT] x0/rdi not a valid pointer; skipping.")
        return

    data = _read_mem(proc, key_ptr, size)
    if data is None:
        _pr(f"[KEYMAT] read failed @ {hex(key_ptr)} len=0x{size:x}")
        return

    _pr(f"[KEYMAT] @{hex(key_ptr)} len=0x{size:x} ({size} bytes) fmt='{fmt or '?'}'\n{_hexdump_block(data, key_ptr)}")

    # ---- splitting logic ----
    sp = _get_reg_int(frame, _sp_name(abi)) or 0

    if fmt == "ammmmaa":
        # IKE SA splitter: use sizes from the call
        if abi == "arm64":
            prf_len = _get_reg_int(frame, "x3") or 0
            ai_len  = _get_reg_int(frame, "x5") or 0
            ar_len  = _get_reg_int(frame, "x7") or 0
            ei_len  = _read_u64(proc, sp + 0x08) if sp else None
            er_len  = _read_u64(proc, sp + 0x18) if sp else None
        else:  # x86_64 SysV
            # After rdi,rsi (struct), regs: rdx=fmt, rcx=key_size, r8=&skd, r9=sk_ai.len
            prf_len = _get_reg_int(frame, "rcx") or 0
            ai_len  = _get_reg_int(frame, "r9")  or 0
            # Stack args (on entry): [rsp+0x08]=&sk_ai, [0x10]=sk_ar.len, [0x18]=&sk_ar,
            # [0x20]=sk_ei.len, [0x28]=&sk_ei, [0x30]=sk_er.len, [0x38]=&sk_er, ...
            ar_len  = _read_u64(proc, sp + 0x10) if sp else None
            ei_len  = _read_u64(proc, sp + 0x20) if sp else None
            er_len  = _read_u64(proc, sp + 0x30) if sp else None

        #sp = _get_reg_int(frame, "sp") or 0
        #if sp:
        #    ei_len = _read_u64(proc, sp + 0x08)
        #    er_len = _read_u64(proc, sp + 0x18)

        if None in (ei_len, er_len):
            _pr("[KEYMAT] ammmmaa: could not read ei_len/er_len from stack; skipping field split.")
            return

        # Compose the 7-field layout
        layout = [
            ("SK_d",  prf_len),
            ("SK_ai", ai_len),
            ("SK_ar", ar_len),
            ("SK_ei", ei_len),
            ("SK_er", er_len),
            ("SK_pi", prf_len),
            ("SK_pr", prf_len),
        ]
        _print_split("IKE SA", key_ptr, data, layout, expect_total=size)

    elif fmt == "aaaa":
        # CHILD SA splitter: enc_i, integ_i, enc_r, integ_r
        #enc_i_len = _get_reg_int(frame, "x3") or 0
        #integ_i_len = _get_reg_int(frame, "x5") or 0
        #enc_r_len = _get_reg_int(frame, "x7") or 0
        if abi == "arm64":
            # x0..x7 cover first 8 args; stack holds the rest
            enc_i_len   = _get_reg_int(frame, "x3") or 0
            integ_i_len = _get_reg_int(frame, "x5") or 0
            enc_r_len   = _get_reg_int(frame, "x7") or 0
            # stack: arg9=int_size(responder) at sp+0x00, arg10=integ_r ptr at sp+0x08
            #integ_r_len = _read_u64(proc, sp + 0x00) if sp else None # need to validated
            integ_r_len = _read_u64(proc, sp + 0x08) if sp else None
        else:  # x86_64
            # regs: rdi/rsi struct, rdx=fmt, rcx=enc_size_i, r8=encr_i, r9=int_size_i
            enc_i_len   = _get_reg_int(frame, "rcx") or 0
            integ_i_len = _get_reg_int(frame, "r8")  or 0
            enc_r_len   = _get_reg_int(frame, "r9") or 0
            integ_r_len = _read_u64(proc, sp + 0x08) if sp else None
            # stack: arg6=integ_i ptr [rsp+0x08], arg7=enc_size_r [0x10], arg8=encr_r ptr [0x18],
            #        arg9=int_size_r [0x20], arg10=integ_r ptr [0x28]
            #enc_r_len   = _read_u64(proc, sp + 0x10) if sp else None
            #integ_r_len = _read_u64(proc, sp + 0x20) if sp else None

        #sp = _get_reg_int(frame, "sp") or 0
        

        if integ_r_len is None:
            _pr("[KEYMAT] aaaa: could not read integ_r_len from stack; skipping field split.")
            return

        layout = [
            ("ENCR_i",  enc_i_len),
            ("INTEG_i", integ_i_len),
            ("ENCR_r",  enc_r_len),
            ("INTEG_r", integ_r_len),
        ]
        # this are the keys we summarize in the Paper as ESP keys (though names differ)
        _print_split("CHILD SA", key_ptr, data, layout, expect_total=size)

    else:
        # If explicitly requested: for x1 == 0xe0 try IKE SA split anyway (common AES-256+SHA256)
        if abi == "arm64" and key_len == 0xE0:
            prf_len_guess = 32
            # We still try to use provided lens if present; otherwise fall back to common 32/32/32
            prf_len  = _get_reg_int(frame, "x3") or prf_len_guess
            ai_len   = _get_reg_int(frame, "x5") or 32
            ar_len   = _get_reg_int(frame, "x7") or 32

            ei_len = _read_u64(proc, sp + 0x08) if sp else 32
            er_len = _read_u64(proc, sp + 0x18) if sp else 32

            layout = [
                ("SK_d",  prf_len),
                ("SK_ai", ai_len),
                ("SK_ar", ar_len),
                ("SK_ei", ei_len or 32),
                ("SK_er", er_len or 32),
                ("SK_pi", prf_len),
                ("SK_pr", prf_len),
            ]
            # these are the keys we summarize in the Paper as IKE keys (though names differ)
            _print_split("IKE SA (fmt unknown, len=0xE0)", key_ptr, data, layout, expect_total=size)
        elif abi != "arm64" and key_len == 0xE0:
            prf_len_guess = 32
            # We still try to use provided lens if present; otherwise fall back to common 32/32/32
            prf_len  = _get_reg_int(frame, "rcx") or prf_len_guess
            ai_len   = _get_reg_int(frame, "r8") or 32
            ar_len   = _get_reg_int(frame, "r9") or 32

            ei_len = _read_u64(proc, sp + 0x08) if sp else 32
            er_len = _read_u64(proc, sp + 0x18) if sp else 32

            layout = [
                ("SK_d",  prf_len),
                ("SK_ai", ai_len),
                ("SK_ar", ar_len),
                ("SK_ei", ei_len or 32),
                ("SK_er", er_len or 32),
                ("SK_pi", prf_len),
                ("SK_pr", prf_len),
            ]
            _print_split("IKE SA (fmt unknown, len=0xE0)", key_ptr, data, layout, expect_total=size)


def _print_split(kind: str, base_addr: int, blob: bytes, fields, expect_total: int):
    """
    fields = [ (name, length), ... ]
    """
    lines = [f"[KEYMAT SPLIT] {kind}"]
    off = 0
    total_declared = sum(l for _, l in fields)
    mismatch = ""
    if total_declared != expect_total:
        mismatch = f" [warn: declared sum=0x{total_declared:x} != len=0x{expect_total:x}]"
    lines.append(f"Total: 0x{expect_total:x} bytes{mismatch}")

    for name, ln in fields:
        if ln is None or ln <= 0 or off + ln > len(blob):
            lines.append(f"  {name:<6} : <unavailable> (len={ln})")
            continue
        chunk = blob[off:off+ln]
        hexd  = chunk.hex()
        lines.append(f"  {name:<6} (0x{ln:x}): {hexd}")
        off += ln
    _pr("\n".join(lines))


# ------------------------ callbacks ------------------------

def chunk_split_entry_callback(frame, bp_loc, _dict):
    """Entry breakpoint: print args, dump keymat, set one-shot return bp, continue."""
    try:
        proc   = frame.GetThread().GetProcess()
        target = proc.GetTarget()

        # per-PID logfile hint
        global _ACTIVE_PID
        try:
            _ACTIVE_PID = proc.GetProcessID()
            _pr(f"(logging to {_resolve_log_path()})")
        except Exception:
            pass

        # Clean any autogen breakpoints/stop-hooks *every time* we hit entry
        _sanitize_breakpoints(target)
        _delete_autogen_stop_hooks(target)

        abi = _detect_abi(target, proc)
        _pr(f"chunk_split ENTRY breakpoint hit. (abi={abi})")
        _dump_basic_args(frame, abi)
        _dump_keymat_and_maybe_split(frame, abi)

        # one-shot return breakpoint at function return (stable callback name)
        retaddr = _retaddr(frame, abi, proc)
        if not retaddr:
            _pr("No return address; not setting return breakpoint.")
            proc.Continue(); return

        bp_ret = target.BreakpointCreateByAddress(retaddr)
        if not bp_ret.IsValid():
            _pr(f"Failed to create return breakpoint at {hex(retaddr)}")
            proc.Continue(); return

        try: bp_ret.SetOneShot(True)
        except Exception: pass

        # Stable, fully-qualified callback (no autogen wrappers)
        bp_ret.SetScriptCallbackFunction(f"{__name__}.chunk_split_return_callback")
        _pr(f"Return breakpoint set at {hex(retaddr)} (id={bp_ret.GetID()}). Continuing.")
        proc.Continue()

    except Exception as e:
        _pr(f"Entry callback error: {e}")
        try: frame.GetThread().GetProcess().Continue()
        except Exception: pass



def chunk_split_return_callback(frame, bp_loc, _dict):
    """Return bp: small register print, continue."""
    try:
        proc = frame.GetThread().GetProcess()
        abi  = _detect_abi(proc.GetTarget(), proc)
        reg_names = ("x0","x1","x2","x3") if abi == "arm64" else ("rax","rbx","rcx","rdx")
        regs = { r: _get_reg_int(frame, r) for r in reg_names }
        lines = ["chunk_split RETURN breakpoint hit.", "=== return regs ==="]
        for r, v in regs.items():
            lines.append(f"{r} = {hex(v) if v is not None else v}")
        _pr("\n".join(lines))
        proc.Continue()
    except Exception as e:
        _pr(f"Return callback error: {e}")
        try: frame.GetThread().GetProcess().Continue()
        except Exception: pass




# ------------------------ user commands ------------------------
def install_chunk_split_bp(debugger, command, result, internal_dict):
    """Install a breakpoint on 'chunk_split' with entry callback (stable)."""
    target = debugger.GetSelectedTarget()
    if not target:
        print("No target selected."); return

    # Purge anything that can cause autogen wrappers
    _sanitize_breakpoints(target)
    _delete_autogen_stop_hooks(target)

    if command.strip() in ("--replace","-r"):
        to_del = []
        for i in range(target.GetNumBreakpoints()):
            bp_i = target.GetBreakpointAtIndex(i)
            if bp_i and bp_i.IsValid() and _bp_has_name(bp_i, NAME_TAG):
                to_del.append(bp_i.GetID())
        for bid in to_del:
            target.BreakpointDelete(bid)
        if to_del:
            _pr(f"[cleanup] removed existing '{NAME_TAG}' breakpoints: {to_del}")

    # Create the entry breakpoint
    bp = target.BreakpointCreateByName("chunk_split", target.GetExecutable().GetFilename())
    if not bp.IsValid() or bp.GetNumLocations() == 0:
        bp = target.BreakpointCreateByName("chunk_split", "")
    if not bp.IsValid() or bp.GetNumLocations() == 0:
        print("Could not find function 'chunk_split'."); return

    # Ensure no command-line commands remain on this BP
    if _bp_has_commands(bp):
        _clear_bp_commands(bp)

    # Tag and set stable Python callback
    try:
        bp.AddName(NAME_TAG)
    except Exception:
        pass
    bp.SetScriptCallbackFunction(f"{__name__}.chunk_split_entry_callback")

    print(f"Installed chunk_split entry breakpoint id={bp.GetID()} (auto return bp).")
    _pr(f"Installed chunk_split entry breakpoint id={bp.GetID()}.")




def set_chunk_split_log(debugger, command, result, internal_dict):
    """
    Set the log filename template. Supports {pid} and {time}.
      Examples:
        set_chunk_split_log /tmp/chunk_{pid}_{time}.log
        set_chunk_split_log /var/log/ike/chunk.log     # auto -> /var/log/ike/chunk_{pid}_{time}.log
        set_chunk_split_log /var/log/ike/chunk_{pid}.log  # auto adds _{time}
    """
    global LOG_TMPL
    arg = command.strip()
    if not arg:
        print(f"Current template: {LOG_TMPL}")
        print(f"Effective path  : {_resolve_log_path()}")
        return

    has_pid  = "{pid}"  in arg
    has_time = "{time}" in arg

    # If user didn’t include placeholders, append missing ones before the extension
    if not (has_pid and has_time):
        base, ext = os.path.splitext(arg)
        suffix = ""
        if not has_pid:
            suffix += "_{pid}"
        if not has_time:
            suffix += "_{time}"
        LOG_TMPL = f"{base}{suffix}{ext or ''}"
    else:
        LOG_TMPL = arg

    print(f"Log template set to: {LOG_TMPL}")
    print(f"Effective path now : {_resolve_log_path()}")


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_chunk_split.install_chunk_split_bp install_chunk_split_bp')
    debugger.HandleCommand('command script add -f lldb_chunk_split.set_chunk_split_log set_chunk_split_log')
    debugger.HandleCommand('command script add -f lldb_chunk_split.dump_bp_callbacks dump_bp_callbacks')
    print('Commands installed: install_chunk_split_bp, set_chunk_split_log, dump_bp_callbacks')