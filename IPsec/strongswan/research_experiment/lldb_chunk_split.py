# /tmp/lldb_chunk_split.py
# LLDB helper: print chunk_split args on AArch64 (x0..x7 + stack args)
import lldb

def _get_reg_int(frame, name):
    reg = frame.FindRegister(name)
    if not reg.IsValid():
        return None
    try:
        # reg.GetValue() returns string like '0x1234' or '0'
        val = reg.GetValue()
        if val is None:
            return None
        return int(val, 0)
    except Exception:
        try:
            return int(reg.GetValue(), 16)
        except Exception:
            return None

def _read_bytes(process, addr, size=64):
    err = lldb.SBError()
    if not addr or addr == 0:
        return b''
    data = process.ReadMemory(addr, size, err)
    if not err.Success():
        return None
    # ensure bytes
    if isinstance(data, str):
        try:
            data = data.encode('latin-1')
        except Exception:
            pass
    return data

def _hex_ascii_preview(process, addr, size=64):
    data = _read_bytes(process, addr, size)
    if data is None:
        return "(mem read failed)"
    if len(data) == 0:
        return "(NULL)"
    n = min(32, len(data))
    hexd = ' '.join(f"{x:02x}" for x in data[:n])
    ascii = ''.join((chr(x) if 32 <= x < 127 else '.') for x in data[:n])
    return f"{hexd}  |{ascii}|"

def print_chunk_split_args(debugger, command=None, result=None, internal_dict=None):
    """Print chunk_split args (x0..x7 & stack args 9..16) for AArch64."""
    target = debugger.GetSelectedTarget()
    if not target:
        print("No target")
        return
    proc = target.GetProcess()
    if not proc.IsValid():
        print("No process")
        return
    thread = proc.GetSelectedThread()
    if not thread.IsValid():
        print("No thread")
        return
    frame = thread.GetFrameAtIndex(0)
    if not frame.IsValid():
        print("No frame")
        return

    # registers x0..x7
    regs = {}
    for i in range(8):
        name = f"x{i}"
        regs[name] = _get_reg_int(frame, name)

    sp = _get_reg_int(frame, "sp")
    print("=== register args (x0..x7) ===")
    for i in range(8):
        name = f"x{i}"
        val = regs[name]
        print(f"{name:>3} = {hex(val) if val is not None else val}")
        if val and val > 0x1000:
            print("    ->", _hex_ascii_preview(proc, val, 128))

    print("\n=== stack args (arg9..arg16) ===")
    # read 8 pointer-sized words from stack: arg9 @ sp+0, arg10 @ sp+8, ...
    for i in range(8):
        argnum = 9 + i
        addr = sp + i*8
        err = lldb.SBError()
        ptr = proc.ReadPointerFromMemory(addr, err)
        if not err.Success():
            val = None
        else:
            try:
                val = int(ptr)
            except Exception:
                val = None
        print(f"arg{argnum:2d} @ {hex(addr)} = {hex(val) if val else val}")
        if val and val > 0x1000:
            print("    ->", _hex_ascii_preview(proc, val, 128))

    # optionally try typed deref if type exists (example sk_vector)
    type_name = "sk_vector"   # change if you want other type names
    found = target.FindFirstType(type_name)
    if found.IsValid():
        print(f"\nType '{type_name}' found in debug info; attempting typed dereferences:")
        # try to deref typical pointer args (example: arg6, arg10, arg12, arg14, arg16)
        # arg positions where &sk_* appear in your call: x5 (arg6), stack arg10 (arg10), etc.
        candidates = [("x5", regs.get("x5")), ("stack_arg10", proc.ReadPointerFromMemory(sp + 8, lldb.SBError())),
                      ("stack_arg12", proc.ReadPointerFromMemory(sp + 24, lldb.SBError())),
                      ("stack_arg14", proc.ReadPointerFromMemory(sp + 40, lldb.SBError())),
                      ("stack_arg16", proc.ReadPointerFromMemory(sp + 56, lldb.SBError()))]
        for name, ptr in candidates:
            try:
                addr = int(ptr)
            except Exception:
                addr = None
            if addr and addr > 0x1000:
                expr = frame.EvaluateExpression(f"*( {type_name}* ) {hex(addr)}")
                if expr.IsValid() and expr.GetError().Success():
                    print(f"\n{name} @ {hex(addr)} (typed {type_name}):")
                    # print object description if available
                    desc = expr.GetObjectDescription() or expr.GetSummary() or expr.GetValue()
                    print(desc)
                else:
                    print(f"\n{name} @ {hex(addr)}: (typed eval failed: {expr.GetError().GetCString()})")
            else:
                print(f"\n{name} = {ptr} (not readable as pointer)")

def __lldb_init_module(debugger, internal_dict):
    # Register command `chunk_split_args` in lldb
    debugger.HandleCommand('command script add -f lldb_chunk_split.print_chunk_split_args chunk_split_args')
    print('The "chunk_split_args" command has been installed. Use "chunk_split_args" at a breakpoint.')
