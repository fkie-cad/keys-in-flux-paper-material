# dropbear_dbg.py
# Minimal LLDB helpers for fork-y daemons like Dropbear.
# Load with: (lldb) command script import /path/dropbear_dbg.py

import lldb, os

def _t(debugger):  # SBTarget
    return debugger.GetSelectedTarget()

def _p(exe_ctx):   # SBProcess
    return exe_ctx.process

# --- follow fork -------------------------------------------------------------

def cmd_followfork(debugger, command, exe_ctx, result, _int):
    mode = (command or "child").strip()
    if mode not in ("child", "parent"):
        result.SetError("usage: followfork [child|parent]")
        return
    debugger.HandleCommand(f"settings set target.process.follow-fork-mode {mode}")
    result.PutCString(f"follow-fork-mode = {mode}")

# --- breakpoints for accept/fork/clone --------------------------------------

def cmd_br_fork(debugger, command, exe_ctx, result, _int):
    for sym in ("accept", "accept4", "fork", "vfork", "clone", "clone3"):
        debugger.HandleCommand(f"breakpoint set -n {sym}")
    result.PutCString("breakpoints set: accept, accept4, fork, vfork, clone, clone3")

# --- wait & attach to a fresh child by name ---------------------------------

def cmd_waitattach(debugger, command, exe_ctx, result, _int):
    name = (command or "dropbear").strip()
    debugger.HandleCommand(f"process attach --name {name} --waitfor")
    # LLDB prints its own status/errors.

# --- watchpoints -------------------------------------------------------------

def _parse_setwp_args(argv):
    if not argv:
        raise ValueError("usage: setwp <addr> [size=1] [r|w|rw]")
    addr = int(argv[0], 0)
    size = int(argv[1], 0) if len(argv) > 1 else 1
    mode = argv[2].lower() if len(argv) > 2 else "rw"
    read = 'r' in mode
    write = 'w' in mode
    return addr, size, read, write

def cmd_setwp(debugger, command, exe_ctx, result, _int):
    try:
        argv = command.split()
        addr, size, read, write = _parse_setwp_args(argv)
    except Exception as e:
        result.SetError(str(e))
        return

    target = _t(debugger)
    err = lldb.SBError()
    wp = target.WatchAddress(addr, size, read, write, err)
    if err.Fail() or not wp or not wp.IsValid():
        result.SetError(f"failed to set watchpoint: {err.GetCString()}")
        return
    result.PutCString(f"watchpoint #{wp.GetID()} @ {hex(addr)} size={size} mode={'r' if read else ''}{'w' if write else ''}")

def cmd_setwp_expr(debugger, command, exe_ctx, result, _int):
    # Example: setwp-expr "&some_global" 4 rw
    parts = command.split()
    if not parts:
        result.SetError("usage: setwp-expr <expr> [size=1] [r|w|rw]")
        return
    expr = parts[0]
    size = int(parts[1], 0) if len(parts) > 1 else 1
    mode = parts[2].lower() if len(parts) > 2 else "rw"
    read = 'r' in mode
    write = 'w' in mode

    frame = exe_ctx.frame
    val = frame.EvaluateExpression(expr)
    if not val.IsValid() or val.GetError().Fail():
        msg = val.GetError().GetCString() if val and val.GetError() else "invalid expression"
        result.SetError(f"expr failed: {msg}")
        return
    try:
        addr = int(val.GetValue(), 0)
    except Exception:
        result.SetError(f"expr did not yield an address: {val.GetValue()}")
        return

    target = _t(debugger)
    err = lldb.SBError()
    wp = target.WatchAddress(addr, size, read, write, err)
    if err.Fail() or not wp or not wp.IsValid():
        result.SetError(f"failed to set watchpoint: {err.GetCString()}")
        return
    result.PutCString(f"watchpoint #{wp.GetID()} @ {hex(addr)} size={size} mode={'r' if read else ''}{'w' if write else ''}")

def cmd_listwp(debugger, command, exe_ctx, result, _int):
    target = _t(debugger)
    any_wp = False
    for wp in target.watchpoint_iter():
        any_wp = True
        mode = ("r" if wp.WatchReads() else "") + ("w" if wp.WatchWrites() else "")
        result.PutCString(f"#{wp.GetID()}  addr={hex(wp.GetWatchAddress())}  size={wp.GetWatchSize()}  mode={mode}  enabled={wp.IsEnabled()}  hits={wp.GetHitCount()}")
    if not any_wp:
        result.PutCString("(no watchpoints)")

def cmd_delwp(debugger, command, exe_ctx, result, _int):
    target = _t(debugger)
    arg = command.strip()
    if arg == "all" or arg == "":
        for wp in list(target.watchpoint_iter()):
            target.DeleteWatchpoint(wp.GetID())
        result.PutCString("deleted all watchpoints")
    else:
        try:
            wid = int(arg, 0)
        except Exception:
            result.SetError("usage: delwp [id|all]")
            return
        ok = target.DeleteWatchpoint(wid)
        if ok:
            result.PutCString(f"deleted watchpoint {wid}")
        else:
            result.SetError(f"no such watchpoint: {wid}")

# --- stop diagnostics --------------------------------------------------------

def cmd_onstop(debugger, command, exe_ctx, result, _int):
    thr = _p(exe_ctx).GetSelectedThread()
    desc = thr.GetStopDescription(512)
    result.PutCString(f"Stop reason: {thr.GetStopReason()} ({desc})")
    if thr.GetStopReason() == lldb.eStopReasonWatchpoint:
        data = [thr.GetStopReasonDataAtIndex(i) for i in range(thr.GetStopReasonDataCount())]
        result.PutCString(f"Watchpoint payload: {data}")

# --- module init -------------------------------------------------------------

def __lldb_init_module(debugger, _int):
    M = "dropbear_dbg"
    cmds = {
        "followfork": "cmd_followfork",
        "br-fork": "cmd_br_fork",
        "waitattach": "cmd_waitattach",
        "setwp": "cmd_setwp",
        "setwp-expr": "cmd_setwp_expr",
        "listwp": "cmd_listwp",
        "delwp": "cmd_delwp",
        "onstop": "cmd_onstop",
    }
    for name, fn in cmds.items():
        debugger.HandleCommand(f"command script add -f {M}.{fn} {name}")
    print("dropbear_dbg loaded. Commands: " + ", ".join(cmds.keys()))
