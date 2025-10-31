#!/usr/bin/env python3
"""
lldb/tracker_main.py

Modular LLDB plugin + command to attach/launch an SSH server process, set breakpoints
on key-derivation functions (symbol or pattern mode), perform pre/post memory dumps,
and run callbacks that try to extract derived SSH keys.

Usage inside lldb (recommended):
    (lldb) command script import /opt/lldb/tracker_main.py
    (lldb) trackssh --binary /usr/sbin/sshd --library openssh --mode symbols --outdir /data/dumps

Or run standalone (requires lldb python bindings available to the interpreter):
    python3 tracker_main.py --binary /usr/sbin/sshd --library openssh --mode symbols --outdir /data/dumps

The plugin registers an LLDB command "trackssh" when imported into the LLDB Python environment.
"""

import os
import sys
import argparse
import time
import json
import traceback

# Try to import lldb; this module can be used either inside lldb (preferred) or as a standalone script
try:
    import lldb
except Exception as e:
    lldb = None

# Make callbacks importable when the user mounts lldb/ under a container path.
THIS_DIR = os.path.dirname(__file__)
PARENT = os.path.abspath(THIS_DIR)
if PARENT not in sys.path:
    sys.path.insert(0, PARENT)

# Callback modules live under lldb/callbacks/<library>_cb.py
CALLBACK_PKG = "callbacks"

# Global state for temporary breakpoints and saved pre-dumps
_TEMP_STATE = {
    "pre_snapshots": {},   # bp_id -> {regions: [ (base,size,data) ], meta: {...}}
    "bp_map": {},          # temp_bp_id -> metadata
}

def create_debugger():
    if not lldb:
        raise RuntimeError("lldb module not available in this Python interpreter.")
    dbg = lldb.SBDebugger.Create()
    dbg.SetAsync(False)
    return dbg

def find_module_by_name(target, want_name):
    for i in range(target.GetNumModules()):
        m = target.GetModuleAtIndex(i)
        fn = m.GetFileSpec().GetFilename()
        if fn and want_name in fn:
            return m
    return None

def get_module_base(target, module):
    base_addr = module.GetObjectFileHeaderAddress()
    if base_addr.IsValid():
        return base_addr.GetLoadAddress(target)
    return None

def read_process_memory(process, addr, size):
    err = lldb.SBError()
    data = process.ReadMemory(addr, size, err)
    if not err.Success():
        return None
    return data

def dump_memory_regions_to_file(process, out_path_prefix):
    """
    Dump readable memory regions to files. Returns metadata list with (base, size, path).
    """
    regions = process.GetMemoryRegions()
    num = regions.GetSize()
    region_info = lldb.SBMemoryRegionInfo()
    written = []
    ts = int(time.time() * 1000)
    idx = 0
    for i in range(num):
        ok = regions.GetMemoryRegionAtIndex(i, region_info)
        if not ok:
            continue
        start = int(region_info.GetRegionBase())
        end = int(region_info.GetRegionEnd())
        size = max(0, end - start)
        if size == 0:
            continue
        # Skip unreadable regions
        if not (region_info.IsReadable()):
            continue
        err = lldb.SBError()
        data = process.ReadMemory(start, size, err)
        if not err.Success() or not data:
            continue
        fname = f"{out_path_prefix}_{ts}_{idx:03d}.raw"
        try:
            with open(fname, "wb") as f:
                f.write(data)
            written.append({"base": start, "size": size, "path": fname})
            idx += 1
        except Exception as e:
            # best-effort
            pass
    return written

def save_pre_snapshot(process, key):
    # Save a lightweight snapshot: for speed we only record hashes of regions and raw bytes for small ranges.
    # For full raw dumps use dump_memory_regions_to_file.
    try:
        regions = process.GetMemoryRegions()
        num = regions.GetSize()
        region_info = lldb.SBMemoryRegionInfo()
        snapshot = []
        for i in range(num):
            ok = regions.GetMemoryRegionAtIndex(i, region_info)
            if not ok:
                continue
            start = int(region_info.GetRegionBase())
            end = int(region_info.GetRegionEnd())
            size = max(0, end - start)
            if size == 0:
                continue
            if not (region_info.IsReadable()):
                continue
            # read up to first 4096 bytes per region to keep snapshot small
            read_size = min(size, 4096)
            err = lldb.SBError()
            data = process.ReadMemory(start, read_size, err)
            if err.Success() and data:
                snapshot.append((start, read_size, data))
        _TEMP_STATE["pre_snapshots"][key] = snapshot
    except Exception as e:
        print("save_pre_snapshot error:", e)

def compute_diffs_between_snapshots(proc, key):
    """
    Compare the stored pre-snapshot with current memory to find regions that changed.
    Returns list of (base, offset_in_region, pre_bytes, post_bytes)
    """
    diffs = []
    snapshot = _TEMP_STATE["pre_snapshots"].get(key)
    if not snapshot:
        return diffs
    process = proc
    for (start, read_size, pre_data) in snapshot:
        err = lldb.SBError()
        post_data = process.ReadMemory(start, read_size, err)
        if not err.Success() or not post_data:
            continue
        # find differing ranges
        pre = pre_data
        post = post_data
        if pre == post:
            continue
        # compute offsets of differences
        cur_off = None
        cur_pre = bytearray()
        cur_post = bytearray()
        for i in range(min(len(pre), len(post))):
            if pre[i] != post[i]:
                if cur_off is None:
                    cur_off = i
                    cur_pre = bytearray()
                    cur_post = bytearray()
                cur_pre.append(pre[i])
                cur_post.append(post[i])
            else:
                if cur_off is not None:
                    diffs.append((start, cur_off, bytes(cur_pre), bytes(cur_post)))
                    cur_off = None
        # tail differences if any
        if cur_off is not None:
            diffs.append((start, cur_off, bytes(cur_pre), bytes(cur_post)))
    return diffs

def set_breakpoint_by_symbol(target, symbol_name, callback_fqn):
    bp = target.BreakpointCreateByName(symbol_name, None)
    if bp and bp.GetNumLocations() > 0:
        bp.SetScriptCallbackFunction(callback_fqn)
        return bp
    return None

def find_pattern_in_module(process, module_base, module, pattern_bytes):
    """
    Search for pattern_bytes in readable+executable regions starting from module_base.
    Simple byte-for-byte search (no masking).
    """
    regions = process.GetMemoryRegions()
    region_info = lldb.SBMemoryRegionInfo()
    num = regions.GetSize()
    for i in range(num):
        ok = regions.GetMemoryRegionAtIndex(i, region_info)
        if not ok:
            continue
        start = int(region_info.GetRegionBase())
        end = int(region_info.GetRegionEnd())
        size = max(0, end - start)
        if start < module_base:
            continue
        if not region_info.IsExecutable() or not region_info.IsReadable():
            continue
        if size < len(pattern_bytes):
            continue
        err = lldb.SBError()
        mem = process.ReadMemory(start, size, err)
        if not err.Success() or not mem:
            continue
        idx = mem.find(pattern_bytes)
        if idx != -1:
            return start + idx
    return None

def set_breakpoint_by_pattern(target, process, hex_pattern, callback_fqn):
    # convert hex string (with spaces) to bytes
    clean = hex_pattern.replace(" ", "").replace("\\x", "")
    try:
        pattern_bytes = bytes.fromhex(clean)
    except Exception:
        print("Invalid hex pattern")
        return None
    # Try to find in modules
    for j in range(target.GetNumModules()):
        mod = target.GetModuleAtIndex(j)
        base = get_module_base(target, mod)
        if base is None:
            continue
        found = find_pattern_in_module(process, base, mod, pattern_bytes)
        if found:
            bp = target.BreakpointCreateByAddress(found)
            if bp and bp.GetNumLocations() > 0:
                bp.SetScriptCallbackFunction(callback_fqn)
                return bp
    return None

def run_tracking(binary, attach_pid=None, library=None, mode="symbols", symbol=None, pattern=None, outdir="/data/dumps"):
    dbg = create_debugger()
    target = None
    if attach_pid:
        # attach to existing process
        print(f"[track] Attaching to PID {attach_pid}")
        target = dbg.CreateTarget(None)
        error = lldb.SBError()
        process = target.AttachToProcessWithID(lldb.SBListener(), int(attach_pid), error)
        if not error.Success():
            print("Attach failed:", error.GetCString())
            return
    else:
        # create target and launch
        print(f"[track] Creating target for binary {binary}")
        target = dbg.CreateTargetWithFileAndArch(binary, lldb.LLDB_ARCH_DEFAULT)
        if not target:
            print("Failed to create target")
            return
        # launch with no args: we expect the process to already be running in container normally
        launch_info = lldb.SBLaunchInfo([])
        launch_info.SetLaunchFlags(launch_info.GetLaunchFlags() & ~lldb.eLaunchFlagDisableASLR)
        process = target.Launch(launch_info, lldb.SBError())
        if not process or process.GetState() == lldb.eStateInvalid:
            print("Launch failed or returned invalid state")
            return

    print("[track] Process PID:", process.GetProcessID())

    # Add lldb dir to sys.path so callbacks can be imported via package
    script_dir = os.path.abspath(os.path.dirname(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Import callback module dynamically
    callback_module_name = f"{CALLBACK_PKG}.{library}_cb" if library else None
    callback_fqn_entry = None
    if callback_module_name:
        try:
            cb_mod = __import__(callback_module_name, fromlist=["*"])
            print(f"[track] Loaded callback module {callback_module_name}")
            # Expect callback function to be named 'kex_entry_callback'
            callback_fqn_entry = f"{callback_module_name}.kex_entry_callback"
        except Exception as e:
            print("Failed to import callback module:", e)
            traceback.print_exc()

    # Choose breakpoint creation method
    bp = None
    if mode == "symbols":
        sym = symbol or os.environ.get("LLDB_KEX_SYMBOL", "kex_derive_keys")
        print(f"[track] Setting breakpoint by symbol: {sym}")
        bp = set_breakpoint_by_symbol(target, sym, callback_fqn_entry)
        if not bp:
            print("[track] Failed to set symbol breakpoint; consider pattern mode or ensure debug symbols are present.")
    elif mode == "pattern":
        if not pattern:
            pattern = os.environ.get("LLDB_PATTERN_x86_64")
        if not pattern:
            print("Pattern not provided")
        else:
            print("[track] Using pattern mode")
            bp = set_breakpoint_by_pattern(target, process, pattern, callback_fqn_entry)
            if not bp:
                print("[track] Pattern not found in any module")

    if bp:
        print(f"[track] Breakpoint set: ID={bp.GetID()} locations={bp.GetNumLocations()}")
        # Continue process; callbacks will handle dumps and extraction
        process.Continue()
        # wait; keep the debugger loop until process exit
        while True:
            st = process.GetState()
            if st == lldb.eStateExited or st == lldb.eStateDisconnected or st == lldb.eStateDetached:
                print("[track] Process exited")
                break
            time.sleep(0.2)
    else:
        print("[track] No breakpoint active; exiting.")

def run(debugger, command, result, internal_dict):
    """
    LLDB command entry point: trackssh
    Syntax example:
      trackssh --binary /usr/sbin/sshd --library openssh --mode symbols --symbol kex_derive_keys --outdir /data/dumps
      trackssh --attach 1234 --library paramiko --mode symbols
    """
    try:
        parser = argparse.ArgumentParser(prog="trackssh", add_help=False)
        parser.add_argument("--binary", default=os.environ.get("LLDB_BINARY"))
        parser.add_argument("--attach", dest="attach_pid", type=int, default=os.environ.get("LLDB_ATTACH_PID"))
        parser.add_argument("--library", default=os.environ.get("LLDB_LIBRARY"))
        parser.add_argument("--mode", choices=("symbols", "pattern"), default=os.environ.get("LLDB_MODE", "symbols"))
        parser.add_argument("--symbol", default=os.environ.get("LLDB_KEX_SYMBOL", "kex_derive_keys"))
        parser.add_argument("--pattern", default=os.environ.get("LLDB_PATTERN_x86_64"))
        parser.add_argument("--outdir", default=os.environ.get("LLDB_OUTDIR", "/data/dumps"))
        args = parser.parse_args(command.split())
    except SystemExit:
        result.SetError("Invalid arguments to trackssh")
        return

    # call core
    try:
        run_tracking(binary=args.binary, attach_pid=args.attach_pid, library=args.library,
                     mode=args.mode, symbol=args.symbol, pattern=args.pattern, outdir=args.outdir)
    except Exception as e:
        print("run error:", e)
        traceback.print_exc()

def __lldb_init_module(debugger, internal_dict):
    # register LLDB command 'trackssh'
    if lldb:
        debugger.HandleCommand('command script add -f lldb.tracker_main.run trackssh')
        print("The 'trackssh' command has been installed. Use 'trackssh --help' for options.")
    else:
        print("Note: lldb module not available; import this file inside lldb to register command.")

if __name__ == "__main__":
    # standalone entry
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=False)
    parser.add_argument("--attach", dest="attach_pid", type=int, default=None)
    parser.add_argument("--library", required=True)
    parser.add_argument("--mode", choices=("symbols","pattern"), default="symbols")
    parser.add_argument("--symbol", default="kex_derive_keys")
    parser.add_argument("--pattern", default=None)
    parser.add_argument("--outdir", default="/data/dumps")
    args = parser.parse_args()
    run_tracking(binary=args.binary, attach_pid=args.attach_pid, library=args.library, mode=args.mode,
                 symbol=args.symbol, pattern=args.pattern, outdir=args.outdir)
