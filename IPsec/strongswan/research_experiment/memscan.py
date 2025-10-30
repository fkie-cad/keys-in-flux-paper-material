# memscan.py — search bytes in the current process memory
#
# Usage:
#   (lldb) command script import /path/to/memscan.py
#   (lldb) process attach -p <PID>          # or have the process already stopped
#   (lldb) memscan --hex "de ad be ef"
#   (lldb) memscan --hex "DEADBEEF"
#   (lldb) memscan --hex "\\xDE\\xAD\\xBE\\xEF"
#   (lldb) memscan --ascii "client_random"
#   (lldb) memscan --hex "00 01 02" --max 200
#   (lldb) memscan --ascii "foobar" --require r --exclude x
#
# Notes:
# - Scans only readable regions.
# - You can require/exclude region perms: r/w/x (e.g., --require rx, --exclude w).
# - Prints Stage 1 (compact hits) then Stage 2 (region + module details).
#
import lldb, os, sys, re
from datetime import datetime

CHUNK = 1024 * 1024   # 1 MiB read chunks
PAGE  = 4096

def _hexdump16(b: bytes) -> str:
    b = b[:16]
    return " ".join(f"{x:02x}" for x in b)

def _parse_hex(s: str) -> bytes:
    """
    Accepts 'de ad be ef', 'DEADBEEF', or '\\xDE\\xAD\\xBE\\xEF'
    """
    s = s.strip()
    if "\\x" in s.lower():
        # remove \x and any spaces
        s = s.replace("\\x", "")
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s) % 2 != 0:
        raise ValueError("hex string has odd length")
    return bytes.fromhex(s)

def _filter_region(perms: str, require: str, exclude: str) -> bool:
    if require:
        for ch in require:
            if ch not in perms:
                return False
    if exclude:
        for ch in exclude:
            if ch in perms:
                return False
    return True

def _load_proc_maps(pid: int):
    maps = []
    path = f"/proc/{pid}/maps"
    try:
        with open(path, "r") as f:
            for line in f:
                # 00400000-0040b000 r-xp 00000000 fc:01 123456 /path/bin
                parts = line.strip().split(None, 5)
                if len(parts) < 5:
                    continue
                addrs, perms, offset, dev, inode = parts[:5]
                pathname = parts[5] if len(parts) >= 6 else ""
                start_s, end_s = addrs.split("-")
                start = int(start_s, 16)
                end   = int(end_s, 16)
                maps.append((start, end, perms, pathname))
    except Exception:
        pass
    return maps

def _find_proc_map(maps, addr: int):
    # maps are usually ordered
    lo, hi = 0, len(maps) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e, perms, path = maps[mid]
        if addr < s:
            hi = mid - 1
        elif addr >= e:
            lo = mid + 1
        else:
            return (s, e, perms, path)
    # linear fallback (just in case)
    for s, e, perms, path in maps:
        if s <= addr < e:
            return (s, e, perms, path)
    return None

def _scan_region(process, start, end, needle: bytes, max_hits, hits_out):
    # chunked scan with overlap to detect cross-boundary matches
    plen = len(needle)
    if plen == 0:
        return
    cur = start
    tail = b''
    while cur < end and (max_hits is None or len(hits_out) < max_hits):
        to_read = min(CHUNK, end - cur)
        err = lldb.SBError()
        data = process.ReadMemory(cur, to_read, err)
        if not err.Success() or not data:
            # jump to next page boundary on failure
            next_page = ((cur // PAGE) + 1) * PAGE
            if next_page <= cur:
                break
            cur = next_page
            tail = b''
            continue

        buf = tail + data
        base_addr = cur - len(tail)

        # search all occurrences in buf
        idx = buf.find(needle)
        while idx != -1 and (max_hits is None or len(hits_out) < max_hits):
            match_addr = base_addr + idx
            hits_out.append(match_addr)
            idx = buf.find(needle, idx + 1)

        # keep last plen-1 bytes for overlap
        tail = buf[-(plen - 1):] if plen > 1 else b''
        cur += to_read

def memscan(debugger, command, exe_ctx, result, internal_dict):
    """
    memscan --hex "<hex-bytes>" | --ascii "<text>" [--max N] [--require r/x/w] [--exclude r/x/w]
    """
    import shlex
    args = shlex.split(command)
    hex_str = None
    ascii_str = None
    max_hits = None
    require = ""
    exclude = ""

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--hex" and i + 1 < len(args):
            hex_str = args[i + 1]; i += 2
        elif a == "--ascii" and i + 1 < len(args):
            ascii_str = args[i + 1]; i += 2
        elif a == "--max" and i + 1 < len(args):
            try:
                max_hits = int(args[i + 1])
            except:
                max_hits = None
            i += 2
        elif a == "--require" and i + 1 < len(args):
            require = args[i + 1]; i += 2
        elif a == "--exclude" and i + 1 < len(args):
            exclude = args[i + 1]; i += 2
        else:
            i += 1

    if not hex_str and not ascii_str:
        print("usage: memscan --hex \"de ad be ef\" | --ascii \"text\" [--max N] [--require rxw] [--exclude w]", file=sys.stderr)
        return

    # Build the needle
    try:
        if hex_str:
            needle = _parse_hex(hex_str)
        else:
            needle = ascii_str.encode("utf-8", "ignore")
    except Exception as e:
        print(f"[memscan] error parsing input: {e}", file=sys.stderr)
        return

    target  = exe_ctx.target
    process = exe_ctx.process
    if not process or not process.IsValid():
        print("[memscan] error: no valid process. Attach and stop it first.", file=sys.stderr)
        return
    if process.GetState() != lldb.eStateStopped:
        print("[memscan] note: process is not stopped; attempting to scan anyway (may fail).")

    regions = process.GetMemoryRegions()
    nregs = regions.GetSize()
    if nregs == 0:
        print("[memscan] no memory regions available.", file=sys.stderr)
        return

    pid = process.GetProcessID()
    proc_maps = _load_proc_maps(pid)  # optional; may be empty if inaccessible

    # Collect readable regions (and apply perms filter)
    reg_infos = []
    reg = lldb.SBMemoryRegionInfo()
    for i in range(nregs):
        if not regions.GetMemoryRegionAtIndex(i, reg):
            continue
        start = int(reg.GetRegionBase())
        end   = int(reg.GetRegionEnd())
        if start >= end:
            continue
        perms = ""
        if reg.IsReadable():   perms += "r"
        if reg.IsWritable():   perms += "w"
        if reg.IsExecutable(): perms += "x"
        if not reg.IsReadable():
            continue
        if not _filter_region(perms, require, exclude):
            continue
        reg_infos.append((start, end, perms))

    # Stage 1: scan + compact print
    hits = []
    for (start, end, perms) in reg_infos:
        _scan_region(process, start, end, needle, max_hits, hits)
        if max_hits is not None and len(hits) >= max_hits:
            break

    if not hits:
        print("[memscan] no matches.")
        return

    print("=== Stage 1: Matches ===")
    for idx, addr in enumerate(hits, 1):
        err = lldb.SBError()
        # Read at least 16 bytes to preview (best-effort)
        data = process.ReadMemory(addr, 16, err)
        preview = _hexdump16(data if err.Success() and data else b'')
        print(f"#{idx:<4}  0x{addr:016x}  {preview}")

    # Stage 2: region + module resolution
    print("\n=== Stage 2: Region / Module details ===")
    for idx, addr in enumerate(hits, 1):
        # Region via /proc/pid/maps (best source for path)
        reg_line = _find_proc_map(proc_maps, addr) if proc_maps else None
        if reg_line:
            rs, re, rperms, rpath = reg_line
            reg_desc = f"[0x{rs:x}-0x{re:x}) perms={rperms} path={rpath or '(anon)'}"
        else:
            # fallback: find from the SB regions we already collected
            match = None
            for (s, e, p) in reg_infos:
                if s <= addr < e:
                    match = (s, e, p); break
            if match:
                s, e, p = match
                reg_desc = f"[0x{s:x}-0x{e:x}) perms={p} path=?"
            else:
                reg_desc = "(region unknown)"

        # Module / section resolution
        saddr = lldb.SBAddress(addr, target)
        mod   = saddr.GetModule()
        mod_desc = "module=?"
        sect_desc = ""
        offs_desc = ""
        if mod and mod.IsValid():
            fs = mod.GetFileSpec()
            mname = fs.GetFilename() or (fs.GetDirectory() + "/" + fs.GetFilename())
            sect = saddr.GetSection()
            if sect and sect.IsValid():
                sect_name = sect.GetName() or ""
                sect_base = sect.GetLoadAddress(target)
                if sect_base != lldb.LLDB_INVALID_ADDRESS:
                    offs = addr - sect_base
                    offs_desc = f" +0x{offs:x}"
                sect_desc = f" .{sect_name}" if sect_name else ""
            mod_desc = f"{mname}{sect_desc}{offs_desc}"

        print(f"#{idx:<4}  0x{addr:016x}")
        print(f"      region: {reg_desc}")
        print(f"      module: {mod_desc}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f memscan.memscan memscan')
    print("[memscan] command registered. Try: memscan --hex \"de ad be ef\"")