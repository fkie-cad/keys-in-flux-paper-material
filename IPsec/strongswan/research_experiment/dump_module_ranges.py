# dump_module_ranges.py
# - Adds 'dumpmod' LLDB command to dump only the memory belonging to a loaded .so (module)
# - Also provides a breakpoint-style callback 'dump_memory' that accepts extra_args keys:
#       file_path   -> output directory
#       kind        -> string tag in filenames (optional)
#       pattern     -> substring/regex for module match (required to do module-scoped dump)
#
# Usage (recommended):
#   (lldb) command script import /path/dump_module_ranges.py
#   (lldb) process attach -p 1234
#   (lldb) dumpmod --pattern libstrongswan --out /tmp/charon-dumps
#
# As breakpoint callback:
#   (lldb) command script import /path/dump_module_ranges.py
#   (lldb) br set -n some_function
#   (lldb) br command add -F dump_module_ranges.dump_memory -k file_path -v /tmp/charon-dumps -k pattern -v libstrongswan
#
import lldb, os, sys, re, json
from datetime import datetime

CHUNK = 64 * 1024  # 64 KiB chunked reads to tolerate partial unreadable pages


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def _read_chunks(process, start, size, fout):
    """Read [start, start+size) in chunks; skip unreadable pages gracefully."""
    total = 0
    addr = start
    end = start + size
    while addr < end:
        to_read = min(CHUNK, end - addr)
        err = lldb.SBError()
        data = process.ReadMemory(addr, to_read, err)
        if not err.Success() or data is None or len(data) == 0:
            # Skip to next page boundary (assume 4K)
            next_page = ((addr // 4096) + 1) * 4096
            if next_page <= addr:
                break
            addr = next_page
            continue
        fout.write(data)
        total += len(data)
        addr += len(data)
    return total


def _iter_matched_sections(target, pattern):
    """Yield (module_name, section_name, load_addr, size) for all sections of modules matching pattern."""
    flags = re.IGNORECASE
    for mod in target.module_iter():
        fs = mod.GetFileSpec()
        mdir = fs.GetDirectory() or ""
        mbase = fs.GetFilename() or ""
        mpath = (mdir + ("/" if mdir else "") + mbase)
        if not re.search(pattern, mpath, flags):
            continue
        # Walk loaded sections
        for sec in mod.section_iter():
            size = sec.GetByteSize()
            if size <= 0:
                continue
            load = sec.GetLoadAddress(target)
            if load == lldb.LLDB_INVALID_ADDRESS:
                continue
            sname = sec.GetName() or ""
            yield (mbase or mpath, sname, load, size)


def _dump_module(process, target, pattern, outdir, kind="module"):
    """Dump all loaded sections of modules matching 'pattern' to outdir. Returns manifest dict."""
    os.makedirs(outdir, exist_ok=True)
    ts = _ts()
    manifest = {
        "pid": process.GetProcessID(),
        "timestamp": ts,
        "pattern": pattern,
        "outdir": outdir,
        "chunks": []
    }
    count = 0
    for (mname, sname, addr, size) in _iter_matched_sections(target, pattern):
        fname = f"{ts}_{kind}_{mname}_{sname or 'no-secname'}_0x{addr:x}_len{size}.bin"
        # sanitize filename
        fname = re.sub(r"[^A-Za-z0-9._+-]", "_", fname)
        outpath = os.path.join(outdir, fname)
        with open(outpath, "wb") as f:
            written = _read_chunks(process, addr, size, f)
        manifest["chunks"].append({
            "module": mname,
            "section": sname,
            "start": f"0x{addr:x}",
            "size": size,
            "written": written,
            "outfile": outpath
        })
        print(f"[dumpmod] {mname}:{sname} @ 0x{addr:x} (+{size}) -> {outpath} ({written} bytes)")
        count += 1

    # Save manifest
    mpath = os.path.join(outdir, f"{ts}_{kind}_manifest.json")
    with open(mpath, "w") as mf:
        json.dump(manifest, mf, indent=2)
    print(f"[dumpmod] Manifest: {mpath} (sections dumped: {count})")
    return manifest


def dumpmod(debugger, command, exe_ctx, result, internal_dict):
    """
    LLDB command:
      dumpmod --pattern <regex-or-substring> --out <dir> [--kind <tag>]
    """
    import shlex
    args = shlex.split(command)
    pattern = None
    outdir = None
    kind = "module"

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--pattern", "-p") and i + 1 < len(args):
            pattern = args[i + 1]; i += 2
        elif a in ("--out", "-o") and i + 1 < len(args):
            outdir = args[i + 1]; i += 2
        elif a in ("--kind", "-k") and i + 1 < len(args):
            kind = args[i + 1]; i += 2
        else:
            i += 1

    if not pattern or not outdir:
        print("usage: dumpmod --pattern <regex> --out <dir> [--kind <tag>]", file=sys.stderr)
        return

    target = exe_ctx.target
    process = exe_ctx.process
    if not process or not process.IsValid() or process.GetState() != lldb.eStateStopped:
        print("[dumpmod] error: attach and stop the process first (e.g., 'process attach -p <PID>')", file=sys.stderr)
        return

    _dump_module(process, target, pattern, outdir, kind)


def dump_memory(frame, bp_loc, extra_args, internal_dict):
    """
    Breakpoint-style callback that reuses your function name.
    If 'pattern' is provided in extra_args, dumps only matching module sections.
    Keys (all optional except file_path when dumping):
      - file_path : output directory
      - kind      : tag in filenames (default 'module')
      - pattern   : regex/basename for module match; if missing, dumps WHOLE address space (legacy behavior)
    """
    import os
    print("=== Dump Memory Callback Invoked ===")
    sys.stdout.flush()
    hit_time = datetime.now()
    timestamp = hit_time.strftime("%Y%m%d_%H%M%S_%f")

    def _get_str(k, default=None):
        if not extra_args or not extra_args.IsValid():
            return default
        v = extra_args.GetValueForKey(k)
        if not v or not v.IsValid():
            return default
        s = v.GetStringValue(4096)
        return s if s else default

    outdir = _get_str("file_path", None)
    kind   = _get_str("kind", "module")
    pattern = _get_str("pattern", None)

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    if not outdir:
        print("[dump] error: 'file_path' (output dir) not provided in extra_args.")
        process.Continue()
        return False

    os.makedirs(outdir, exist_ok=True)

    if pattern:
        print(f"[dump] module-scoped dump; pattern='{pattern}', out='{outdir}'")
        _dump_module(process, target, pattern, outdir, kind)
        process.Continue()
        return False

    # Fallback: legacy whole-address-space dump (your original behavior)
    print("[dump] WARNING: no 'pattern' provided -> dumping ENTIRE address space.")
    dump_path = os.path.join(outdir, f"{timestamp}_{kind}.dump")

    try:
        regions = process.GetMemoryRegions()
        total_written = 0
        with open(dump_path, "wb") as out_f:
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()
            for i in range(num_regions):
                if not regions.GetMemoryRegionAtIndex(i, region_info):
                    continue
                start = int(region_info.GetRegionBase())
                end   = int(region_info.GetRegionEnd())
                size  = max(0, end - start)
                if size <= 0:
                    continue
                total_written += _read_chunks(process, start, size, out_f)
        print(f"[dump] Wrote {total_written} bytes to {dump_path}")
    except Exception as e:
        print(f"[dump] error: {e}")

    process.Continue()
    return False


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f dump_module_ranges.dumpmod dumpmod')
    print("[dumpmod] command registered. Use: dumpmod --pattern <regex> --out <dir>")
