# openssh_kex_lldb.py
# LLDB Python script to extract OpenSSH kex-derived keys, dump memory pre/post events,
# write Wireshark-compatible keylog lines, and save raw key/iv blobs.
#
# Usage (examples):
# 1) Attach to existing pid:
#    (lldb) command script import ./openssh_kex_lldb.py
#    (lldb) script main(attach_pid=12345)
#
# 2) Launch binary under debugger:
#    (lldb) command script import ./openssh_kex_lldb.py
#    (lldb) script main(binary="/usr/sbin/sshd", args=["-D","-p","2222"])
#
# Environment and optional inputs:
# - If you want pattern scanning for the function (fallback), provide:
#    os.environ["KEX_PATTERN_HEX"] = "f3 0f 1e fa ..."  # a space-separated hex pattern
# - The script writes to the current working directory:
#    - ssh_keys.log           (Wireshark-compatible keylog lines)
#    - ssh_key_mode0.bin      (raw key for mode 0)
#    - ssh_iv_mode0.bin
#    - ssh_key_mode1.bin
#    - ssh_iv_mode1.bin
#    - dumps/<timestamp>_pre_kex_derive.dump
#    - dumps/<timestamp>_post_kex_derive.dump
#
# Important: This script attempts to be conservative and auto-continue the process after dumps.
# If you want to pause instead of continuing, change process.Continue() calls accordingly.

import lldb, os, sys, threading, struct, time
from datetime import datetime

# ---------- Configuration ----------
KEYLOG_FILENAME = "ssh_keys.log"   # Wireshark-compatible keylog
DUMPS_DIR = "dumps"                # where memory dumps are written
CSV_PATH = "ssh_keys.csv"          # csv logger optional
SAVE_INTERVAL = 5                  # seconds for csv write timer (if used)
AUTO_EXIT_AFTER_CSV = False        # set True to exit LLDB after CSV flush

# Function names we will try to hook (symbol-first)
PRIMARY_KEX_FN = "kex_derive_keys"      # entry to hook
SECONDARY_NEWKEYS_FN = "ssh_set_newkeys" # may be called during KEX (useful)
# Candidate abort/terminate functions — we will set breakpoints if present
TERMINATION_CANDIDATES = ["packet_disconnect", "fatal", "cleanup", "session_close", "close_session"]

# Option: if no symbol for kex_derive_keys, you can set pattern via environment variable
# KEX_PATTERN_HEX = "f3 0f 1e fa ..."  # optional, space-separated hex bytes to search for
KEX_PATTERN_ENV = "KEX_PATTERN_HEX"

# Known cipher names used to validate sshenc candidates during structural scan
KNOWN_CIPHER_NAMES = [
    b"aes128-ctr", b"aes192-ctr", b"aes256-ctr",
    b"aes128-gcm@openssh.com", b"aes256-gcm@openssh.com",
    b"chacha20-poly1305@openssh.com",
    b"aes128-cbc", b"aes192-cbc", b"aes256-cbc",
    b"3des-cbc", b"none"
]

# ---------- Utility helpers ----------
def now_ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")

def debug(msg):
    print(f"[{now_ts()}] {msg}")
    sys.stdout.flush()

def save_bytes(filename, b):
    try:
        with open(filename, "wb") as f:
            f.write(b)
        debug(f"Saved {len(b)} bytes -> {filename}")
    except Exception as e:
        debug(f"Failed saving bytes to {filename}: {e}")

def append_keylog_line(cookie_hex, key_hex, key_type="SHARED_SECRET"):
    try:
        line = f"{cookie_hex} {key_type} {key_hex}\n"
        with open(KEYLOG_FILENAME, "a") as f:
            f.write(line)
        debug(f"Wrote keylog line for cookie {cookie_hex[:16]}... to {KEYLOG_FILENAME}")
    except Exception as e:
        debug(f"Failed to append keylog line: {e}")

# CSV logger (ported from TLS code you provided)
class CSVLogger:
    def __init__(self, file_path: str, save_interval: int = SAVE_INTERVAL, auto_exit: bool = AUTO_EXIT_AFTER_CSV):
        self.file_path = file_path
        self.save_interval = save_interval
        self.auto_exit = auto_exit
        self.header = "ID, timestamp, label, secret\n"
        self.csvData = []
        self.LOGFILE = None
        self.save_timer = None

    def init_log_file(self):
        os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
        file_exists = os.path.exists(self.file_path) and os.path.getsize(self.file_path) > 0
        try:
            mode = "a" if file_exists else "w"
            self.LOGFILE = open(self.file_path, mode)
            if not file_exists:
                self.LOGFILE.write(self.header)
                self.LOGFILE.flush()
        except Exception as e:
            debug(f"Failed to open CSV file {self.file_path}: {e}")
            self.LOGFILE = None

    def deinit_log_file(self):
        if self.LOGFILE:
            self.LOGFILE.close()
            self.LOGFILE = None

    def write_to_csv(self):
        self.init_log_file()
        max_id = 0
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    for line in f:
                        if line.strip():
                            parts = line.split(',')
                            if len(parts) > 0 and parts[0].strip().isdigit():
                                max_id = max(max_id, int(parts[0].strip()))
            except Exception as e:
                debug(f"Error reading existing CSV file: {e}")
        for data in self.csvData:
            try:
                self.LOGFILE.write(f"{max_id + 1}, {data}\n")
                max_id += 1
            except Exception as e:
                debug(f"Failed to write CSV row: {e}")
        if self.LOGFILE:
            self.LOGFILE.flush()
        self.deinit_log_file()
        self.csvData.clear()
        if self.save_timer:
            self.save_timer.cancel()
        if self.auto_exit:
            debug("Auto-exit after CSV write requested; terminating process.")
            os._exit(0)
        return True

    def queue_for_write(self, timestamp, label, secret):
        data_entry = f"{timestamp}, {label}, {secret}"
        self.csvData.append(data_entry)

    def start_save_timer(self):
        self.save_timer = threading.Timer(self.save_interval, self.write_to_csv)
        self.save_timer.daemon = True
        self.save_timer.start()

# Instantiate csv logger
csv_logger = CSVLogger(CSV_PATH)

# ---------- Memory dump functions (pre/post) ----------
def ensure_dumps_dir():
    os.makedirs(DUMPS_DIR, exist_ok=True)

def dump_full_memory_to(path, process):
    """Dump all readable memory regions to 'path'"""
    try:
        with open(path, "wb") as out_f:
            regions = process.GetMemoryRegions()
            region_info = lldb.SBMemoryRegionInfo()
            total_written = 0
            num_regions = regions.GetSize()
            for i in range(num_regions):
                ok = regions.GetMemoryRegionAtIndex(i, region_info)
                if not ok:
                    continue
                start = int(region_info.GetRegionBase())
                end = int(region_info.GetRegionEnd())
                size = max(0, end - start)
                if size == 0 or not region_info.IsReadable():
                    continue
                err = lldb.SBError()
                data = process.ReadMemory(start, size, err)
                if not err.Success() or not data:
                    # skip unreadable chunk
                    continue
                out_f.write(data)
                total_written += len(data)
        debug(f"[dump] Wrote {total_written} bytes to {path}")
        return True
    except Exception as e:
        debug(f"[dump] exception writing memory dump: {e}")
        return False

def dump_memory_onEntry(frame, bp_loc, extra_args, internal_dict):
    debug("== dump_memory_onEntry invoked ==")
    thread = frame.GetThread()
    process = thread.GetProcess()
    ensure_dumps_dir()
    ts = now_ts()
    kind = "kex_derive"  # default kind; extra_args may override
    try:
        if extra_args and extra_args.IsValid():
            val = extra_args.GetValueForKey("kind")
            if val and val.IsValid():
                s = val.GetStringValue(1024)
                if s:
                    kind = s
    except Exception:
        pass
    dump_path = os.path.join(DUMPS_DIR, f"{ts}_pre_{kind}.dump")
    dump_full_memory_to(dump_path, process)
    # continue process; return False instructs LLDB to continue if auto-continue is set up
    process.Continue()
    return False

def dump_memory_onExit(frame, bp_loc, extra_args, internal_dict):
    debug("== dump_memory_onExit invoked ==")
    thread = frame.GetThread()
    process = thread.GetProcess()
    ensure_dumps_dir()
    ts = now_ts()
    kind = "kex_derive"
    try:
        if extra_args and extra_args.IsValid():
            val = extra_args.GetValueForKey("kind")
            if val and val.IsValid():
                s = val.GetStringValue(1024)
                if s:
                    kind = s
    except Exception:
        pass
    dump_path = os.path.join(DUMPS_DIR, f"{ts}_post_{kind}.dump")
    dump_full_memory_to(dump_path, process)
    process.Continue()
    return False

# ---------- Pattern matching helpers (simple masked search) ----------
def create_mask_for_pattern(pattern_bytes):
    """create mask where relative addresses are marked as 0 when encountering common opcodes"""
    mask = bytearray([1] * len(pattern_bytes))
    i = 0
    L = len(pattern_bytes)
    while i < L:
        b = pattern_bytes[i]
        # CALL rel32 (0xE8) and JMP rel32 (0xE9) - mask following 4 bytes
        if b == 0xE8 or b == 0xE9:
            for j in range(i+1, min(i+5, L)):
                mask[j] = 0
            i += 5
        # conditional jumps 0x0f 0x8x rel32
        elif i + 1 < L and pattern_bytes[i] == 0x0f and (pattern_bytes[i+1] & 0xF0) == 0x80:
            for j in range(i+2, min(i+6, L)):
                mask[j] = 0
            i += 6
        else:
            i += 1
    return mask

def find_masked(mem, pattern, mask):
    plen = len(pattern)
    mlen = len(mem)
    if mlen < plen:
        return -1
    for off in range(0, mlen - plen + 1):
        ok = True
        for i in range(plen):
            if mask[i] != 0 and mem[off + i] != pattern[i]:
                ok = False
                break
        if ok:
            return off
    return -1

def pattern_scan_process(process, pattern_hex):
    """Scan readable executable regions for byte pattern (with mask) and return first absolute addr or None."""
    clean = pattern_hex.replace(" ", "").replace("\n", "")
    pattern = bytes.fromhex(clean)
    mask = create_mask_for_pattern(pattern)
    regs = process.GetMemoryRegions()
    info = lldb.SBMemoryRegionInfo()
    for i in range(regs.GetSize()):
        ok = regs.GetMemoryRegionAtIndex(i, info)
        if not ok:
            continue
        if not info.IsReadable() or not info.IsExecutable():
            continue
        start = info.GetRegionBase()
        end = info.GetRegionEnd()
        size = end - start
        if size < len(pattern):
            continue
        # read region in chunks to avoid huge allocations
        CHUNK = 1024 * 1024
        offset = 0
        err = lldb.SBError()
        while offset < size:
            rsize = min(CHUNK, size - offset)
            mem = process.ReadMemory(start + offset, rsize, err)
            if err.Fail() or not mem:
                break
            found = find_masked(mem, pattern, mask)
            if found != -1:
                return start + offset + found
            # step with some overlap
            offset += rsize - len(pattern) - 1 if rsize > (len(pattern) + 1) else rsize
    return None

# ---------- Key extraction helpers ----------
def read_pointer(process, addr):
    """Read pointer-sized value (unsigned) from process memory"""
    target = process.GetTarget()
    ptr_size = target.GetAddressByteSize()
    err = lldb.SBError()
    data = process.ReadMemory(addr, ptr_size, err)
    if err.Fail() or not data:
        return 0
    if ptr_size == 8:
        return struct.unpack("<Q", data)[0]
    else:
        return struct.unpack("<I", data)[0]

def read_uint32(process, addr):
    err = lldb.SBError()
    data = process.ReadMemory(addr, 4, err)
    if err.Fail() or not data or len(data) < 4:
        return 0
    return struct.unpack("<I", data)[0]

def read_bytes(process, addr, length):
    err = lldb.SBError()
    data = process.ReadMemory(addr, length, err)
    if err.Fail() or data is None:
        return None
    return data

def try_symbolic_extract(frame, mode_hint=None):
    """
    Attempt to extract keys using debug symbols & expression evaluation.
    This requires OpenSSH debug symbols (types).
    Returns dict with cookie_hex, mode -> (key, iv) on success (may be partial).
    """
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    arch = target.GetTriple()
    debug("Attempting symbolic extraction via expression evaluator...")

    # Get the first argument for kex_derive_keys: Kex *kex
    try:
        # Get argument register depending on arch
        if "x86_64" in arch:
            arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
        elif "arm64" in arch or "aarch64" in arch:
            arg0 = frame.FindRegister("x0").GetValueAsUnsigned()
        else:
            arg0 = None
    except Exception:
        arg0 = None

    if not arg0:
        debug("Could not obtain Kex* pointer via registers for symbolic extraction.")
        return None

    # Try an LLDB expression to fetch newkeys pointers via symbol types if available.
    # Many OpenSSH versions: Kex struct contains 'newkeys' or has kex_get_newkeys() helper in source.
    # We'll attempt a few expression forms (best-effort) and catch exceptions.

    expr_opts = lldb.SBExpressionOptions()
    res = {}

    candidate_expressions = [
        # Try to get newkeys pointer array from kex (C field name guess)
        "((struct Kex*){kex})->newkeys[0]".format(kex=arg0),
        "((struct Kex*){kex})->newkeys[1]".format(kex=arg0),
        # fallback: if Kex contains 'ssh' pointer that we can navigate to ssh->newkeys
        "((struct Kex*){kex})->ssh".format(kex=arg0),
    ]
    try:
        # Try reading cookie from kex->hash? Many implementations include 'kex->cookie' not universal.
        cookie_expr = "((struct Kex*){kex})->hash".format(kex=arg0)
        cookie_val = frame.EvaluateExpression(cookie_expr, expr_opts)
        if cookie_val.IsValid():
            # get pointer and length if available; best-effort to read 16 bytes
            cookie_ptr = cookie_val.GetValueAsUnsigned()
            if cookie_ptr:
                cookie_bytes = read_bytes(process, cookie_ptr, 16)
                if cookie_bytes:
                    res['cookie_hex'] = cookie_bytes.hex()
    except Exception:
        pass

    # Try to fetch newkeys[mode]->enc fields
    for mode in (0,1):
        try:
            # Try a couple expression templates
            exprs = [
                f"((struct Kex*){arg0})->newkeys[{mode}]->enc",
                f"((struct Kex*){arg0})->newkeys[{mode}]->encoder",
                f"((struct Kex*){arg0})->newkeys[{mode}]"  # fallback pointer to newkeys struct
            ]
            found = False
            for e in exprs:
                val = frame.EvaluateExpression(e, expr_opts)
                if not val.IsValid() or val.GetError().Fail():
                    continue
                addr = val.GetValueAsUnsigned()
                if addr:
                    # Try read fields expected in sshenc layout
                    # offsets guessed: name ptr at +0, enabled @ +16, key_len @ +20, iv_len @ +24, key ptr @ +32, iv ptr @ +40
                    enc_addr = addr
                    key_len = read_uint32(process, enc_addr + 20)
                    iv_len = read_uint32(process, enc_addr + 24)
                    key_ptr = read_pointer(process, enc_addr + 32)
                    iv_ptr  = read_pointer(process, enc_addr + 40)
                    if key_ptr and key_len:
                        k = read_bytes(process, key_ptr, key_len)
                        iv = read_bytes(process, iv_ptr, iv_len) if iv_ptr and iv_len else b""
                        res.setdefault('modes', {})[mode] = (k, iv)
                        found = True
                        break
            if not found:
                debug(f"Symbolic: could not find newkeys->enc for mode {mode} (fields may differ by version).")
        except Exception as e:
            debug(f"Symbolic extraction exception for mode {mode}: {e}")
    return res if res else None

def scan_for_sshenc_and_extract(process):
    """
    Fallback: scan memory for sshenc-like structures (pattern-based)
    Return dict with modes -> (key,iv) and optionally cookie_hex if found
    """
    debug("Running fallback structural scan for sshenc-like structures...")
    target = process.GetTarget()
    ptr_size = target.GetAddressByteSize()

    # The sshenc struct layout assumptions (best-effort):
    # offset 0: char *name  (ptr)
    # offset 16: enabled (uint32)
    # offset 20: key_len (uint32)
    # offset 24: iv_len  (uint32)
    # offset 28: block_size (uint32)
    # offset 32: key_ptr  (ptr)
    # offset 32+ptr_size: iv_ptr
    # This layout is used elsewhere; we search for occurrences of (enabled=1,key_len in plausible set)
    plausible_keylens = {16, 24, 32}
    plausible_ivlens = {8, 12, 16}
    # iterate memory regions
    regs = process.GetMemoryRegions()
    info = lldb.SBMemoryRegionInfo()
    sshenc_addrs = []
    for i in range(regs.GetSize()):
        ok = regs.GetMemoryRegionAtIndex(i, info)
        if not ok:
            continue
        if not info.IsReadable():
            continue
        start = info.GetRegionBase()
        end = info.GetRegionEnd()
        size = end - start
        # scan in 8/16 aligned strides
        stride = ptr_size
        offset = 0
        err = lldb.SBError()
        CHUNK = 1024*512
        while offset < size:
            to_read = min(CHUNK, size - offset)
            mem = process.ReadMemory(start + offset, to_read, err)
            if err.Fail() or not mem:
                break
            # scan each alignment
            for off in range(0, len(mem) - 64, stride):
                abs_addr = start + offset + off
                # read candidate name pointer
                name_ptr = None
                try:
                    if ptr_size == 8:
                        name_ptr = struct.unpack_from("<Q", mem, off)[0]
                    else:
                        name_ptr = struct.unpack_from("<I", mem, off)[0]
                except Exception:
                    continue
                # quick sanity: name_ptr should point into readable region and contain ascii
                if name_ptr == 0:
                    continue
                name_bytes = process.ReadMemory(name_ptr, 32, err)
                if err.Fail() or not name_bytes:
                    continue
                name_str = name_bytes.split(b'\x00')[0]
                if not any(name_str.startswith(x) for x in KNOWN_CIPHER_NAMES):
                    continue
                # read enabled/key_len/iv_len
                try:
                    # offsets relative to enc base
                    enabled = struct.unpack_from("<I", mem, off + 16)[0]
                    key_len = struct.unpack_from("<I", mem, off + 20)[0]
                    iv_len  = struct.unpack_from("<I", mem, off + 24)[0]
                except Exception:
                    continue
                if enabled != 1 or key_len not in plausible_keylens or iv_len not in plausible_ivlens:
                    continue
                # read pointers for key/iv
                key_ptr_off = off + 32
                iv_ptr_off = key_ptr_off + ptr_size
                try:
                    if ptr_size == 8:
                        key_ptr = struct.unpack_from("<Q", mem, key_ptr_off)[0]
                        iv_ptr  = struct.unpack_from("<Q", mem, iv_ptr_off)[0]
                    else:
                        key_ptr = struct.unpack_from("<I", mem, key_ptr_off)[0]
                        iv_ptr  = struct.unpack_from("<I", mem, iv_ptr_off)[0]
                except Exception:
                    continue
                if key_ptr == 0 or key_len == 0:
                    continue
                # read key bytes
                key_bytes = process.ReadMemory(key_ptr, key_len, err)
                if err.Fail() or not key_bytes:
                    continue
                iv_bytes = None
                if iv_ptr and iv_len:
                    iv_bytes = process.ReadMemory(iv_ptr, iv_len, err)
                # candidate found
                debug(f"Found sshenc candidate at 0x{abs_addr:x} cipher={name_str.decode(errors='ignore')}, key_len={key_len}, iv_len={iv_len}")
                sshenc_addrs.append((abs_addr, name_str, key_bytes, iv_bytes))
            offset += to_read - 64
    # Now choose up to two most-likely entries (lowest addresses heuristic)
    sshenc_addrs = sshenc_addrs[:4]  # limit
    modes = {}
    for idx, (addr, name, key, iv) in enumerate(sshenc_addrs):
        # map to mode 0/1 by index as heuristic (best-effort)
        mode = idx  # 0, 1, ...
        modes[mode] = (key, iv or b"")
    result = {'modes': modes}
    # cookie extraction optional (scan for SSH_MSG_KEXINIT cookie pattern, 16 bytes random near KEX exchange)
    # Heuristic: search for 16-byte block that looks random near kex structures; complicated -> omitted here
    return result

# ---------- Breakpoint callbacks ----------
def kex_entry_callback(frame, bp_loc, user_data):
    """
    Called when kex_derive_keys is entered. We will:
     - do pre-kex memory dump,
     - set a one-shot breakpoint at return address to do post-kex dump and extraction.
    """
    debug("kex_derive_keys entry breakpoint hit.")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    arch = target.GetTriple().lower()

    # run pre-dump
    try:
        sd = lldb.SBStructuredData()
        sd.SetFromDictionary({"file_path": os.path.join(DUMPS_DIR, "kex"), "kind": "kex_derive"})
    except Exception:
        sd = None

    # do a synchronous pre dump using the same logic as your TLS script
    dump_memory_onEntry(frame, bp_loc, sd, None)

    # find return address & set one-shot breakpoint for post
    try:
        if "x86_64" in arch:
            rsp_reg = frame.FindRegister("rsp")
            if rsp_reg and rsp_reg.IsValid():
                rsp = int(rsp_reg.GetValue(), 0)
                # return address lives at [rsp]
                retaddr = read_pointer(process, rsp)
            else:
                retaddr = None
        elif "arm64" in arch or "aarch64" in arch:
            # return address is in x30 (lr) at entry
            lr = frame.FindRegister("lr") or frame.FindRegister("x30")
            if lr and lr.IsValid() and lr.GetValue():
                retaddr = int(lr.GetValue(), 0)
            else:
                # fallback: read from stack
                sp = int(frame.FindRegister("sp").GetValue(), 0)
                retaddr = read_pointer(process, sp)
        else:
            retaddr = None
    except Exception as e:
        debug(f"Failed to determine return address: {e}")
        retaddr = None

    if retaddr and retaddr != 0:
        bp = target.BreakpointCreateByAddress(retaddr)
        if bp and bp.GetNumLocations() > 0:
            bp.SetOneShot(True)
            debug(f"Set one-shot post-kex breakpoint at 0x{retaddr:x}")
            # the callback for post will perform post-dump and extraction
            bp.SetScriptCallbackFunction(__name__ + ".kex_exit_callback")
        else:
            debug("Failed to set post-kex breakpoint by address (no locations).")
    else:
        debug("Could not compute return address; post-kex one-shot breakpoint not set. We will rely on ssh_set_newkeys symbol breakpoint (if present).")

    # Continue execution immediately
    process.Continue()
    return False

def kex_exit_callback(frame, bp_loc, user_data):
    """
    One-shot callback triggered at kex return address. Do post-dump and try to extract keys.
    """
    debug("kex_derive_keys exit (one-shot) breakpoint hit.")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    # perform post-dump
    try:
        sd = lldb.SBStructuredData()
        sd.SetFromDictionary({"file_path": os.path.join(DUMPS_DIR, "kex"), "kind": "kex_derive"})
    except Exception:
        sd = None
    dump_memory_onExit(frame, bp_loc, sd, None)

    # Attempt to extract keys (symbolic preferred)
    out = None
    try:
        out = try_symbolic_extract(frame)
    except Exception as e:
        debug(f"Symbolic extraction raised: {e}")

    if not out:
        # fallback structural scan of the whole process memory
        out = scan_for_sshenc_and_extract(process)

    # If we have keys, write them and produce keylog line
    if out and 'modes' in out:
        modes = out['modes']
        cookie_hex = out.get('cookie_hex', None)
        # If cookie is missing, we try to find SSH_MSG_KEXINIT cookie elsewhere later, but for now warn and add CSV message
        if not cookie_hex:
            debug("Cookie not found automatically; you must add it manually to keylog lines or extract it separately.")
        for mode, (key, iv) in modes.items():
            if not key:
                continue
            save_bytes(f"ssh_key_mode{mode}.bin", key)
            if iv:
                save_bytes(f"ssh_iv_mode{mode}.bin", iv)
            # prepare keylog: if cookie found -> write cookie + SHARED_SECRET + hex(key)
            if cookie_hex:
                append_keylog_line(cookie_hex, key.hex(), "SHARED_SECRET")
            else:
                # fallback: write a hint line to csv logger for manual cookie insertion
                ts = now_ts()
                label = f"mode{mode}"
                secret_hex = key.hex()
                csv_logger.queue_for_write(ts, label, secret_hex)
    else:
        debug("No keys found after kex.")

    # continue process
    process.Continue()
    return False

def ssh_set_newkeys_callback(frame, bp_loc, user_data):
    """Callback for ssh_set_newkeys symbol — helpful as it is invoked after newkeys are activated."""
    debug("ssh_set_newkeys breakpoint hit.")
    # do pre-dump? do post-dump? we'll do both around the call similarly but simpler: do a post-dump & extraction
    process = frame.GetThread().GetProcess()

    # perform a dump after ssh_set_newkeys (it runs when newkeys activated)
    try:
        sd = lldb.SBStructuredData()
        sd.SetFromDictionary({"file_path": os.path.join(DUMPS_DIR, "ssh_set_newkeys"), "kind": "ssh_set_newkeys"})
    except Exception:
        sd = None
    dump_memory_onExit(frame, bp_loc, sd, None)

    # Attempt to symbolically extract keys (best chance now)
    out = try_symbolic_extract(frame)
    if not out:
        out = scan_for_sshenc_and_extract(process)

    if out and 'modes' in out:
        cookie_hex = out.get('cookie_hex', None)
        for mode, (key, iv) in out['modes'].items():
            if not key:
                continue
            save_bytes(f"ssh_key_mode{mode}.bin", key)
            if iv:
                save_bytes(f"ssh_iv_mode{mode}.bin", iv)
            if cookie_hex:
                append_keylog_line(cookie_hex, key.hex(), "SHARED_SECRET")
            else:
                ts = now_ts()
                csv_logger.queue_for_write(ts, f"ssh_set_newkeys_mode{mode}", key.hex())
    else:
        debug("ssh_set_newkeys: no keys found.")

    process.Continue()
    return False

def termination_cb(frame, bp_loc, user_data):
    """Generic callback for termination/abort candidate functions to dump memory."""
    debug("Termination/abort breakpoint hit; producing memory dump.")
    try:
        sd = lldb.SBStructuredData()
        sd.SetFromDictionary({"file_path": os.path.join(DUMPS_DIR, "termination"), "kind": "termination"})
    except Exception:
        sd = None
    dump_memory_onEntry(frame, bp_loc, sd, None)
    # after dump, continue
    return False

# ---------- Main orchestration ----------
def install_breakpoints(target, process):
    """Install breakpoints: primary kex function (symbol or pattern), ssh_set_newkeys if present, termination candidates."""
    dbg = target.GetDebugger()
    bp_count = 0
    # Try symbol first
    sym_kex = target.FindFunctions(PRIMARY_KEX_FN, lldb.eFunctionNameTypeAuto)
    if sym_kex.GetSize() > 0:
        debug(f"Symbolic function '{PRIMARY_KEX_FN}' found. Installing entry breakpoint.")
        bp = target.BreakpointCreateByName(PRIMARY_KEX_FN)
        bp.SetScriptCallbackFunction(__name__ + ".kex_entry_callback")
        bp.SetOneShot(False)
        bp.SetAutoContinue(True)
        bp_count += 1
    else:
        # pattern fallback via env
        pat = os.environ.get(KEX_PATTERN_ENV, None)
        if pat:
            debug(f"No symbol for {PRIMARY_KEX_FN}. Using pattern from {KEX_PATTERN_ENV}.")
            addr = pattern_scan_process(process, pat)
            if addr:
                bpa = target.BreakpointCreateByAddress(addr)
                bpa.SetScriptCallbackFunction(__name__ + ".kex_entry_callback")
                bpa.SetOneShot(False)
                bpa.SetAutoContinue(True)
                debug(f"Pattern-based breakpoint set at 0x{addr:x}")
                bp_count += 1
            else:
                debug("Pattern scan did not find the function address.")
        else:
            debug(f"No symbol for {PRIMARY_KEX_FN} & no pattern provided; primary kex hook not installed.")

    # ssh_set_newkeys
    sym_newkeys = target.FindFunctions(SECONDARY_NEWKEYS_FN, lldb.eFunctionNameTypeAuto)
    if sym_newkeys.GetSize() > 0:
        bp2 = target.BreakpointCreateByName(SECONDARY_NEWKEYS_FN)
        bp2.SetScriptCallbackFunction(__name__ + ".ssh_set_newkeys_callback")
        bp2.SetOneShot(False)
        bp2.SetAutoContinue(True)
        bp_count += 1
        debug(f"Installed symbolic breakpoint on {SECONDARY_NEWKEYS_FN}")

    # termination candidate hooks (best-effort)
    for fn in TERMINATION_CANDIDATES:
        syms = target.FindFunctions(fn, lldb.eFunctionNameTypeAuto)
        if syms.GetSize() > 0:
            bp = target.BreakpointCreateByName(fn)
            bp.SetScriptCallbackFunction(__name__ + ".termination_cb")
            bp.SetOneShot(False)
            bp.SetAutoContinue(True)
            debug(f"Installed termination breakpoint on {fn}")
            bp_count += 1

    if bp_count == 0:
        debug("Warning: no breakpoints installed. Check symbols or provide patterns.")
    else:
        debug(f"Installed {bp_count} breakpoints (symbol/pattern mix).")

def main(attach_pid=None, binary=None, args=None, env=None, timeout=0):
    """
    Entrypoint to set up LLDB target and breakpoints.
    - attach_pid: if provided, attach to running process
    - binary + args: if provided, launch the binary under LLDB
    """
    debugger = lldb.debugger
    if debugger is None:
        debug("Error: This script must be run inside LLDB (lldb -s script.py or command script import).")
        return

    debugger.SetAsync(False)
    target = None
    process = None

    if attach_pid:
        debug(f"Attaching to PID {attach_pid} ...")
        error = lldb.SBError()
        process = debugger.GetSelectedTarget().AttachToProcessWithID(lldb.SBListener(), int(attach_pid), error)
        if error.Fail():
            debug(f"Failed to attach: {error.GetCString()}")
            return
        target = process.GetTarget()
    elif binary:
        arch = lldb.LLDB_ARCH_DEFAULT
        debug(f"Creating target for binary: {binary}")
        target = debugger.CreateTargetWithFileAndArch(binary, arch)
        if not target:
            debug(f"Failed to create target for binary: {binary}")
            return
        launch_info = lldb.SBLaunchInfo(args or [])
        if env:
            # format env entries as KEY=VALUE
            env_entries = [f"{k}={v}" for k, v in (env.items() if isinstance(env, dict) else [])]
            launch_info.SetEnvironmentEntries(env_entries, True)
        # Keep ASLR as default (not disabling)
        err = lldb.SBError()
        process = target.Launch(launch_info, err)
        if err.Fail():
            debug(f"Failed to launch process: {err.GetCString()}")
            return
        debug(f"Launched process with PID {process.GetProcessID()}")
    else:
        # try to use current selected target & process
        target = debugger.GetSelectedTarget()
        if not target:
            debug("No target found in LLDB. Provide attach_pid or binary.")
            return
        process = target.GetProcess()
        if not process or not process.IsValid():
            debug("No process running for current target. Provide attach_pid or binary.")
            return

    # start CSV timer (to flush queued keys if cookie missing)
    csv_logger.start_save_timer()

    # Install breakpoints on target based on symbols/patterns
    install_breakpoints(target, process)
    debug("Breakpoint installation finished. Continuing process to let breakpoints hit.")

    # ensure process continues to run
    try:
        if process.GetState() != lldb.eStateRunning:
            process.Continue()
    except Exception:
        pass

# Expose functions to LLDB 'script' command
def __lldb_init_module(debugger, internal_dict):
    # This will be called when script is imported in LLDB
    print("OpenSSH KEX LLDB helper imported. Call main(attach_pid=PID) or main(binary='/usr/sbin/sshd', args=['-D']).")

# allow users to call main() via 'script' command in lldb
if __name__ == "__main__":
    # allow running module directly for testing (not typical)
    main()
