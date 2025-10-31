#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dropbear LLDB callbacks (r16) – fork-aware, first-hit watchpoints, no re-arm.

What this does:
- Attach to the master process, follow the FIRST fork (session worker).
- Install watchpoints ONLY in the session child, at/after switch_keys().
- Delete a watchpoint on the FIRST overwrite (no re-enable).
- Avoid following the SECOND fork (chansession → user shell/command).
- Auto-continue libc memwipe 'trace' stops (configurable).
- Auto-continue after import so you don’t need to press 'c'.

Architectures: AArch64 + x86-64
"""

import lldb
import os, sys, time, struct

__version__ = "dropbear-cb 2025.10.22-r16"
_modname    = __name__

# ───── Config via environment ────────────────────────────────────────────
_ENABLE_WP            = os.getenv("LLDB_ENABLE_WATCHPOINTS", "1").lower() in ("1","true","yes")
_AUTOCONT_ALWAYS      = os.getenv("LLDB_AUTOCONT_ALWAYS", "1").lower() in ("1","true","yes")  # default: ALWAYS
_TRACE_SQUELCH_SECS   = float(os.getenv("LLDB_TRACE_SQUELCH_SECS", "0.35"))
_AUTOCONT_ON_ATTACH   = os.getenv("LLDB_AUTOCONT_ON_ATTACH", "1").lower() in ("1","true","yes")
_MBURN_ENABLED        = os.getenv("LLDB_MBURN_HOOK", "0").lower() in ("1","true","yes")       # default: off
_AVOID_SHELL_FORK     = os.getenv("LLDB_AVOID_SHELL_FORK", "1").lower() in ("1","true","yes") # default: on
_RESTORE_CHILD_AFTER  = os.getenv("LLDB_RESTORE_CHILD_AFTER_CHANFORK", "0").lower() in ("1","true","yes")
_KEYLOG               = os.environ.get('LLDB_KEYLOG', '/data/keylogs/ssh_keylog_dropbear.log')

# ───── State ─────────────────────────────────────────────────────────────
_proc = {"pid": None, "target": None, "debugger": None, "process": None}
_watchpoints = {}    # key_name -> SBWatchpoint
_watch_meta  = {}    # wp_id -> {"key_name":..., "address":...}
keys = {}            # keys[pid][key_id] = {addrs/hex}
_kex_counter = {}    # per-pid
_next_key_id = {}    # per-pid

_squelch_until = 0.0
_prev_follow_mode = None    # remember before we flip to parent in chansession

# ───── Utilities ─────────────────────────────────────────────────────────
def _log(msg): print(msg, flush=True)
def _ev(tag,msg): _log(f"[{tag}] {msg}")

def _is_arm64(t):
    arch = (t.GetTriple() or "").split('-')[0].lower()
    return ('aarch64' in arch) or ('arm64' in arch)

def _is_x86(t):
    arch = (t.GetTriple() or "").split('-')[0].lower()
    return ('x86_64' in arch) or ('amd64' in arch)

def _read_bytes(proc, addr, size):
    err = lldb.SBError()
    data = proc.ReadMemory(addr, size, err)
    return None if err.Fail() else data

def _hex(data, max_len=32):
    if not data: return "(empty)"
    s = data.hex()
    return s if len(data) <= max_len else f"{s[:max_len]}... ({len(data)} bytes)"

def _pid(): 
    p = _proc["process"]
    return p.GetProcessID() if p and p.IsValid() else -1

def _ensure_pid_maps(pid):
    if pid not in keys: keys[pid] = {}
    if pid not in _kex_counter: _kex_counter[pid] = 0
    if pid not in _next_key_id: _next_key_id[pid] = 0

def _safe_target():  return _proc["target"]  if _proc["target"]  and _proc["target"].IsValid()  else None
def _safe_process(): return _proc["process"] if _proc["process"] and _proc["process"].IsValid() else None

def _set_follow_mode(mode):
    dbg = _proc["debugger"]
    if not dbg: return
    dbg.HandleCommand(f"settings set target.process.follow-fork-mode {mode}")
    _ev("FOLLOW_MODE", f"set follow-fork-mode = {mode}")

# ───── Watchpoints (first-hit only, delete on hit) ───────────────────────
def _watchpoint_cb(frame, wp, internal_dict):
    global _squelch_until
    try:
        proc = frame.GetThread().GetProcess()
        pid  = proc.GetProcessID()
        meta = _watch_meta.get(wp.GetID(), {})
        key_name = meta.get("key_name", f"wp{wp.GetID()}")
        addr     = meta.get("address", 0)
        ts = time.time()
        _ev("KEY_OVERWRITE", f"[pid {pid}] {key_name} at 0x{addr:x} @ {ts:.6f}")

        # delete, don't re-enable
        tgt = _safe_target()
        if tgt and wp and wp.IsValid():
            wid = wp.GetID()
            try:
                tgt.DeleteWatchpoint(wid)
            except Exception:
                wp.SetEnabled(False)
            _watch_meta.pop(wid, None)
        _squelch_until = ts + _TRACE_SQUELCH_SECS
    except Exception as e:
        _ev("WATCHPOINT_CB_ERROR", str(e))
    return False  # keep running

def _set_watchpoint(key_name, address, key_data):
    if not _ENABLE_WP: 
        _ev("WATCHPOINT_SKIP", f"disabled; skip {key_name}")
        return
    tgt = _safe_target()
    if not tgt:
        _ev("WATCHPOINT_ERROR", "no target")
        return
    # Dropbear AEAD often uses zero MAC keys; don't arm on zero
    if key_data and all(b == 0 for b in key_data):
        _ev("WATCHPOINT_INFO", f"{key_name} all-zero, skip")
        return
    try:
        if tgt.GetNumWatchpoints() >= tgt.GetNumSupportedHardwareWatchpoints():
            _ev("WATCHPOINT_INFO", f"HW limit reached; skip {key_name}")
            return
    except Exception:
        pass

    length = 8 if ((address & 0x7) == 0) else 4
    err = lldb.SBError()
    wp  = tgt.WatchAddress(address, length, False, True, err)  # write-only
    if err.Fail() or not wp or not wp.IsValid():
        _ev("WATCHPOINT_FAIL", f"{key_name} @0x{address:x}: {err.GetCString() or 'unknown'}")
        return
    try: wp.SetOneShot(True)
    except Exception: pass

    wid = wp.GetID()
    _watchpoints[key_name] = wp
    _watch_meta[wid] = {"key_name": key_name, "address": address}
    _proc["debugger"].HandleCommand(f"watchpoint command add -F {_modname}._watchpoint_cb {wid}")
    _ev("WATCHPOINT", f"Armed {key_name} (wp {wid}) at 0x{address:x} in pid {_pid()}")

def _clear_all_watchpoints():
    tgt = _safe_target()
    if not tgt: return
    try:
        n = tgt.GetNumWatchpoints()
        ids = []
        for i in range(n):
            wp = tgt.GetWatchpointAtIndex(i)
            if wp and wp.IsValid():
                ids.append(wp.GetID())
        for wid in ids:
            try: tgt.DeleteWatchpoint(wid)
            except Exception:
                try:
                    wp = tgt.FindWatchpointByID(wid)
                    if wp and wp.IsValid(): wp.SetEnabled(False)
                except Exception: pass
    except Exception: pass
    _watchpoints.clear()
    _watch_meta.clear()

# ───── Key extraction (ChaCha20/Poly1305 layout) ─────────────────────────
def _extract_and_watch_keys(frame, key_id):
    proc = frame.GetThread().GetProcess()
    tgt  = proc.GetTarget()
    pid  = proc.GetProcessID()

    _ev("WATCHPOINT_CONFIG", f"ENABLE_WATCHPOINTS={_ENABLE_WP}")
    _ev("WATCHPOINTS_ENABLED" if _ENABLE_WP else "WATCHPOINTS_DISABLED",
        "HW watchpoints will be installed" if _ENABLE_WP else "Skipping HW watchpoints")

    ses = tgt.FindFirstGlobalVariable("ses")
    if not ses.IsValid():
        _ev("KEY_EXTRACT_ERROR", "global 'ses' not found")
        return

    _ev("KEY_EXTRACT", f"[pid {pid}] ses @ 0x{ses.GetLoadAddress():x}")

    newkeys = ses.GetChildMemberWithName("newkeys")
    if not newkeys.IsValid():
        _ev("KEY_EXTRACT_ERROR", "ses.newkeys not found")
        return

    nk_addr = newkeys.GetValueAsUnsigned()
    if nk_addr == 0:
        _ev("KEY_EXTRACT_ERROR", "ses.newkeys is NULL")
        return
    _ev("KEY_EXTRACT", f"[pid {pid}] ses.newkeys @ 0x{nk_addr:x}")

    trans = newkeys.Dereference().GetChildMemberWithName("trans")
    recv  = newkeys.Dereference().GetChildMemberWithName("recv")
    if not trans.IsValid() or not recv.IsValid():
        _ev("KEY_EXTRACT_ERROR", "trans/recv missing")
        return

    trans_m = trans.GetChildMemberWithName("mackey")
    recv_m  = recv.GetChildMemberWithName("mackey")
    trans_m_addr = trans_m.GetLoadAddress() if trans_m.IsValid() else 0
    recv_m_addr  = recv_m.GetLoadAddress()  if recv_m.IsValid()  else 0
    _ev("KEY_EXTRACT", f"trans.mackey @ 0x{trans_m_addr:x}")
    _ev("KEY_EXTRACT", f"recv.mackey  @ 0x{recv_m_addr:x}")

    trans_cs = trans.GetChildMemberWithName("cipher_state")
    recv_cs  = recv.GetChildMemberWithName("cipher_state")

    trans_key = recv_key = None
    trans_key_addr = recv_key_addr = None
    trans_poly = recv_poly = None

    if trans_cs.IsValid():
        base = trans_cs.GetLoadAddress()
        data = _read_bytes(proc, base, 128)
        if data and data[:16] == b"expand 32-byte k":
            trans_key = data[16:48]; trans_poly = data[48:80]; trans_key_addr = base + 16
            _ev("KEY_EXTRACT_SUCCESS", f"[pid {pid}] Extracted trans ChaCha20/Poly1305")
    if recv_cs.IsValid():
        base = recv_cs.GetLoadAddress()
        data = _read_bytes(proc, base, 128)
        if data and data[:16] == b"expand 32-byte k":
            recv_key = data[16:48]; recv_poly = data[48:80]; recv_key_addr = base + 16
            _ev("KEY_EXTRACT_SUCCESS", f"[pid {pid}] Extracted recv ChaCha20/Poly1305")

    trans_mac = _read_bytes(proc, trans_m_addr, 32) or b""
    recv_mac  = _read_bytes(proc, recv_m_addr, 32)  or b""
    _ev("KEY_EXTRACT_SUCCESS", f"trans MAC: {_hex(trans_mac,16)}")
    _ev("KEY_EXTRACT_SUCCESS", f"recv  MAC: {_hex(recv_mac,16)}")

    # record
    _ensure_pid_maps(pid)
    keys[pid][key_id] = {
        "generated_at": time.time(),
        "status": "active",
        "trans_mackey_addr": trans_m_addr,
        "recv_mackey_addr":  recv_m_addr,
        "trans_mackey": trans_mac.hex() if trans_mac else "",
        "recv_mackey":  recv_mac.hex()  if recv_mac  else "",
    }
    if trans_key and trans_key_addr:
        keys[pid][key_id]["trans_cipher_key"] = trans_key.hex()
        keys[pid][key_id]["trans_cipher_key_addr"] = trans_key_addr
    if recv_key and recv_key_addr:
        keys[pid][key_id]["recv_cipher_key"] = recv_key.hex()
        keys[pid][key_id]["recv_cipher_key_addr"] = recv_key_addr

    # arm WPs (prefer cipher keys; fallback to MACs)
    if _ENABLE_WP:
        if trans_key_addr: _set_watchpoint("trans_cipher_key", trans_key_addr, trans_key)
        else:              _set_watchpoint("trans_mackey",     trans_m_addr,  trans_mac)
        if recv_key_addr:  _set_watchpoint("recv_cipher_key",  recv_key_addr, recv_key)
        else:              _set_watchpoint("recv_mackey",      recv_m_addr,   recv_mac)

    # optional keylog
    try:
        if _KEYLOG:
            ts = int(time.time())
            if trans_key and trans_poly:
                with open(_KEYLOG,"a") as f:
                    f.write(f"{ts} NEWKEYS MODE OUT CIPHER chacha20-poly1305@openssh.com "
                            f"KEY {trans_key.hex()+trans_poly.hex()} IV unknown\n")
            if recv_key and recv_poly:
                with open(_KEYLOG,"a") as f:
                    f.write(f"{ts} NEWKEYS MODE IN  CIPHER chacha20-poly1305@openssh.com "
                            f"KEY {recv_key.hex()+recv_poly.hex()} IV unknown\n")
    except Exception:
        pass

# ───── Breakpoint callbacks ──────────────────────────────────────────────
def fork_callback(frame, bp_loc, internal_dict):
    """First fork (session worker). We follow child per global setting."""
    thr = frame.GetThread()
    proc = thr.GetProcess()
    pid  = proc.GetProcessID()
    _proc.update(dict(pid=pid, process=proc, target=proc.GetTarget(), debugger=proc.GetTarget().GetDebugger()))
    _log("\n" + "="*72)
    _log(f"[FORK-CHILD] Now in child PID {pid}. Watchpoints will be installed here.")
    _log("="*72 + "\n")
    return False

def gen_new_keys_entry(frame, bp_loc, internal_dict):
    pid = frame.GetThread().GetProcess().GetProcessID()
    _ensure_pid_maps(pid)
    kexn = _kex_counter[pid]
    _log("\n" + "="*72)
    _log(f"[CALLBACK_FIRED] gen_new_keys_entry()")
    _log(f"[CALLBACK_FIRED] PID: {pid}  TID: {frame.GetThread().GetThreadID()}  KEX#: {kexn}")
    _log("="*72 + "\n")
    return False

def switch_keys_callback(frame, bp_loc, internal_dict):
    """Keys become active in the session worker → extract & arm WPs."""
    proc = frame.GetThread().GetProcess()
    pid  = proc.GetProcessID()
    _ensure_pid_maps(pid)
    _kex_counter[pid] += 1
    key_id = f"dropbear_pid{pid}_key{_next_key_id[pid]}"
    _next_key_id[pid] += 1
    _ev("KEYS_ACTIVATED", f"[pid {pid}] switch_keys()")
    _extract_and_watch_keys(frame, key_id)
    return False

def kex_init_callback(frame, bp_loc, internal_dict):
    pid = frame.GetThread().GetProcess().GetProcessID()
    fn  = frame.GetFunctionName() or "unknown"
    tag = "KEX_MESSAGE"
    if "first" in fn.lower():   tag = "INITIAL_KEX"
    elif "kexinitialise" in fn: tag = "REKEY_KEX"
    elif "recv_msg_kexinit" in fn: tag = "REKEY_INIT"
    _ev(tag, f"[pid {pid}] Entered {fn}")
    return False

def session_cleanup_callback(frame, bp_loc, internal_dict):
    pid = frame.GetThread().GetProcess().GetProcessID()
    _ev("CLEANUP", f"pid {pid}: cleared watchpoints and state (session_cleanup)")
    _clear_all_watchpoints(); keys.pop(pid, None)
    return False

def abort_callback(frame, bp_loc, internal_dict):
    pid = frame.GetThread().GetProcess().GetProcessID()
    _ev("CLEANUP", f"pid {pid}: cleared watchpoints and state (exit/_exit)")
    _clear_all_watchpoints(); keys.pop(pid, None)
    return False

# ── Chansession: avoid following the second fork (shell/command) ────────
def _chanfork_guard_entry(frame, bp_loc, internal_dict):
    """Called on entry to sessioncommand/ptycommand/noptycommand.
       Flip follow-fork-mode to 'parent' so we stay with dropbear session.
    """
    if not _AVOID_SHELL_FORK: 
        return False
    dbg = _proc["debugger"]
    if not dbg: 
        return False
    # remember previous mode (best-effort)
    global _prev_follow_mode
    _prev_follow_mode = "child"  # assume child; we’ll switch to parent now
    _set_follow_mode("parent")
    _ev("CHAN_FORK_GUARD", "armed (stay on session worker; ignore shell child)")
    return False

def _chanfork_guard_exit(frame, bp_loc, internal_dict):
    """Optional: restore previous follow-fork-mode (off by default)."""
    if not (_AVOID_SHELL_FORK and _RESTORE_CHILD_AFTER):
        return False
    mode = _prev_follow_mode or "child"
    _set_follow_mode(mode)
    _ev("CHAN_FORK_GUARD", f"restored follow-fork-mode = {mode}")
    return False

# m_burn (optional; no watchpoint juggling here)
def m_burn_entry(frame, bp_loc, internal_dict):
    return False

# ───── Stop-hook: auto-continue libc memwipe 'trace' stops ───────────────
def _autocont_trace_cmd(debugger, command, exe_ctx, result, internal_dict):
    try:
        import time as _t
        now = _t.time()
        if not _AUTOCONT_ALWAYS and now > _squelch_until:
            return
        thr = exe_ctx.thread
        if not thr or thr.GetStopReason() != lldb.eStopReasonTrace:
            return
        fr = thr.GetFrameAtIndex(0)
        if not fr or not fr.IsValid(): return
        mod = fr.GetModule().GetFileSpec().GetFilename() or ""
        fn  = fr.GetFunctionName() or ""
        is_libc = ("libc.so" in mod) or ("libc-" in mod)
        looks  = ("memset" in fn) or ("bzero" in fn) or ("explicit_bzero" in fn) or ("___lldb_unnamed_symbol" in fn)
        if is_libc and looks:
            exe_ctx.process.Continue()
    except Exception:
        pass

# ───── Module init ───────────────────────────────────────────────────────
def __lldb_init_module(debugger, internal_dict):
    target  = debugger.GetSelectedTarget()
    process = target.GetProcess() if target and target.IsValid() else None

    _proc.update(dict(debugger=debugger, target=target, process=process,
                      pid=(process.GetProcessID() if process and process.IsValid() else None)))

    print("="*72)
    print("Loading Dropbear callbacks...")
    print(f"[DROPBEAR_CB_VERSION] {__version__}")
    print(f"[DROPBEAR_CB_LOADED ] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} local")
    print(f"[DROPBEAR_CB_FILE   ] {__file__}")
    print(f"Watchpoints: {'ENABLED' if _ENABLE_WP else 'DISABLED'}")
    print("="*72)

    if process and process.IsValid():
        print(f"[INFO] Parent/master PID: {process.GetProcessID()}")

    def addbp(name, cb=None, autoc=True, must=False):
        bp = target.BreakpointCreateByName(name) if target and target.IsValid() else lldb.SBBreakpoint()
        if bp and bp.IsValid() and (not must or bp.GetNumLocations() > 0):
            if cb: bp.SetScriptCallbackFunction(f"{_modname}.{cb}")
            if autoc: bp.SetAutoContinue(True)
            print(f" {name} (bp {bp.GetID()}{', %d loc'%bp.GetNumLocations() if bp.GetNumLocations()>0 else ''})")
        else:
            print(f" ⚠ {name} not found")
        return bp

    # KEX & activation
    addbp("gen_new_keys",           "gen_new_keys_entry")
    addbp("kexfirstinitialise",     "kex_init_callback")
    addbp("kexinitialise",          "kex_init_callback")
    addbp("recv_msg_kexinit",       "kex_init_callback")
    addbp("send_msg_kexinit",       "kex_init_callback")
    addbp("recv_msg_kexdh_init",    "kex_init_callback")
    addbp("send_msg_kexdh_reply",   "kex_init_callback")
    addbp("send_msg_newkeys",       "kex_init_callback")
    addbp("recv_msg_newkeys",       "kex_init_callback")
    addbp("switch_keys",            "switch_keys_callback")

    # Shared-secret sites (informational)
    addbp("kexcurve25519_comb_key", "kex_init_callback")
    addbp("kexdh_comb_key",         "kex_init_callback")
    addbp("kexecdh_comb_key",       "kex_init_callback")

    # First fork (session child)
    addbp("fork",                   "fork_callback", autoc=True, must=True)

    # Chansession fork guards
    addbp("sessioncommand",         "_chanfork_guard_entry")
    addbp("ptycommand",             "_chanfork_guard_entry")
    addbp("noptycommand",           "_chanfork_guard_entry")

    if _RESTORE_CHILD_AFTER:
        # Optionally restore after chansession returns (best-effort)
        pass

    # Cleanup / exit
    addbp("session_cleanup",        "session_cleanup_callback")
    addbp("cleanup_keys",           "session_cleanup_callback")
    addbp("dropbear_exit",          "abort_callback")
    addbp("exit",                   "abort_callback")
    addbp("_exit",                  "abort_callback")
    addbp("_Exit",                  "abort_callback")

    # Optional m_burn
    if _MBURN_ENABLED:
        addbp("m_burn", "m_burn_entry")
    else:
        print(" m_burn hook DISABLED (LLDB_MBURN_HOOK=0)")

    # Stop-hook to auto-continue libc memwipe trace stops
    debugger.HandleCommand(f"command script add -f {_modname}._autocont_trace_cmd dbcb.autocont")
    debugger.HandleCommand("target stop-hook add -o dbcb.autocont")
    print("Stop hook added: dbcb.autocont (Python)")
    print("Stop hook mode:",
          "ALWAYS auto-continue libc memwipe traces" if _AUTOCONT_ALWAYS
          else f"Auto-continue libc memwipe traces for {_TRACE_SQUELCH_SECS}s after a hit")

    print("\n Loaded (HW watchpoints {0})".format("ENABLED" if _ENABLE_WP else "DISABLED"))
    print("Abort/exit hooks armed")

    # Auto-continue so you don’t have to press 'c'
    if _AUTOCONT_ON_ATTACH and process and process.IsValid():
        st = process.GetState()
        if st in (lldb.eStateStopped, lldb.eStateAttaching, lldb.eStatePaused, lldb.eStateCrashed):
            debugger.HandleCommand("process continue")
