#!/usr/bin/env python3
# strongswan_cb.py
# Still under development... 
#
# LLDB callback helpers to hook IKEv2 KDF in strongSwan:
#  - prf->set_key(prf, chunk_t key)
#  - prf_plus_create(prf, chunk_t seed) / prf+ consumption points
#  - charon->bus->ike_derived_keys(... sk_ei, sk_er, ...)
#
# Supports:
#  * x86_64 (SysV ABI)
#  * aarch64 (AAPCS64)
# And two modes:
#  * With symbols/debug info (preferred) -> allows extracting locals by name
#  * Without symbols -> reads arguments from registers (and best-effort stack)
#
# Output:
#  * Prints to LLDB console
#  * Appends JSON lines to /tmp/ike_kdf_dump.jsonl
#
# Usage (examples):
#   (inside the appropriate netns)
#   sudo ip netns exec left lldb -p $(pgrep -n -x charon)
#   (lldb) command script import /path/to/strongswan_cb.py
#   (lldb) ss_prf_set_key
#   (lldb) ss_prf_plus
#   (lldb) ss_ike_keys
#   (lldb) c
#
# Or use your monitoring.py pattern-based loader to bind the callbacks below.
#
# NOTE:
#  * chunk_t in strongSwan is { uint8_t* ptr; size_t len; } (16 bytes on 64-bit)
#  * Passing convention (prf_set_key/prf_plus_create): (prf*, chunk.ptr, chunk.len)
#    - x86_64:    rdi=prf, rsi=ptr, rdx=len
#    - aarch64:   x0=prf,  x1=ptr,  x2=len
#  * For bus->ike_derived_keys(..., sk_ei, sk_er, ...), the argument explosion
#    may spill to stack when stripped; we implement a robust symbol-aware path,
#    and a best-effort register/stack fallback for sk_ei/sk_er.
#
import lldb
import json
import os
from datetime import datetime
import struct

OUT_PATH = os.environ.get("IKE_KDF_DUMP", "/tmp/ike_kdf_dump.jsonl")

def _append_json(obj):
    try:
        with open(OUT_PATH, "a") as f:
            f.write(json.dumps(obj) + "\n")
    except Exception as e:
        print(f"[ss] failed writing {OUT_PATH}: {e}")

def _triple(frame):
    return frame.GetThread().GetProcess().GetTarget().GetTriple()

def _arch_regs(frame):
    """Return register map for current arch (x86_64/aarch64)."""
    triple = _triple(frame)
    regs = {}
    if "aarch64" in triple:
        regs["A"] = ["x0","x1","x2","x3","x4","x5","x6","x7"]
        regs["SP"]="sp"
        regs["IP"]="pc"
    else:
        regs["A"] = ["rdi","rsi","rdx","rcx","r8","r9"]
        regs["SP"]="rsp"
        regs["IP"]="rip"
    return regs

def _read_mem(proc, addr, size):
    err = lldb.SBError()
    data = proc.ReadMemory(addr, size, err)
    if not err.Success():
        raise RuntimeError(f"ReadMemory(0x{addr:x}, {size}) failed: {err}")
    return bytes(data)

def _read_chunk_from_regs(frame, first_idx):
    """Return (ptr,len,data) reading a chunk_t passed-by-value starting at arg index 'first_idx'."""
    regs = _arch_regs(frame)
    thread = frame.GetThread()
    proc = thread.GetProcess()
    ptr = frame.FindRegister(regs["A"][first_idx]).GetValueAsUnsigned()
    length = frame.FindRegister(regs["A"][first_idx+1]).GetValueAsUnsigned()
    data = b""
    try:
        if ptr and length:
            data = _read_mem(proc, ptr, min(length, 65536))
    except Exception as e:
        print(f"[ss] read chunk failed: {e}")
    return ptr, length, data

def _read_chunk_from_addr(frame, addr):
    """addr points to chunk_t in memory (ptr, len). Returns (ptr,len,data)."""
    proc = frame.GetThread().GetProcess()
    buf = _read_mem(proc, addr, 16)
    ptr, length = struct.unpack("<QQ", buf)
    data = _read_mem(proc, ptr, min(length, 65536)) if ptr and length else b""
    return ptr, length, data

def _fmt_hex(b, limit=128):
    if b is None: return "<nil>"
    sl = b[:limit]
    return " ".join(f"{x:02x}" for x in sl) + ("" if len(b)<=limit else " ...")

def _now_iso():
    return datetime.utcnow().isoformat() + "Z"

# -------------------- Callbacks --------------------

def prf_set_key_callback(frame, bp_loc, _dict):
    """Hook prf->set_key(prf, chunk_t key)"""
    try:
        ptr, length, data = _read_chunk_from_regs(frame, 1)
        msg = {
            "ts": _now_iso(),
            "event": "prf_set_key",
            "len": int(length),
            "sample": data[:64].hex(),
        }
        print(f"[PRF set_key] len={length} ptr=0x{ptr:x} sample={_fmt_hex(data,64)}")
        _append_json(msg)
    except Exception as e:
        print(f"[PRF set_key] error: {e}")
    return False

def prf_plus_create_callback(frame, bp_loc, _dict):
    """Hook prf_plus_create(prf, chunk_t seed)"""
    try:
        ptr, length, data = _read_chunk_from_regs(frame, 1)
        msg = {
            "ts": _now_iso(),
            "event": "prf_plus_seed",
            "len": int(length),
            "sample": data[:64].hex(),
        }
        print(f"[PRF+] seed len={length} ptr=0x{ptr:x} sample={_fmt_hex(data,64)}")
        _append_json(msg)
    except Exception as e:
        print(f"[PRF+] error: {e}")
    return False

def ike_derived_keys_callback(frame, bp_loc, _dict):
    """Hook bus->ike_derived_keys(..., sk_ei, sk_er, ...)"""
    try:
        proc = frame.GetThread().GetProcess()
        extracted = {}
        symbolic_ok = False
        for name in ("sk_ai","sk_ar","sk_ei","sk_er","sk_pi","sk_pr"):
            val = frame.EvaluateExpression(f"(&{name})")
            if val.IsValid() and val.GetValueAsUnsigned() != 0:
                symbolic_ok = True
                addr = val.GetValueAsUnsigned()
                ptr, length, data = _read_chunk_from_addr(frame, addr)
                extracted[name] = {"len": int(length), "sample": data[:64].hex()}
        if not symbolic_ok:
            regs = _arch_regs(frame)["A"]
            def try_idx(idx):
                try:
                    p = frame.FindRegister(regs[idx]).GetValueAsUnsigned()
                    l = frame.FindRegister(regs[idx+1]).GetValueAsUnsigned()
                    d = _read_mem(proc, p, min(l, 65536)) if p and l else b""
                    return {"len": int(l), "sample": d[:64].hex()}
                except Exception:
                    return None
            extracted["sk_ei"] = try_idx(3) or extracted.get("sk_ei")
            extracted["sk_er"] = try_idx(5) or extracted.get("sk_er")

        if extracted:
            print("[IKE keys] " + ", ".join(f"{k}:len={v['len']}" for k,v in extracted.items() if v))
            _append_json({"ts": _now_iso(), "event": "ike_derived_keys", "keys": extracted})
        else:
            print("[IKE keys] could not extract (likely stripped + stack-spilled)")
    except Exception as e:
        print(f"[IKE keys] error: {e}")
    return False

# -------------------- Convenience commands --------------------
def ss_prf_set_key(debugger, command, result, _dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("set_key")
    bp.SetScriptCallbackFunction(__name__ + ".prf_set_key_callback")
    print(f"[ss] breakpoint {bp.GetID()} on set_key; continue with 'c'")

def ss_prf_plus(debugger, command, result, _dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("prf_plus_create")
    bp.SetScriptCallbackFunction(__name__ + ".prf_plus_create_callback")
    print(f"[ss] breakpoint {bp.GetID()} on prf_plus_create; continue with 'c'")

def ss_ike_keys(debugger, command, result, _dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("ike_derived_keys")
    if bp and bp.num_locations > 0:
        bp.SetScriptCallbackFunction(__name__ + ".ike_derived_keys_callback")
        print(f"[ss] breakpoint {bp.GetID()} on ike_derived_keys; continue with 'c'")
    else:
        print("[ss] No symbol 'ike_derived_keys'. If you have debug info, try:")
        print("      br s -f keymat_v2.c -l 381")

def __lldb_init_module(debugger, _dict):
    debugger.HandleCommand('command script add -f strongswan_cb.ss_prf_set_key ss_prf_set_key')
    debugger.HandleCommand('command script add -f strongswan_cb.ss_prf_plus ss_prf_plus')
    debugger.HandleCommand('command script add -f strongswan_cb.ss_ike_keys ss_ike_keys')
    print("[ss] strongswan_cb loaded. Commands: ss_prf_set_key | ss_prf_plus | ss_ike_keys")