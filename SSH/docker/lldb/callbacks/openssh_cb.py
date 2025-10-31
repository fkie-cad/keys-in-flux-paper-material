#!/usr/bin/env python3
"""
lldb/callbacks/openssh_cb.py

OpenSSH-specific LLDB callbacks for tracking KEX/key derivation events.

Implements:
- kex_entry_callback(frame, bp_loc, dict)  -> entry breakpoint callback
- kex_exit_callback(frame, bp_loc, dict)   -> exit (return-address) breakpoint callback

Behavior:
- On entry: record a lightweight memory snapshot and write a pre-dump file; set a one-shot breakpoint
  at the recorded return address so we can capture post-state when the function returns.
- On exit: write a post-dump file, compute diffs vs pre-snapshot, heuristically search for changed byte
  sequences that look like key material (16-64 bytes) and write diagnostic JSON and keylog lines when
  confident.

Note: this is best-effort and intended for use in a lab. It is intentionally conservative and writes
diagnostic JSON files to help you refine heuristics for your OpenSSH build/version.
"""

import os
import sys
import json
import time
import traceback
from hashlib import sha256

# Make sure package imports work when loaded by tracker_main
_this = os.path.dirname(__file__)
_root = os.path.abspath(os.path.join(_this, ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)

import lldb

OUT_DIR = os.environ.get("LLDB_OUTDIR", "/data/dumps")
KEYLOG_FILE = os.environ.get("LLDB_KEYLOG", "/data/keylogs/ssh_keylog.log")
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(KEYLOG_FILE), exist_ok=True)

# helper to write diagnostic JSON
def write_diag(name, data):
    ts = int(time.time() * 1000)
    path = os.path.join(OUT_DIR, f"{name}_{ts}.json")
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=repr)
        print(f"[diag] Wrote {path}")
    except Exception as e:
        print("write_diag error:", e)

def dump_memory_regions(process, label):
    """
    Full raw dump into files similar to the TLS script.
    """
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(OUT_DIR, f"{ts}_{label}")
    regions = process.GetMemoryRegions()
    num = regions.GetSize()
    region_info = lldb.SBMemoryRegionInfo()
    total_written = 0
    files = []
    for i in range(num):
        ok = regions.GetMemoryRegionAtIndex(i, region_info)
        if not ok:
            continue
        start = int(region_info.GetRegionBase())
        end = int(region_info.GetRegionEnd())
        size = max(0, end - start)
        if size == 0:
            continue
        if not region_info.IsReadable():
            continue
        err = lldb.SBError()
        data = process.ReadMemory(start, size, err)
        if not err.Success() or not data:
            continue
        path = f"{base}_{i:03d}.dump"
        try:
            with open(path, "wb") as f:
                f.write(data)
            files.append({"path": path, "base": start, "size": size})
            total_written += len(data)
        except Exception as e:
            print("dump write err", e)
    print(f"[dump] Wrote {total_written} bytes for {label}")
    return files

def read_register_value(frame, regname):
    try:
        rv = frame.FindRegister(regname)
        if rv and rv.IsValid() and rv.GetValue():
            return int(rv.GetValue(), 0)
    except Exception:
        pass
    return None

def read_rsp_return_address(frame):
    # x86_64: return address is at [rsp]
    try:
        rsp_reg = frame.FindRegister("rsp")
        if rsp_reg and rsp_reg.IsValid() and rsp_reg.GetValue():
            rsp = int(rsp_reg.GetValue(), 0)
            proc = frame.GetThread().GetProcess()
            err = lldb.SBError()
            data = proc.ReadMemory(rsp, 8, err)
            if err.Success() and data and len(data) >= 8:
                return int.from_bytes(data[:8], byteorder='little', signed=False)
    except Exception:
        pass
    return None

def read_lr_return_address(frame):
    # AArch64: try x30 or lr
    for name in ("x30", "lr"):
        val = read_register_value(frame, name)
        if val:
            return val
    # fallback to reading stack pointer
    try:
        sp_reg = frame.FindRegister("sp") or frame.FindRegister("rsp")
        if sp_reg and sp_reg.IsValid() and sp_reg.GetValue():
            sp = int(sp_reg.GetValue(), 0)
            proc = frame.GetThread().GetProcess()
            err = lldb.SBError()
            data = proc.ReadMemory(sp, 8, err)
            if err.Success() and data and len(data) >= 8:
                return int.from_bytes(data[:8], byteorder='little', signed=False)
    except Exception:
        pass
    return None

def kex_entry_callback(frame, bp_loc, dict):
    """
    Entry callback invoked at function start. We:
      - write a pre memory dump (lightweight snapshot)
      - set a one-shot breakpoint at the return address and map it to this entry
    """
    print("[openssh_cb] kex_entry_callback hit")
    sys.stdout.flush()
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        target = process.GetTarget()

        # write a (potentially heavy) pre-dump file
        pre_files = dump_memory_regions(process, "pre_kex")

        # attempt to extract stack/args for diagnostics
        args_info = {}
        try:
            # print registers of interest
            for rn in ("rdi","rsi","rdx","rcx","r8","r9","rsp","rbp","rip"):
                try:
                    rv = frame.FindRegister(rn)
                    if rv and rv.IsValid() and rv.GetValue():
                        args_info[rn] = rv.GetValue()
                except Exception:
                    pass
        except Exception:
            pass

        # try to determine return address
        arch = target.GetTriple()
        ret_addr = None
        if arch and arch.startswith("x86_64"):
            ret_addr = read_rsp_return_address(frame)
        else:
            ret_addr = read_lr_return_address(frame)

        meta = {
            "time": time.time(),
            "arch": arch,
            "args": args_info,
            "pre_files": pre_files,
            "frame_func": frame.GetFunctionName()
        }
        write_diag("kex_entry_meta", meta)

        # Set a one-shot breakpoint at ret_addr (if found)
        if ret_addr:
            bp = target.BreakpointCreateByAddress(ret_addr)
            if bp and bp.GetNumLocations() > 0:
                bp.SetOneShot(True)
                # callback fully-qualified name
                cb_fqn = "callbacks.openssh_cb.kex_exit_callback"
                bp.SetScriptCallbackFunction(cb_fqn)
                # store mapping in a global table on module for the exit handler
                # store meta keyed by bp id
                try:
                    global _KEX_BP_META
                    _KEX_BP_META[bp.GetID()] = meta
                except Exception:
                    _KEX_BP_META = {bp.GetID(): meta}
                print(f"[openssh_cb] set exit bp id={bp.GetID()} at {ret_addr:#x}")
            else:
                print("[openssh_cb] failed to set exit breakpoint")
        else:
            print("[openssh_cb] could not determine return address")
    except Exception as e:
        print("[openssh_cb] entry callback exception:", e)
        traceback.print_exc()
    # continue execution
    return False

def _find_candidate_key_bytes(pre_files, post_files):
    """
    Heuristic: compare first N bytes of corresponding pre/post dumps from same base addresses.
    Look for changed byte runs between 16 and 64 bytes that look random (high entropy).
    Return list of candidate hex strings.
    """
    candidates = []
    try:
        # Map by base
        pre_map = {os.path.basename(x["path"]): x for x in pre_files}
        post_map = {os.path.basename(x["path"]): x for x in post_files}
        # For each pre file, compare with corresponding post file by index in filename ordering
        for p in pre_files:
            # find corresponding post file with same index suffix
            name = os.path.basename(p["path"])
            # naive match by index after last underscore
            # We'll instead compare by base addresses if available
            # For simplicity, open both and compute byte diffs for the first 4096 bytes
            try:
                with open(p["path"], "rb") as f:
                    preb = f.read(4096)
            except Exception:
                preb = b""
            corresponding_post = None
            # choose the post file with same region index (best-effort)
            for q in post_files:
                if q["base"] == p["base"]:
                    corresponding_post = q
                    break
            if not corresponding_post and post_files:
                corresponding_post = post_files[0]
            postb = b""
            if corresponding_post:
                try:
                    with open(corresponding_post["path"], "rb") as f:
                        postb = f.read(4096)
                except Exception:
                    postb = b""
            if not preb or not postb:
                continue
            # find changed runs
            run = None
            runs = []
            for i in range(min(len(preb), len(postb))):
                if preb[i] != postb[i]:
                    if run is None:
                        run = [i, i]
                    else:
                        run[1] = i
                else:
                    if run is not None:
                        runs.append((run[0], run[1]))
                        run = None
            if run is not None:
                runs.append((run[0], run[1]))
            # evaluate runs for key-like properties
            for (s,e) in runs:
                length = e - s + 1
                if length < 16 or length > 256:
                    continue
                chunk = postb[s:e+1]
                # entropy check (simple): check byte distribution
                uniq = len(set(chunk))
                if uniq < max(4, length//4):
                    # likely low-entropy (not key)
                    continue
                # candidate
                candidates.append(chunk.hex())
    except Exception as e:
        print("_find_candidate_key_bytes err", e)
    return candidates

def kex_exit_callback(frame, bp_loc, dict):
    """
    Callback triggered at return address. Compute diffs and try extraction.
    """
    print("[openssh_cb] kex_exit_callback hit")
    sys.stdout.flush()
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        target = process.GetTarget()

        # write post-dump
        post_files = dump_memory_regions(process, "post_kex")
        # try to retrieve meta saved at entry
        bp = bp_loc.GetBreakpoint()
        meta = {}
        try:
            global _KEX_BP_META
            meta = _KEX_BP_META.pop(bp.GetID(), {})
        except Exception:
            meta = {}

        # write diagnostics
        info = {
            "time": time.time(),
            "meta": meta,
            "post_files": post_files,
            "frame": frame.GetFunctionName()
        }

        # attempt to find candidate keys by comparing pre & post files
        pre_files = meta.get("pre_files", [])
        candidates = _find_candidate_key_bytes(pre_files, post_files)
        info["candidates_count"] = len(candidates)
        info["candidates_example"] = candidates[:5]
        write_diag("kex_exit_meta", info)

        # If we found a single candidate, write keylog line (cookie unknown -> placeholder)
        if len(candidates) == 1:
            cookie = meta.get("args", {}).get("cookie", None) or ("00"*16)
            line = f"{cookie} SHARED_SECRET {candidates[0]}"
            try:
                with open(KEYLOG_FILE, "a") as f:
                    f.write(line + "\\n")
                print("[openssh_cb] wrote keylog line")
            except Exception as e:
                print("failed to write keylog", e)
        else:
            if len(candidates) > 1:
                print("[openssh_cb] multiple candidate key blobs found; check diagnostic JSON for details")
            else:
                print("[openssh_cb] no viable candidate key found in memory diffs")
    except Exception as e:
        print("exit callback err", e)
        traceback.print_exc()
    # continue process
    return False
