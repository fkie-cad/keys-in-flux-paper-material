#!/usr/bin/env python3
"""
Simple Paramiko client that monkeypatches the same handlers as the server
so we can capture client-side cookie + K and write to ssh_keylog.log.
Useful if you want the client to produce the Wireshark keylog.
"""

import os
import sys
import argparse
import socket
import time
from datetime import datetime
import json

import paramiko

LOGFILE = os.path.abspath("ssh_keylog.log")
DUMP_DIR = os.path.abspath("kex_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)

def append_keylog_line(line: str):
    with open(LOGFILE, "a") as f:
        f.write(line.rstrip() + "\n")
    print("[KEYLOG] " + line)

# We'll reuse the same handler-wrapping approach used in the server script
import paramiko.common as common
MSG_KEXINIT = common.MSG_KEXINIT
MSG_NEWKEYS = common.MSG_NEWKEYS

_transport = paramiko.transport.Transport
_orig_handler_table = dict(_transport._handler_table)

def write_diag(name, info):
    path = os.path.join(DUMP_DIR, f"{name}_{int(time.time()*1000)}.json")
    with open(path, "w") as f:
        json.dump(info, f, indent=2, default=repr)
    print(f"[DIAG] {path}")

def format_bigint_to_bytes_hex(v):
    if v is None:
        return None
    if isinstance(v, int):
        if v == 0:
            return "00"
        bytelen = (v.bit_length() + 7) // 8
        return v.to_bytes(bytelen, "big").hex()
    try:
        b = bytes(v)
        return b.hex()
    except Exception:
        pass
    return None

def my_kexinit_handler(transport_obj, m):
    try:
        m.rewind()
        cookie = m.get_bytes(16)
        cookie_hex = cookie.hex()
        # store locally on transport
        setattr(transport_obj, "_last_kex_cookie_remote", cookie_hex)
        print(f"[kexinit] remote cookie {cookie_hex}")
    except Exception as e:
        print("[kexinit] err", e)
    orig = _orig_handler_table.get(MSG_KEXINIT)
    if orig:
        return orig(transport_obj, m)
    return None

def my_newkeys_handler(transport_obj, m):
    info = {"time": datetime.utcnow().isoformat() + "Z", "role": "client"}
    cookie_remote = getattr(transport_obj, "_last_kex_cookie_remote", None)
    info["cookie_remote"] = cookie_remote
    extracted = None
    try:
        kex_engine = getattr(transport_obj, "kex_engine", None) or getattr(transport_obj, "_kex_engine", None)
        info["kex_engine_type"] = type(kex_engine).__name__ if kex_engine else None
        if kex_engine:
            for attr in ("K", "shared_secret", "K_int"):
                val = getattr(kex_engine, attr, None)
                if val is not None:
                    hexv = format_bigint_to_bytes_hex(val)
                    info.setdefault("attempts", []).append({"method": f"attr:{attr}", "hex": hexv})
                    if hexv:
                        extracted = hexv
                        break
            # DH fallback:
            if not extracted:
                f = getattr(kex_engine, "f", None)
                x = getattr(kex_engine, "x", None)
                p = getattr(kex_engine, "p", None)
                if all(v is not None for v in (f, x, p)):
                    try:
                        if not isinstance(f, int):
                            f = int.from_bytes(bytes(f), "big")
                        if not isinstance(x, int):
                            x = int.from_bytes(bytes(x), "big")
                        if not isinstance(p, int):
                            p = int.from_bytes(bytes(p), "big")
                        K = pow(f, x, p)
                        hexv = format_bigint_to_bytes_hex(K)
                        info.setdefault("attempts", []).append({"method": "dh_pow", "hex": hexv})
                        extracted = hexv
                    except Exception as e:
                        info.setdefault("attempts", []).append({"method": "dh_pow_error", "err": repr(e)})
    except Exception as e:
        info["error"] = repr(e)

    if extracted:
        cookie = cookie_remote or ("00"*16)
        line = f"{cookie} SHARED_SECRET {extracted}"
        append_keylog_line(line)
        info["keylog_line"] = line
    else:
        info["note"] = "Could not auto-extract shared secret; see attempts for details."

    write_diag("client_newkeys", info)
    orig = _orig_handler_table.get(MSG_NEWKEYS)
    if orig:
        return orig(transport_obj, m)
    return None

# install
_transport._handler_table[MSG_KEXINIT] = my_kexinit_handler
_transport._handler_table[MSG_NEWKEYS] = my_newkeys_handler

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--username", default="testuser")
    p.add_argument("--password", default="testpass")
    args = p.parse_args()

    print(f"[CLIENT] connecting to {args.host}:{args.port}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.host, port=args.port, username=args.username, password=args.password, timeout=10)
    stdin, stdout, stderr = client.exec_command("echo hello_from_paramiko")
    print("[CLIENT] stdout:", stdout.read().decode().strip())
    client.close()

if __name__ == "__main__":
    import argparse
    main()
