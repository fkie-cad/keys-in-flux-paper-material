#!/usr/bin/env python3
"""
Minimal Paramiko server that logs SSH KEX cookies and SHARED_SECRETs
to ./ssh_keylog.log in a Wireshark compatible format:
  <cookie_hex> SHARED_SECRET <K_hex>

Also writes JSON diagnostics per KEX into ./kex_dumps/
"""

import os
import sys
import json
import socket
import threading
import time
from datetime import datetime

import paramiko

LOGFILE = os.path.abspath("ssh_keylog.log")
DUMP_DIR = os.path.abspath("kex_dumps")
os.makedirs(DUMP_DIR, exist_ok=True)

# Simple server host key (generate for lab; in prod, use real host keys)
HOST_KEY_FILE = "server_host_key.pem"
if not os.path.exists(HOST_KEY_FILE):
    # generate ephemeral RSA host key for demo with paramiko
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(HOST_KEY_FILE)
else:
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)

# helper: append a line to ssh_keylog.log
def append_keylog_line(line: str):
    with open(LOGFILE, "a") as f:
        f.write(line.rstrip() + "\n")
    print("[KEYLOG] " + line)

# helper: write diagnostic json
def write_diag(idx, info):
    path = os.path.join(DUMP_DIR, f"{idx}_{int(time.time()*1000)}.json")
    with open(path, "w") as f:
        json.dump(info, f, indent=2, default=repr)
    print(f"[DIAG] Wrote {path}")

# --- monkeypatch paramiko transport handlers to capture cookie and shared secret
import paramiko.common as common
MSG_KEXINIT = common.MSG_KEXINIT
MSG_NEWKEYS = common.MSG_NEWKEYS

# store original handlers to call later
_transport = paramiko.transport.Transport
_orig_handler_table = dict(_transport._handler_table)

# shared storage: attach cookie and extracted K to the Transport instance
def my_kexinit_handler(transport_obj, m):
    """
    Wrap MSG_KEXINIT handler to capture the 16-byte cookie sent in MSG_KEXINIT
    m is a paramiko.message.Message
    """
    try:
        # rewind message to read the raw cookie bytes (first 16 bytes)
        m.rewind()
        cookie = m.get_bytes(16)
        cookie_hex = cookie.hex()
        # store cookie on the transport obj - need to know who sent it:
        # in server we receive client's KEXINIT (so client cookie),
        # paramiko handlers usually store packets with self._remote_kexinit etc but we keep a local attr:
        setattr(transport_obj, "_last_kex_cookie_remote", cookie_hex)
        print(f"[kexinit] stored remote cookie: {cookie_hex}")
    except Exception as e:
        print(f"[kexinit] cookie extraction error: {e}")

    # call original handler
    orig = _orig_handler_table.get(MSG_KEXINIT)
    if orig:
        return orig(transport_obj, m)
    else:
        # fallback if orig missing
        return None

def format_bigint_to_bytes_hex(v):
    """
    Accept several bigint/pymath types and return hex string of bytes (big-endian).
    """
    if v is None:
        return None
    # If it's an int:
    if isinstance(v, int):
        # compute minimal bytes
        if v == 0:
            return "00"
        bytelen = (v.bit_length() + 7) // 8
        return v.to_bytes(bytelen, "big").hex()
    # If Paramiko mpint-like or bytes:
    try:
        # try bytes-like
        b = bytes(v)
        return b.hex()
    except Exception:
        pass
    # try repr fallback
    return None

def my_newkeys_handler(transport_obj, m):
    """
    Wrap MSG_NEWKEYS handler: this event happens at the point keys switch.
    We attempt to extract shared secret K and write keylog line.
    """
    # Try to gather data
    timestamp = datetime.utcnow().isoformat() + "Z"
    role = "server" if transport_obj.server_mode else "client"
    cookie_remote = getattr(transport_obj, "_last_kex_cookie_remote", None)
    info = {
        "timestamp": timestamp,
        "role": role,
        "cookie_remote": cookie_remote,
        "attempts": []
    }

    # Try multiple heuristics for obtaining shared secret
    extracted_hex = None
    try:
        # kex_engine often lives in transport_obj.kex_engine or similar; explore attributes
        kex_engine = getattr(transport_obj, "kex_engine", None)
        if not kex_engine:
            # some paramiko versions store as _kex_engine
            kex_engine = getattr(transport_obj, "_kex_engine", None)
        info["kex_engine_type"] = type(kex_engine).__name__ if kex_engine else None

        if kex_engine:
            # heuristic 1: engine.K or engine.shared_secret (common)
            for attr in ("K", "shared_secret", "K_int", "_K"):
                val = getattr(kex_engine, attr, None)
                if val is not None:
                    hexv = format_bigint_to_bytes_hex(val)
                    info["attempts"].append({"method": f"attr:{attr}", "value_repr": repr(val)[:200], "hex": hexv})
                    if hexv:
                        extracted_hex = hexv
                        break

            # heuristic 2: if DH group: maybe 'f' (server public), 'x' (priv), 'p' (modulus)
            if not extracted_hex:
                f = getattr(kex_engine, "f", None) or getattr(kex_engine, "server_key", None)
                x = getattr(kex_engine, "x", None) or getattr(kex_engine, "priv", None)
                p = getattr(kex_engine, "p", None) or getattr(kex_engine, "prime", None)
                info["attempts"].append({"method": "dh_parts", "f": repr(f)[:200], "x": repr(x)[:200], "p": repr(p)[:200]})
                if all(v is not None for v in (f, x, p)):
                    try:
                        # ensure ints
                        if not isinstance(f, int):
                            try:
                                f = int(f)
                            except Exception:
                                f = int.from_bytes(bytes(f), "big")
                        if not isinstance(x, int):
                            try:
                                x = int(x)
                            except Exception:
                                x = int.from_bytes(bytes(x), "big")
                        if not isinstance(p, int):
                            try:
                                p = int(p)
                            except Exception:
                                p = int.from_bytes(bytes(p), "big")
                        K = pow(f, x, p)
                        hexv = format_bigint_to_bytes_hex(K)
                        info["attempts"].append({"method": "dh_pow", "hex": hexv})
                        extracted_hex = hexv
                    except Exception as e:
                        info["attempts"].append({"method": "dh_pow_error", "error": repr(e)})

            # heuristic 3: maybe the engine stored an encoded shared secret
            if not extracted_hex:
                for attr in ("shared_key", "_shared_key", "k"):
                    val = getattr(kex_engine, attr, None)
                    if val is not None:
                        try:
                            hexv = bytes(val).hex()
                        except Exception:
                            hexv = format_bigint_to_bytes_hex(val)
                        info["attempts"].append({"method": f"attr:{attr}", "value_repr": repr(val)[:200], "hex": hexv})
                        if hexv:
                            extracted_hex = hexv
                            break

    except Exception as e:
        info["attempts"].append({"method": "exception", "error": repr(e)})

    # final fallback: place a message
    if not extracted_hex:
        info["note"] = ("Could not auto-extract K (shared secret). "
                        "Check the JSON diag file to see available attributes of the kex engine. "
                        "You can compute shared secret from the server private value and peer public value if present.")
    else:
        # write Wireshark keylog line (cookie from remote side + type + key)
        if not cookie_remote:
            # If we have no cookie stored, create a pseudo cookie using timestamp (NOT ideal) — prefer real cookie.
            cookie_remote = ("00" * 16)
            info["cookie_fallback"] = True
        line = f"{cookie_remote} SHARED_SECRET {extracted_hex}"
        append_keylog_line(line)
        info["keylog_line"] = line

    # dump diag
    write_diag("newkeys", info)

    # call original handler
    orig = _orig_handler_table.get(MSG_NEWKEYS)
    if orig:
        return orig(transport_obj, m)
    return None

# install the wrapper handlers
_transport._handler_table[MSG_KEXINIT] = my_kexinit_handler
_transport._handler_table[MSG_NEWKEYS] = my_newkeys_handler

# --- minimal server code that uses Paramiko's server interface
class SimpleServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        # permit the user supplied in client script for demo
        if username == "testuser" and password == "testpass":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

def handle_connection(client_sock, addr):
    print("[CONN] Incoming connection from", addr)
    t = paramiko.Transport(client_sock)
    t.add_server_key(host_key)
    server = SimpleServer()
    try:
        t.start_server(server=server)
    except Exception as e:
        print("[ERR] start_server:", e)
        client_sock.close()
        return

    # accept a single session channel
    chan = t.accept(20)
    if chan is None:
        print("[ERR] No channel")
        t.close()
        return

    chan.send("Welcome to demo SSH server. Type 'exit' to close.\n".encode())
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break
            text = data.decode().strip()
            if text.lower() in ("exit", "quit"):
                chan.send(b"bye\n")
                break
            chan.send(b"Echo: " + data)
    except Exception as e:
        print("[ERR] channel handling:", e)
    finally:
        try:
            chan.close()
        except Exception:
            pass
        try:
            t.close()
        except Exception:
            pass
    print("[CONN] closed", addr)

def main():
    bind_addr = ("0.0.0.0", 2222)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind_addr)
    sock.listen(100)
    print(f"[SERVER] Listening on {bind_addr[0]}:{bind_addr[1]}. Username/password: testuser/testpass")
    while True:
        client_sock, addr = sock.accept()
        thr = threading.Thread(target=handle_connection, args=(client_sock, addr))
        thr.daemon = True
        thr.start()

if __name__ == "__main__":
    main()
