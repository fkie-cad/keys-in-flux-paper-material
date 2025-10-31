#!/usr/bin/env python3
"""
Paramiko SSH server - simplified for compatibility with Paramiko 3.5+

This version provides a working SSH server without attempting to hook into
internal Paramiko APIs that have changed. For key extraction, use the
openssh_groundtruth client which has built-in SSHKEYLOGFILE support.

Also exposes a simple UNIX admin socket at /data/dumps/paramiko_admin.sock
that accepts commands: LIST, TERMINATE, SHUTDOWN
"""
import os
import sys
import socket
import threading
import time
from pathlib import Path

import paramiko

DATA_KEYLOGS = Path(os.environ.get("KEYLOG_DIR", "/data/keylogs"))
DATA_DUMPS = Path(os.environ.get("DUMP_DIR", "/data/dumps"))
ADMIN_SOCK = DATA_DUMPS / "paramiko_admin.sock"

DATA_KEYLOGS.mkdir(parents=True, exist_ok=True)
DATA_DUMPS.mkdir(parents=True, exist_ok=True)

# Track active transports
ACTIVE_TRANSPORTS = set()
ACTIVE_TRANSPORTS_LOCK = threading.Lock()

# --- Paramiko server bootstrap ---
HOST_KEY_FILE = "/tmp/ssh_host_rsa_key"
if not os.path.exists(HOST_KEY_FILE):
    # generate ephemeral host key
    print("[INIT] Generating host key...")
    k = paramiko.RSAKey.generate(2048)
    k.write_private_key_file(HOST_KEY_FILE)
host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)

class SimpleServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.username = None

    def check_auth_password(self, username, password):
        # accept testuser/password for lab testing
        if username == "testuser" and password == "password":
            self.username = username
            print(f"[AUTH] Authenticated user: {username}")
            return paramiko.AUTH_SUCCESSFUL
        print(f"[AUTH] Failed authentication for: {username}")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        # Allow command execution
        self.event.set()
        return True

def handle_connection(client_sock, addr):
    """Handle a single SSH connection"""
    print(f"[CONN] New connection from {addr}")
    t = None
    try:
        t = paramiko.Transport(client_sock)
        t.add_server_key(host_key)

        with ACTIVE_TRANSPORTS_LOCK:
            ACTIVE_TRANSPORTS.add(t)

        server = SimpleServer()
        t.start_server(server=server)

        # Wait for channel
        chan = t.accept(20)
        if chan is None:
            print("[CONN] No channel opened, closing")
            return

        print(f"[CONN] Channel opened, authenticated as {server.username}")

        # Simple echo server or command execution
        server.event.wait(10)
        if not server.event.is_set():
            chan.close()
            return

        # Handle shell or exec
        try:
            # Send welcome message
            chan.send(b"Welcome to Paramiko SSH Server\r\n")
            chan.send(b"Type 'exit' to close connection\r\n")
            chan.send(b"$ ")

            buf = b""
            while True:
                r = chan.recv(1024)
                if len(r) == 0:
                    break

                buf += r
                if b"\n" in buf or b"\r" in buf:
                    line = buf.replace(b"\r", b"").replace(b"\n", b"").strip()
                    buf = b""

                    if not line:
                        chan.send(b"$ ")
                        continue

                    cmd = line.decode('utf-8', errors='ignore')
                    print(f"[CMD] Received: {cmd}")

                    if cmd.lower() in ("exit", "quit"):
                        chan.send(b"Goodbye!\r\n")
                        break
                    elif cmd == "hostname":
                        import socket as sock
                        chan.send(sock.gethostname().encode() + b"\r\n")
                    elif cmd == "pwd":
                        chan.send(b"/home/testuser\r\n")
                    else:
                        chan.send(f"Echo: {cmd}\r\n".encode())

                    chan.send(b"$ ")
        except Exception as e:
            print(f"[CONN] Channel error: {e}")

        chan.close()
        print("[CONN] Channel closed")

    except Exception as e:
        print(f"[CONN] Connection error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if t:
            try:
                t.close()
            except Exception:
                pass
            with ACTIVE_TRANSPORTS_LOCK:
                ACTIVE_TRANSPORTS.discard(t)
        print(f"[CONN] Connection closed: {addr}")

def admin_socket_worker():
    """Simple UNIX socket admin interface"""
    if ADMIN_SOCK.exists():
        ADMIN_SOCK.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(ADMIN_SOCK))
    srv.listen(5)
    print(f"[ADMIN] Listening on {ADMIN_SOCK}")

    while True:
        try:
            conn, _ = srv.accept()
            data = conn.recv(1024).decode().strip().upper()

            if data == "LIST":
                with ACTIVE_TRANSPORTS_LOCK:
                    count = len(ACTIVE_TRANSPORTS)
                response = f"Active transports: {count}\n"
                conn.sendall(response.encode())

            elif data == "TERMINATE":
                with ACTIVE_TRANSPORTS_LOCK:
                    for t in list(ACTIVE_TRANSPORTS):
                        try:
                            t.close()
                        except Exception:
                            pass
                    ACTIVE_TRANSPORTS.clear()
                conn.sendall(b"All transports terminated\n")

            elif data == "SHUTDOWN":
                conn.sendall(b"Shutting down...\n")
                conn.close()
                srv.close()
                os._exit(0)

            else:
                conn.sendall(f"Unknown command: {data}\n".encode())

            conn.close()
        except Exception as e:
            print(f"[ADMIN] Error: {e}")

def main():
    print("[INIT] Starting Paramiko SSH Server")
    print(f"[INIT] Keylogs: {DATA_KEYLOGS}")
    print(f"[INIT] Dumps: {DATA_DUMPS}")

    # Start admin socket in background
    admin_thread = threading.Thread(target=admin_socket_worker, daemon=True)
    admin_thread.start()

    # Main SSH server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", 22))
    server_sock.listen(10)

    print("[INIT] SSH Server listening on 0.0.0.0:22")

    while True:
        try:
            client, addr = server_sock.accept()
            # Handle each connection in a new thread
            t = threading.Thread(target=handle_connection, args=(client, addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            print("\n[INIT] Shutting down...")
            break
        except Exception as e:
            print(f"[INIT] Accept error: {e}")

if __name__ == "__main__":
    main()
