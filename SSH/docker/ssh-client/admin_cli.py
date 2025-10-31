#!/usr/bin/env python3
"""
admin_cli.py - Manage SSH sessions started from this container.

Usage:
  ssh-admin connect --host HOST [--port PORT] [--user USER] [--password PASS] [--id ID]
  ssh-admin list
  ssh-admin rekey [ID|all]
  ssh-admin terminate [ID|all]
  ssh-admin attach ID   # tail session log
  ssh-admin keylog [--tail] [--count N]  # view exported keys
  ssh-admin cleanup     # remove stale metadata

Implementation:
- Each 'connect' starts an expect-based ssh wrapper in background using nohup.
- Control commands (REKEY, TERMINATE) are delivered via a FIFO per-session.
- Metadata persisted at /data/dumps/sessions.json
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

DATA_DUMPS = Path(os.environ.get("DUMP_DIR", "/data/dumps"))
KEYLOG_DIR = Path(os.environ.get("KEYLOG_DIR", "/data/keylogs"))
SESSIONS_FILE = DATA_DUMPS / "sessions.json"
KEYLOG_FILE = KEYLOG_DIR / "ssh_keylog.log"

# Ensure directories exist
DATA_DUMPS.mkdir(parents=True, exist_ok=True)
KEYLOG_DIR.mkdir(parents=True, exist_ok=True)

def load_sessions():
    if SESSIONS_FILE.exists():
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_sessions(sessions):
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))

def gen_id():
    return uuid.uuid4().hex[:8]

def ensure_expect_available():
    if shutil.which("expect") is None:
        print("Error: 'expect' binary not found. Install 'expect' in the container.", file=sys.stderr)
        sys.exit(1)

def make_expect_script(tmpfile_path, host, port, user, password, fifo_path, log_path):
    """
    Create an expect script that:
    - spawns ssh -tt user@host -p port
    - opens fifo_path for reading commands; when it reads a line:
        - if line == "REKEY": send "~R\r"
        - if line == "TERMINATE": send "~.\r" then exit
        - else: send the full line to the ssh session (so you can type commands)
    - logs ssh output to log_path
    """
    # The expect script uses blocking open on the FIFO which is created by admin_cli
    script = f"""#!/usr/bin/expect -f
# Generated expect wrapper
log_user 1
log_file -a "{log_path}"
set timeout -1

set host "{host}"
set port "{port}"
set user "{user}"
set password "{password}"
set fifo "{fifo_path}"

# spawn ssh
spawn -noecho ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -tt -p $port $user@$host

# handle password prompt
# We use a background thread to listen to fifo commands and send them to child
# Create the fifo if it doesn't exist (the Python caller creates it normally)
if { [file exists $fifo] } {
    set fp [open $fifo r]
} else {
    # open non-blocking fallback
    set fp [open $fifo r+]
}

# If password is non-empty we handle it when asked
if {$password != ""} {
    expect {
        -re "(?i)password: " {
            send -- "$password\r"
        }
        -re "Are you sure you want to continue connecting" {
            send -- "yes\r"
            exp_continue
        }
        timeout { }
        eof { }
        -re "\\$|#|>" {}
    } -timeout 2
}

# Now main I/O loop: read fifo lines (non-blocking) and pass them to ssh.
# Also forward interactive input to the session (so the session is still interactive if attached)
# but since this is background wrapper, we primarily respond to fifo entries
while {1} {
    # read available line from fifo (blocking read)
    set line [gets $fp]
    if {$line >= 0} {
        # line is the content read; strip trailing newline
        set cmd $::expect_out(buffer)
        # map control commands
        if {$cmd == "REKEY"} {
            # client-side escape to request rekey
            send -- "~R\r"
        } elseif {$cmd == "TERMINATE"} {
            send -- "~.\r"
            # allow SSH to close gracefully
            sleep 1
            exit 0
        } else {
            # send raw content to ssh (use carriage return)
            send -- "$cmd\r"
        }
    } else {
        # no available data, sleep shortly
        sleep 0.1
    }
}
"""
    tmpfile_path.write_text(script)
    tmpfile_path.chmod(0o755)

def start_session(host, port, user, password, id_hint=None):
    ensure_expect_available()
    sid = id_hint or gen_id()
    fifo = DATA_DUMPS / f"session_{sid}.ctl"
    log = DATA_DUMPS / f"session_{sid}.log"
    # create fifo
    try:
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(str(fifo), 0o600)
    except Exception as e:
        print(f"[WARN] Failed to create FIFO {fifo}: {e}", file=sys.stderr)
    # write expect wrapper to temp file
    tmp = Path(tempfile.gettempdir()) / f"ssh_admin_{sid}.exp"
    make_expect_script(tmp, host, port, user, password or "", fifo, log)
    # start expect with nohup so it survives our parent process exit
    # redirect stdout/stderr to the log; expect already appends to log via log_file
    cmd = ["nohup", str(tmp), ">", str(log), "2>&1", "&"]
    # Use shell because we used redirections above
    shell_cmd = f"nohup {str(tmp)} >/dev/null 2>&1 & echo $!"
    try:
        pid = int(subprocess.check_output(shell_cmd, shell=True).decode().strip())
    except Exception as e:
        print("Failed to spawn expect wrapper:", e)
        return None

    # persist session metadata
    sessions = load_sessions()
    sessions[sid] = {
        "id": sid,
        "host": host,
        "port": port,
        "user": user,
        "fifo": str(fifo),
        "log": str(log),
        "pid": pid,
        "started_at": int(time.time())
    }
    save_sessions(sessions)
    print(f"Started session id={sid} pid={pid} host={host}:{port} user={user} log={log}")
    return sid

def list_sessions():
    sessions = load_sessions()
    if not sessions:
        print("No sessions tracked.")
        return
    print("Tracked sessions:")
    for sid, info in sessions.items():
        pid = info.get("pid")
        alive = False
        try:
            if pid and int(pid):
                os.kill(int(pid), 0)
                alive = True
        except Exception:
            alive = False
        print(f" - {sid}: {info['user']}@{info['host']}:{info['port']} pid={pid} alive={alive} log={info.get('log')} fifo={info.get('fifo')}")

def write_to_fifo(fifo_path, message):
    try:
        with open(fifo_path, "w") as f:
            f.write(message + "\n")
        return True
    except Exception as e:
        print(f"Failed to write to fifo {fifo_path}: {e}", file=sys.stderr)
        return False

def rekey_target(sid):
    sessions = load_sessions()
    if sid not in sessions:
        print(f"No such session {sid}")
        return
    info = sessions[sid]
    fifo = info.get("fifo")
    if not fifo:
        print(f"No fifo for session {sid}")
        return
    ok = write_to_fifo(fifo, "REKEY")
    print(f"Rekey for {sid} -> {'ok' if ok else 'failed'}")

def terminate_target(sid):
    sessions = load_sessions()
    if sid not in sessions:
        print(f"No such session {sid}")
        return
    info = sessions[sid]
    fifo = info.get("fifo")
    pid = info.get("pid")
    if fifo:
        write_to_fifo(fifo, "TERMINATE")
        # Give it a moment to close gracefully
        time.sleep(0.5)
    # If still alive, kill
    try:
        if pid:
            os.kill(int(pid), signal.SIGTERM)
            time.sleep(0.2)
            os.kill(int(pid), 0)
            # still alive? force kill
            os.kill(int(pid), signal.SIGKILL)
    except Exception:
        pass
    # remove metadata
    sessions.pop(sid, None)
    save_sessions(sessions)
    print(f"Terminated session {sid}")

def attach_log(sid):
    sessions = load_sessions()
    if sid not in sessions:
        print(f"No such session {sid}")
        return
    log = sessions[sid].get("log")
    if not log:
        print("No log path found")
        return
    try:
        print(f"== tail -f {log} (press Ctrl-C to exit) ==")
        subprocess.run(["tail", "-f", log])
    except KeyboardInterrupt:
        pass

def cleanup_sessions():
    # Remove sessions whose process no longer exists, cleanup FIFOs
    sessions = load_sessions()
    changed = False
    for sid, info in list(sessions.items()):
        pid = info.get("pid")
        alive = False
        try:
            if pid:
                os.kill(int(pid), 0)
                alive = True
        except Exception:
            alive = False
        if not alive:
            fifo = info.get("fifo")
            try:
                if fifo and os.path.exists(fifo):
                    os.unlink(fifo)
            except Exception:
                pass
            sessions.pop(sid, None)
            changed = True
    if changed:
        save_sessions(sessions)
    print("Cleanup completed.")

def view_keylog(tail_mode=False, count=None):
    """
    View exported SSH keys from SSHKEYLOGFILE.
    Supports both Paramiko format and openssh-standalone format.
    """
    if not KEYLOG_FILE.exists():
        print(f"Keylog file not found: {KEYLOG_FILE}")
        print("No keys have been exported yet.")
        return

    try:
        if tail_mode:
            # Live tail mode
            print(f"== Tailing keylog (press Ctrl-C to exit) ==")
            print(f"== File: {KEYLOG_FILE} ==\n")
            subprocess.run(["tail", "-f", str(KEYLOG_FILE)])
        else:
            # Read and display mode
            with open(KEYLOG_FILE, "r") as f:
                lines = f.readlines()

            if not lines:
                print("Keylog file is empty.")
                return

            # Show last N lines if count specified
            if count:
                lines = lines[-count:]

            print(f"== SSH Keylog Entries ==")
            print(f"== File: {KEYLOG_FILE} ==")
            print(f"== Total entries: {len(lines)} ==\n")

            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue

                # Parse different keylog formats
                parts = line.split()
                if len(parts) >= 3:
                    # Try to identify format
                    if "SHARED_SECRET" in line:
                        # Paramiko format: <cookie_hex> SHARED_SECRET <K_hex>
                        cookie = parts[0]
                        k_hex = parts[2] if len(parts) > 2 else "unknown"
                        print(f"[{i}] Paramiko Format")
                        print(f"     Cookie: {cookie[:32]}...")
                        print(f"     Shared Secret: {k_hex[:64]}...")
                    elif "NEWKEYS" in line:
                        # openssh-standalone format: <ts> NEWKEYS MODE <in|out> CIPHER <cipher> KEY <key> IV <iv>
                        timestamp = parts[0]
                        mode = parts[3] if len(parts) > 3 else "unknown"
                        cipher = parts[5] if len(parts) > 5 else "unknown"
                        key_idx = line.find("KEY ") + 4
                        iv_idx = line.find(" IV ")
                        key = line[key_idx:iv_idx].strip() if iv_idx > 0 else "unknown"
                        iv = parts[-1] if "IV" in line else "unknown"
                        print(f"[{i}] OpenSSH-Standalone NEWKEYS")
                        print(f"     Timestamp: {timestamp}")
                        print(f"     Mode: {mode}")
                        print(f"     Cipher: {cipher}")
                        print(f"     Key: {key[:64]}...")
                        print(f"     IV: {iv[:32]}...")
                    elif "COOKIE" in line:
                        # openssh-standalone format: <ts> COOKIE <cookie> CIPHER_IN <cipher> CIPHER_OUT <cipher> SESSION_ID <sid>
                        timestamp = parts[0]
                        cookie = parts[2] if len(parts) > 2 else "unknown"
                        cipher_in = parts[4] if len(parts) > 4 else "unknown"
                        cipher_out = parts[6] if len(parts) > 6 else "unknown"
                        session_id = parts[-1] if "SESSION_ID" in line else "unknown"
                        print(f"[{i}] OpenSSH-Standalone KEX")
                        print(f"     Timestamp: {timestamp}")
                        print(f"     Cookie: {cookie[:32]}...")
                        print(f"     Cipher IN: {cipher_in}")
                        print(f"     Cipher OUT: {cipher_out}")
                        print(f"     Session ID: {session_id[:32]}...")
                    else:
                        # Unknown format, print raw
                        print(f"[{i}] {line[:100]}...")
                    print()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error reading keylog: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(prog="ssh-admin")
    sub = parser.add_subparsers(dest="cmd")

    p_connect = sub.add_parser("connect", help="Start a new SSH session")
    p_connect.add_argument("--host", required=True)
    p_connect.add_argument("--port", default="22")
    p_connect.add_argument("--user", default=os.environ.get("USER", "root"))
    p_connect.add_argument("--password", default="")
    p_connect.add_argument("--id", default=None)

    sub.add_parser("list", help="List active sessions")

    p_rekey = sub.add_parser("rekey", help="Trigger rekey on session(s)")
    p_rekey.add_argument("target", nargs="?", default="all")

    p_term = sub.add_parser("terminate", help="Terminate session(s)")
    p_term.add_argument("target", nargs="?", default="all")

    p_attach = sub.add_parser("attach", help="Tail session log")
    p_attach.add_argument("id")

    p_keylog = sub.add_parser("keylog", help="View exported SSH keys")
    p_keylog.add_argument("--tail", action="store_true", help="Live tail mode")
    p_keylog.add_argument("--count", "-n", type=int, help="Show last N entries")

    sub.add_parser("cleanup", help="Cleanup stale sessions")

    args = parser.parse_args()
    if args.cmd == "connect":
        start_session(args.host, args.port, args.user, args.password, args.id)
    elif args.cmd == "list":
        list_sessions()
    elif args.cmd == "rekey":
        target = args.target
        if target == "all":
            for sid in list(load_sessions().keys()):
                rekey_target(sid)
        else:
            rekey_target(target)
    elif args.cmd == "terminate":
        target = args.target
        if target == "all":
            for sid in list(load_sessions().keys()):
                terminate_target(sid)
        else:
            terminate_target(target)
    elif args.cmd == "attach":
        attach_log(args.id)
    elif args.cmd == "keylog":
        view_keylog(tail_mode=args.tail, count=args.count)
    elif args.cmd == "cleanup":
        cleanup_sessions()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
