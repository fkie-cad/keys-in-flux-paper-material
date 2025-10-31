#!/usr/bin/env bash
# sshd_manage.sh
# Start a local OpenSSH server (test instance), list sessions, terminate sessions,
# and help trigger/test rekey behavior.
#
# Designed for local testing. Writes logs, hostkeys and dumps to the current directory.
# Usage: sudo ./sshd_manage.sh start|stop|status|list|terminate-all|rekey-new-client [args]
#
# NOTE: Forcing an immediate rekey for arbitrary *existing* sessions from outside the
#       process is NOT reliably possible without modifying OpenSSH or using an in-process
#       debugger (LLDB). See 'rekey-help' below for options.
#
set -euo pipefail

WORKDIR="${PWD}/sshd_test"
SSHD_CONF="${WORKDIR}/sshd_config"
SSHD_PID_FILE="${WORKDIR}/sshd.pid"
SSHD_LOG="${WORKDIR}/sshd.log"
SSHD_PORT="${SSHD_PORT:-2222}"         # default port (override with env var)
REKEY_LIMIT="${REKEY_LIMIT:-1M 60}"    # default RekeyLimit used in the test config
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
EXPECT_BIN="$(command -v expect || true)"

mkdir -p "$WORKDIR"

function ensure_sshd_exists() {
    if [ ! -x "$SSHD_BIN" ]; then
        echo "Error: sshd not found at $SSHD_BIN or not executable."
        echo "Install OpenSSH server (e.g. apt install openssh-server) or set SSHD_BIN env var."
        exit 1
    fi
}

function create_test_config() {
    mkdir -p "$WORKDIR"
    # generate host keys if not present
    for k in rsa ed25519 ecdsa; do
        keyfile="${WORKDIR}/ssh_host_${k}_key"
        if [ ! -f "$keyfile" ]; then
            echo "Generating hostkey $keyfile..."
            ssh-keygen -q -N '' -t "$k" -f "$keyfile" || true
        fi
    done

    cat > "$SSHD_CONF" <<EOF
# Minimal sshd_config for testing (generated)
Port ${SSHD_PORT}
ListenAddress 0.0.0.0
ListenAddress ::
PidFile ${SSHD_PID_FILE}
AuthorizedKeysFile ${WORKDIR}/authorized_keys
HostKey ${WORKDIR}/ssh_host_rsa_key
HostKey ${WORKDIR}/ssh_host_ecdsa_key
HostKey ${WORKDIR}/ssh_host_ed25519_key
UsePAM no
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
LogLevel VERBOSE
SyslogFacility AUTH
# Force strict modes off so the temp dir can be permissive
StrictModes no
# RekeyLimit: small by default for quicker rekeys in tests (env override possible)
RekeyLimit ${REKEY_LIMIT}
# Allow simple sessions
Subsystem sftp /usr/lib/openssh/sftp-server
# Do not fork (we'll launch -D), handled by script
EOF

    # create an empty authorized_keys file (optional)
    touch "${WORKDIR}/authorized_keys"
    chmod 644 "${WORKDIR}/authorized_keys"

    echo "Created config at $SSHD_CONF (port ${SSHD_PORT}, RekeyLimit=${REKEY_LIMIT})"
}

function start_sshd() {
    ensure_sshd_exists
    create_test_config

    if [ -f "$SSHD_PID_FILE" ]; then
        if pid=$(cat "$SSHD_PID_FILE" 2>/dev/null) && kill -0 "$pid" 2>/dev/null; then
            echo "sshd already running (pid $pid)."
            return 0
        else
            echo "Stale pidfile found; removing."
            rm -f "$SSHD_PID_FILE"
        fi
    fi

    echo "Starting sshd (foreground) with config $SSHD_CONF ..."
    # Launch in background but keep -D (no fork) so it remains attached to this process group
    # We'll run it with nohup so it persists if the terminal closes.
    nohup "$SSHD_BIN" -f "$SSHD_CONF" -E "$SSHD_LOG" -D >/dev/null 2>&1 &
    sleep 0.5

    # try to find pid (sshd -D spawns no child; search by pidfile or process match)
    # sshd may write pid file only when run -f with forking; since we run -D, pidfile may not be created.
    # Try to find the process by command line.
    pids=$(ps -eo pid,cmd | grep "[s]shd -f $SSHD_CONF" | awk '{print $1}')
    if [ -n "$pids" ]; then
        echo "$pids" > "$SSHD_PID_FILE"
        echo "sshd started (pid(s): $pids), log: $SSHD_LOG"
    else
        # fallback: grep for sshd process with our hostkey path as identifier
        pids=$(ps -eo pid,cmd | grep "[s]shd" | grep "$WORKDIR/ssh_host_" | awk '{print $1}' || true)
        if [ -n "$pids" ]; then
            echo "$pids" > "$SSHD_PID_FILE"
            echo "sshd started (pid(s): $pids), log: $SSHD_LOG"
        else
            echo "Failed to detect sshd process. Check $SSHD_LOG for errors."
            tail -n 50 "$SSHD_LOG" || true
            exit 1
        fi
    fi
}

function stop_sshd() {
    if [ -f "$SSHD_PID_FILE" ]; then
        pids="$(cat "$SSHD_PID_FILE")"
        for pid in $pids; do
            if kill -0 "$pid" 2>/dev/null; then
                echo "Killing sshd pid $pid ..."
                kill "$pid" || true
            fi
        done
        rm -f "$SSHD_PID_FILE"
    else
        echo "No pidfile found at $SSHD_PID_FILE; attempting to find test sshd processes..."
        pids=$(ps -eo pid,cmd | grep "[s]shd" | grep "$WORKDIR" | awk '{print $1}' || true)
        if [ -n "$pids" ]; then
            echo "Killing: $pids"
            for pid in $pids; do kill "$pid" || true; done
        else
            echo "No test sshd processes found."
        fi
    fi
    echo "Stopped."
}

function show_status() {
    if [ -f "$SSHD_PID_FILE" ]; then
        pid=$(cat "$SSHD_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "sshd (test) running with pid: $pid"
            echo "log: $SSHD_LOG"
            echo "config: $SSHD_CONF"
            return 0
        fi
    fi
    echo "No test sshd running (or pidfile missing)."
}

function list_sessions() {
    # List sshd child processes handling sessions.
    # On many systems ps shows "sshd: username@pts/X" for session procs.
    echo "Active sshd child processes (likely active sessions):"
    ps -eo pid,ppid,user,cmd --sort=pid | grep "[s]shd" | while read -r pid ppid user cmdrest; do
        # print the full cmdline
        cmdline=$(ps -p "$pid" -o cmd=)
        # try to get peer address (netstat/ss) by mapping FD to socket
        peer=""
        # discover listening fd -> skip
        echo " PID: $pid USER: $user CMD: $cmdline"
    done

    echo
    echo "You can also run: ss -tnp | grep sshd  (to map TCP sockets to pids)"
    ss -tnp | grep sshd || true
}

function terminate_all_sessions() {
    # Kill all sshd child processes except the main daemon(s)
    echo "Terminating all sshd session processes (except main master if present)..."
    # Identify processes with "sshd:" (session handlers)
    ps -eo pid,cmd | grep "[s]shd:" | awk '{print $1}' | while read -r p; do
        # don't kill the master process (sshd without ':')
        if kill -0 "$p" 2>/dev/null; then
            echo "Sending TERM to $p ..."
            kill "$p" || true
            sleep 0.2
            if kill -0 "$p" 2>/dev/null; then
                echo "Term didn't work; sending KILL to $p ..."
                kill -9 "$p" || true
            fi
        fi
    done
    echo "If you used a single-process sshd run (no forking), you may need to stop the process via stop command."
}

function rekey_new_client() {
    # This helper will create a new client connection and send client escape "~R" (capital R)
    # to force a rekey in that new client session. This is useful to exercise the rekey
    # path without needing to modify existing sessions.
    #
    # Usage: ./sshd_manage.sh rekey-new-client <user> [<password>]
    local user="${1:-root}"
    local password="${2:-}"
    local host="127.0.0.1"
    local port="${SSHD_PORT}"

    if [ -z "$EXPECT_BIN" ]; then
        echo "Expect is required for rekey-new-client helper. Install it (apt install expect) and retry."
        return 1
    fi

    # Expect script: open an interactive ssh session, wait for prompt, send "~R" (escape) to client
    # Note: the escape must be sent from the local client. Expect will emulate a terminal and send the escape.
    tmp_expect="$(mktemp)"
    cat > "$tmp_expect" <<'EOF'
#!/usr/bin/expect -f
set timeout 15
set host [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set passwd [lindex $argv 3]

# spawn ssh with -tt to force allocation of a tty so client escape handling is active
spawn -noecho ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -tt -p $port $user@$host

expect {
    -re ".*assword.*:" {
        if {$passwd != ""} {
            send -- "$passwd\r"
            exp_continue
        } else {
            # no password provided: give user a chance to type it
            interact
            exit 0
        }
    }
    -re ".*\$ | .*# | .*% | .*>" {
        # we are at shell prompt; send newline then the escape ~R
        send -- "\r"
        # Send the client escape to request rekey: "~R" must be first on a line; client processes it.
        send -- "~R\r"
        # Wait a few seconds for rekey to occur
        sleep 2
        # then exit
        send -- "exit\r"
    }
    timeout { exit 2 }
}
expect eof
EOF
    chmod +x "$tmp_expect"

    echo "Spawning a fresh ssh client to ${user}@${host}:${port} and sending client escape ~R (this will rekey that new connection)."
    if [ -n "$password" ]; then
        "$tmp_expect" "$host" "$port" "$user" "$password"
    else
        echo "No password provided: expect will wait for you to type password interactively."
        "$tmp_expect" "$host" "$port" "$user" ""
    fi
    rm -f "$tmp_expect"
}

function rekey_help() {
    cat <<EOF
REKEY OPTIONS / HELP
---------------------

1) From an interactive ssh client: type the client escape sequence:
   - At the start of a line in your interactive ssh session press:
        ~R     (tilde then capital R)
     That requests the client to initiate a rekey. Server will respond and a key exchange happens.
     (This is the simplest method for an end-user who is at the client.)

2) For testing new client connections:
   - Use the helper: ./sshd_manage.sh rekey-new-client <user> [<password>]
     This opens a new client connection and sends the "~R" client escape to trigger a rekey in that new session.

3) Forcing rekey for arbitrary existing sessions:
   - There is NO standard external command or UNIX signal that forces an existing sshd child
     (session) to perform an immediate rekey. To do that you must either:
       a) convince the client to request a rekey (client "~R"), or
       b) use an in-process debugger (LLDB) to instruct or call the server's kex routine (you already
          have an LLDB-based workflow), or
       c) modify OpenSSH source to add an admin API for rekeying, or
       d) set RekeyLimit to a very small value before the session is established (affects new sessions only)
          so rekey will happen automatically shortly after traffic flows.
EOF
}

function usage() {
    cat <<EOF
Usage: sudo $0 <command> [args...]

Commands:
  start               Create minimal config and start a test sshd on port $SSHD_PORT (override with SSHD_PORT env var)
  stop                Stop the test sshd instance(s) started by this script
  status              Show status of the test sshd
  list                List candidate sshd session processes and socket mappings
  terminate-all       Terminate all active sshd session processes (gracefully then force)
  rekey-new-client <user> [password]
                      Open a fresh ssh client to the test server and send client escape ~R to force rekey
                      (requires 'expect' on the machine where you run the client)
  rekey-help          Print rekey options & explanation (why forcing rekey on arbitrary sessions is limited)

Examples:
  sudo SSHD_PORT=2222 REKEY_LIMIT='1M 60' $0 start
  sudo $0 list
  sudo $0 terminate-all
  sudo $0 rekey-new-client root

EOF
}

# main dispatcher
if [ $# -lt 1 ]; then
    usage
    exit 1
fi

cmd="$1"; shift || true

case "$cmd" in
    start)
        start_sshd
        ;;
    stop)
        stop_sshd
        ;;
    status)
        show_status
        ;;
    list)
        list_sessions
        ;;
    terminate-all)
        terminate_all_sessions
        ;;
    "rekey-new-client")
        rekey_new_client "$@"
        ;;
    "rekey-help")
        rekey_help
        ;;
    *)
        usage
        exit 2
        ;;
esac
