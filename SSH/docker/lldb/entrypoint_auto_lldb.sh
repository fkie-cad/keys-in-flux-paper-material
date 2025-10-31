#!/usr/bin/env bash
set -euo pipefail

# Start Dropbear in background with stderr logging (-E) and foreground mode (-F)
# Using -w to disallow root logins by password; adjust as needed.
dropbear -E -F -p 22 -r /etc/dropbear/dropbear_rsa_host_key \
  -r /etc/dropbear/dropbear_ecdsa_host_key -r /etc/dropbear/dropbear_ed25519_host_key \
  -w 2>&1 | tee -a "${LLDB_RESULTS_DIR}/dropbear.log" &
DB_PID=$!

# Give the server a moment
sleep 0.5

# Headless LLDB that waits to attach to the pre-auth child on first connection.
# It loads your helper commands, sets follow-fork, plants the usual accept/fork bps,
# and then waits for a process named 'dropbear'.
# Keep the session alive to be able to 'docker exec -it' and interact if you like.
lldb -b \
  -o "command script import /opt/lldb/dropbear_dbg.py" \
  -o "followfork child" \
  -o "br-fork" \
  -o "waitattach dropbear" \
  2>&1 | tee -a "${LLDB_RESULTS_DIR}/lldb.log" &

# Keep container alive; tail both logs
wait -n "$DB_PID"
