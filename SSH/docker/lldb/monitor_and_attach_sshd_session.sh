#!/bin/bash
# Monitor for sshd-session processes and attach LLDB immediately
# Key insight: KEX happens BEFORE password, so we must attach during initial handshake

RESULTS_DIR="${LLDB_RESULTS_DIR:-/data/lldb_results}"
MONITORED_PIDS="/tmp/monitored_pids.txt"
touch "$MONITORED_PIDS"

log() {
    echo "[$(date +%H:%M:%S)] $*" | tee -a "$RESULTS_DIR/monitor.log"
}

log "========================================="
log "sshd-session Monitor Started"
log "========================================="

while true; do
    # Find all sshd-session processes
    pgrep -x "sshd-session" | while read PID; do
        # Skip if already monitored
        if grep -q "^${PID}$" "$MONITORED_PIDS"; then
            continue
        fi
        
        log "⚡ NEW sshd-session detected: PID $PID"
        echo "$PID" >> "$MONITORED_PIDS"
        
        # Attach LLDB immediately (in background)
        (
            log "  Attaching LLDB to PID $PID..."
            lldb \
                -o "process attach --pid $PID" \
                -o "breakpoint set --name kex_derive_keys" \
                -o "breakpoint command add 1 -s python -o \"exec(open('/opt/lldb/kex_extract.py').read())\"" \
                -o "continue" \
                > "$RESULTS_DIR/lldb_session_${PID}.log" 2>&1 &

            log "  ✓ LLDB attached to PID $PID"
        ) &
    done
    
    sleep 0.1  # Check every 100ms for new processes
done
