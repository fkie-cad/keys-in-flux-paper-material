#!/bin/bash
# OpenSSH LD_PRELOAD Entrypoint - Non-invasive Key Extraction
#
# Hooks into OpenSSH key derivation without LLDB/ptrace
# Memory dumps at 7 critical lifecycle events:
#   1. Before KEX
#   2. After KEX
#   3. Before rekey
#   4. After rekey
#   5. Fork (parent + child)
#   6. Before session close
#   7. After session close

set -e

echo "======================================================================"
echo "  OpenSSH with LD_PRELOAD Key Extraction"
echo "======================================================================"
echo ""

# Configuration
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}
KEYLOG_FILE=${LLDB_KEYLOG:-/data/keylogs/ssh_keylog.log}
EVENTS_FILE=${DUMPS_DIR}/openssh_events.jsonl
ENABLE_DUMPS=${LLDB_ENABLE_MEMORY_DUMPS:-true}

# Create directories
mkdir -p "$RESULTS_DIR" "$DUMPS_DIR" /data/keylogs /data/captures
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR" /data/keylogs /data/captures

# Set LD_PRELOAD environment variables
export HOOK_KEYLOG="$KEYLOG_FILE"
export HOOK_EVENTS="$EVENTS_FILE"
export HOOK_DUMPS="$DUMPS_DIR"

if [ "$ENABLE_DUMPS" = "false" ]; then
    export HOOK_ENABLE_DUMPS=0
    echo "  Memory dumps: DISABLED"
else
    export HOOK_ENABLE_DUMPS=1
    echo "  Memory dumps: ENABLED"
fi

export LD_PRELOAD="/opt/hooks/libssh_kex_hook.so"

echo "Configuration:"
echo "  LD_PRELOAD:   $LD_PRELOAD"
echo "  Keylog:       $HOOK_KEYLOG"
echo "  Events:       $HOOK_EVENTS"
echo "  Dumps:        $HOOK_DUMPS"
echo ""

# Verify library exists
if [ ! -f "$LD_PRELOAD" ]; then
    echo "ERROR: LD_PRELOAD library not found: $LD_PRELOAD"
    exit 1
fi

echo "Starting OpenSSH with LD_PRELOAD..."
echo "======================================================================"
echo ""

# Start sshd with LD_PRELOAD
exec /usr/sbin/sshd -D -e
