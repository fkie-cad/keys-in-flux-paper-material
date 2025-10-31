#!/bin/bash
# Launch Dropbear directly under LLDB (no attach, no permission issues)

set -e

echo "======================================================================"
echo "  Dropbear with LLDB Launch (V2 Test)"
echo "======================================================================"

# Results directory
RESULTS_DIR=${LLDB_RESULTS_DIR:-/data/lldb_results}
DUMPS_DIR=${LLDB_DUMPS_DIR:-/data/dumps}

mkdir -p "$RESULTS_DIR" "$DUMPS_DIR"
chmod 777 "$RESULTS_DIR" "$DUMPS_DIR"

export SSH_SERVER_TYPE="dropbear"
export LLDB_RESULTS_DIR="$RESULTS_DIR"
export LLDB_DUMPS_DIR="$DUMPS_DIR"

echo "Starting Dropbear under LLDB with V2 test script..."
echo "Logs: $RESULTS_DIR/lldb_output.log"
echo ""

# Launch Dropbear directly with LLDB
exec lldb \
  -o "settings set target.process.follow-fork-mode child" \
  -o "settings set target.process.stop-on-exec false" \
  -o "command script import /opt/lldb/dropbear_test_minimal_v2.py" \
  -o "process launch -- -F -E -p 22" \
  > "$RESULTS_DIR/lldb_output.log" 2>&1
