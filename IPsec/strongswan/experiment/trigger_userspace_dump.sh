#!/usr/bin/env bash
#
# trigger_userspace_dump.sh
#
# Creates a marker file that the LLDB monitoring loop will detect and trigger
# a userspace memory dump.
#
# This script is called from run_ipsec_experiment.sh menu and creates marker
# files that the LLDB keep-alive loop checks for periodically.
#
# Usage:
#   ./trigger_userspace_dump.sh <output_dir> <checkpoint_name>
#
# Arguments:
#   output_dir: Directory where LLDB is writing logs (contains .lldb_ready_* files)
#   checkpoint_name: Name for the checkpoint (e.g., "manual", "debug", etc.)
#
# Example:
#   ./trigger_userspace_dump.sh results/20251010_155313/userspace/left manual_dump
#

set -euo pipefail

# Check arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <output_dir> <checkpoint_name>" >&2
    echo "Example: $0 results/20251010_155313/userspace/left manual" >&2
    exit 1
fi

OUTPUT_DIR="$1"
CHECKPOINT_NAME="$2"

# Validate output directory exists
if [[ ! -d "$OUTPUT_DIR" ]]; then
    echo "Error: Output directory not found: $OUTPUT_DIR" >&2
    exit 1
fi

# Create marker file for dump request
MARKER_FILE="$OUTPUT_DIR/.dump_request"
TIMESTAMP=$(date +%s)

# Write dump request to marker file
cat > "$MARKER_FILE" <<EOF
checkpoint=$CHECKPOINT_NAME
timestamp=$TIMESTAMP
requested_by=trigger_userspace_dump.sh
EOF

echo "[trigger_userspace_dump] Dump request created: $MARKER_FILE"
echo "[trigger_userspace_dump] Checkpoint name: $CHECKPOINT_NAME"
echo "[trigger_userspace_dump] LLDB will process this request within 1-2 seconds"
