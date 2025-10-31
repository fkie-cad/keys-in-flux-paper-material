#!/bin/bash
#
# SSH Lifecycle Experiment - Metadata Generator
#
# Generates JSON metadata files for experiment results containing:
#   - Implementation version and role (client/server)
#   - Timestamps (start/end/duration)
#   - Configuration flags (watchpoints, memory dumps)
#   - Host architecture and platform
#   - Results (key count, file sizes, status)
#
# Usage:
#   ./generate_experiment_metadata.sh \
#       --implementation <impl> \
#       --role <client|server> \
#       --start-time <unix_timestamp> \
#       --end-time <unix_timestamp> \
#       --results-dir <path> \
#       --status <success|failure|skip>
#

set -e

# Default values
IMPLEMENTATION=""
ROLE="client"
START_TIME=""
END_TIME=""
RESULTS_DIR=""
STATUS="success"
MODE="base"  # "base" or "ku"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --implementation)
            IMPLEMENTATION="$2"
            shift 2
            ;;
        --role)
            ROLE="$2"
            shift 2
            ;;
        --start-time)
            START_TIME="$2"
            shift 2
            ;;
        --end-time)
            END_TIME="$2"
            shift 2
            ;;
        --results-dir)
            RESULTS_DIR="$2"
            shift 2
            ;;
        --status)
            STATUS="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 --implementation <impl> --role <role> --start-time <time> --end-time <time> --results-dir <dir> --status <status> --mode <base|ku>"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "${IMPLEMENTATION}" ] || [ -z "${START_TIME}" ] || [ -z "${END_TIME}" ] || [ -z "${RESULTS_DIR}" ]; then
    echo "Error: Missing required arguments"
    echo "Required: --implementation, --start-time, --end-time, --results-dir"
    exit 1
fi

# Version mapping (hardcoded; for OpenSSH we did the experiments with )
get_version() {
    local impl=$1
    case "${impl}" in
        wolfssh)
            echo "1.4.20"
            ;;
        dropbear)
            echo "2025.88"
            ;;
        openssh)
            echo "10.2p1"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Get architecture information
ARCH=$(uname -m)
OS=$(uname -s)

# Calculate duration
DURATION=$((END_TIME - START_TIME))

# Convert Unix timestamps to ISO 8601 format
if command -v date >/dev/null 2>&1; then
    # Try GNU date format first
    START_ISO=$(date -u -d "@${START_TIME}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "${START_TIME}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
    END_ISO=$(date -u -d "@${END_TIME}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "${END_TIME}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")
else
    START_ISO=""
    END_ISO=""
fi

# Get version
VERSION=$(get_version "${IMPLEMENTATION}")

# Determine rekey status based on mode
REKEY_ENABLED="false"
if [ "${MODE}" = "ku" ]; then
    REKEY_ENABLED="true"
fi

# Configuration detection
WATCHPOINTS_ENABLED="false"
MEMORY_DUMPS_ENABLED="false"
WATCHPOINT_ENV_VAR=""

# Check per-implementation watchpoint flag
case "${IMPLEMENTATION}" in
    wolfssh)
        if [ "${LLDB_ENABLE_WATCHPOINTS_WOLFSSH}" = "true" ] || [ "${LLDB_ENABLE_WATCHPOINTS}" = "true" ]; then
            WATCHPOINTS_ENABLED="true"
            WATCHPOINT_ENV_VAR="LLDB_ENABLE_WATCHPOINTS_WOLFSSH=true"
        fi
        ;;
    dropbear)
        if [ "${LLDB_ENABLE_WATCHPOINTS_DROPBEAR}" = "true" ] || [ "${LLDB_ENABLE_WATCHPOINTS}" = "true" ]; then
            WATCHPOINTS_ENABLED="true"
            WATCHPOINT_ENV_VAR="LLDB_ENABLE_WATCHPOINTS_DROPBEAR=true"
        fi
        ;;
    openssh)
        if [ "${LLDB_ENABLE_WATCHPOINTS_OPENSSH}" = "true" ] || [ "${LLDB_ENABLE_WATCHPOINTS}" = "true" ]; then
            WATCHPOINTS_ENABLED="true"
            WATCHPOINT_ENV_VAR="LLDB_ENABLE_WATCHPOINTS_OPENSSH=true"
        fi
        ;;
esac

# Check memory dumps flag
if [ "${LLDB_ENABLE_MEMORY_DUMPS}" = "true" ]; then
    MEMORY_DUMPS_ENABLED="true"
fi

# Find keylog file in results directory
KEYLOG_FILE="${RESULTS_DIR}/${IMPLEMENTATION}_client_keylog.log"
if [ ! -f "${KEYLOG_FILE}" ]; then
    # Try alternative patterns
    KEYLOG_FILE=$(find "${RESULTS_DIR}" -name "${IMPLEMENTATION}_client_keylog*.log" -type f | head -1)
fi

# Count extracted keys
KEYS_EXTRACTED=0
KEYLOG_SIZE=0
KEYLOG_FILENAME="none"
if [ -f "${KEYLOG_FILE}" ]; then
    KEYLOG_FILENAME=$(basename "${KEYLOG_FILE}")
    KEYLOG_SIZE=$(wc -c < "${KEYLOG_FILE}" 2>/dev/null || echo "0")
    # Count CLIENT lines (key entries)
    KEYS_EXTRACTED=$(grep -c "CLIENT" "${KEYLOG_FILE}" 2>/dev/null || echo "0")
fi

# Check for timing CSV (watchpoint data)
TIMING_CSV_EXISTS="false"
TIMING_CSV_FILE="${RESULTS_DIR}/timing_${IMPLEMENTATION}.csv"
if [ ! -f "${TIMING_CSV_FILE}" ]; then
    # Check in data/lldb_results/ directory
    TIMING_CSV_FILE="./data/lldb_results/timing_${IMPLEMENTATION}.csv"
fi

if [ -f "${TIMING_CSV_FILE}" ]; then
    TIMING_CSV_EXISTS="true"
    # Copy to results directory if not already there
    cp "${TIMING_CSV_FILE}" "${RESULTS_DIR}/" 2>/dev/null || true
fi

# Generate JSON metadata
JSON_FILE="${RESULTS_DIR}/${IMPLEMENTATION}_info.json"

cat > "${JSON_FILE}" << EOF
{
  "implementation": "${IMPLEMENTATION}",
  "version": "${VERSION}",
  "role": "${ROLE}",
  "experiment_type": "${MODE}",
  "rekey_enabled": ${REKEY_ENABLED},
  "timestamp": {
    "start": "${START_ISO}",
    "end": "${END_ISO}",
    "start_unix": ${START_TIME},
    "end_unix": ${END_TIME},
    "duration_seconds": ${DURATION}
  },
  "configuration": {
    "watchpoints_enabled": ${WATCHPOINTS_ENABLED},
    "memory_dumps_enabled": ${MEMORY_DUMPS_ENABLED},
    "watchpoint_env_var": "${WATCHPOINT_ENV_VAR}"
  },
  "host": {
    "architecture": "${ARCH}",
    "uname_m": "${ARCH}",
    "uname_s": "${OS}"
  },
  "results": {
    "status": "${STATUS}",
    "keys_extracted": ${KEYS_EXTRACTED},
    "keylog_file": "${KEYLOG_FILENAME}",
    "keylog_size_bytes": ${KEYLOG_SIZE},
    "timing_csv_exists": ${TIMING_CSV_EXISTS}
  }
}
EOF

echo "[METADATA] Generated ${JSON_FILE}"
echo "[METADATA] Implementation: ${IMPLEMENTATION} ${VERSION} (${ROLE})"
echo "[METADATA] Duration: ${DURATION}s, Keys: ${KEYS_EXTRACTED}, Status: ${STATUS}"
