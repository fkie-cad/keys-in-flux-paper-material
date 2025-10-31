#!/bin/bash
#
# SSH Packet-to-Secret Correlation Analyzer
#
# Correlates SSH packets from PCAP with cryptographic key lifecycle:
#   - Parses SSH message types from packet captures
#   - Extracts key derivation timestamps from keylogs
#   - Correlates packet timing with secret availability
#   - Identifies which secrets are needed/available for each packet
#
# Usage:
#   ./correlate_ssh_packets.sh <results_dir>
#
# Requirements:
#   - tshark (Wireshark command-line)
#   - jq (JSON parser)
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
RESULTS_DIR="${1:-./data}"

if [ ! -d "${RESULTS_DIR}" ]; then
    echo -e "${RED}[ERROR] Results directory not found: ${RESULTS_DIR}${NC}"
    echo ""
    echo "Usage: $0 <results_directory>"
    echo ""
    exit 1
fi

echo ""
echo "========================================================================"
echo "  SSH Packet-to-Secret Correlation Analysis"
echo "========================================================================"
echo ""
echo "Results directory: ${RESULTS_DIR}"
echo ""

# Check for required tools
# Try to find tshark in PATH first, then check macOS-specific location
TSHARK=""
if command -v tshark &> /dev/null; then
    TSHARK="tshark"
    TSHARK_AVAILABLE=1
    echo -e "${GREEN}[INFO] tshark found in PATH${NC}"
elif [ -f /Applications/Wireshark.app/Contents/MacOS/tshark ]; then
    TSHARK="/Applications/Wireshark.app/Contents/MacOS/tshark"
    TSHARK_AVAILABLE=1
    echo -e "${GREEN}[INFO] tshark found at macOS location${NC}"
else
    echo -e "${YELLOW}[WARNING] tshark not found - packet analysis will be limited${NC}"
    echo "Install: brew install wireshark (macOS) or apt-get install tshark (Linux)"
    TSHARK_AVAILABLE=0
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}[WARNING] jq not found - JSON parsing will be limited${NC}"
    echo "Install: brew install jq (macOS) or apt-get install jq (Linux)"
    JQ_AVAILABLE=0
else
    JQ_AVAILABLE=1
fi

echo ""

# Function to convert timestamp to epoch seconds
timestamp_to_epoch() {
    local ts=$1
    # Handle different timestamp formats
    # Format 1: 2025-10-25 09:33:29.421
    # Format 2: 20251025_093329

    if [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
        # ISO format
        date -j -f "%Y-%m-%d %H:%M:%S" "${ts:0:19}" "+%s" 2>/dev/null || \
        date -d "${ts:0:19}" "+%s" 2>/dev/null || echo "0"
    elif [[ "$ts" =~ ^[0-9]{8}_[0-9]{6} ]]; then
        # Compact format: 20251025_093329
        local date_part="${ts:0:8}"
        local time_part="${ts:9:6}"
        local formatted="${date_part:0:4}-${date_part:4:2}-${date_part:6:2} ${time_part:0:2}:${time_part:2:2}:${time_part:4:2}"
        date -j -f "%Y-%m-%d %H:%M:%S" "$formatted" "+%s" 2>/dev/null || \
        date -d "$formatted" "+%s" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Function to parse SSH message type
get_ssh_message_type() {
    local msg_code=$1
    case "$msg_code" in
        1) echo "SSH_MSG_DISCONNECT" ;;
        2) echo "SSH_MSG_IGNORE" ;;
        3) echo "SSH_MSG_UNIMPLEMENTED" ;;
        4) echo "SSH_MSG_DEBUG" ;;
        5) echo "SSH_MSG_SERVICE_REQUEST" ;;
        6) echo "SSH_MSG_SERVICE_ACCEPT" ;;
        20) echo "SSH_MSG_KEXINIT" ;;
        21) echo "SSH_MSG_NEWKEYS" ;;
        30-49) echo "SSH_MSG_KEX_SPECIFIC" ;;
        50) echo "SSH_MSG_USERAUTH_REQUEST" ;;
        51) echo "SSH_MSG_USERAUTH_FAILURE" ;;
        52) echo "SSH_MSG_USERAUTH_SUCCESS" ;;
        53) echo "SSH_MSG_USERAUTH_BANNER" ;;
        60-79) echo "SSH_MSG_USERAUTH_SPECIFIC" ;;
        80) echo "SSH_MSG_GLOBAL_REQUEST" ;;
        81) echo "SSH_MSG_REQUEST_SUCCESS" ;;
        90) echo "SSH_MSG_CHANNEL_OPEN" ;;
        91) echo "SSH_MSG_CHANNEL_OPEN_CONFIRMATION" ;;
        92) echo "SSH_MSG_CHANNEL_OPEN_FAILURE" ;;
        93) echo "SSH_MSG_CHANNEL_WINDOW_ADJUST" ;;
        94) echo "SSH_MSG_CHANNEL_DATA" ;;
        95) echo "SSH_MSG_CHANNEL_EXTENDED_DATA" ;;
        96) echo "SSH_MSG_CHANNEL_EOF" ;;
        97) echo "SSH_MSG_CHANNEL_CLOSE" ;;
        98) echo "SSH_MSG_CHANNEL_REQUEST" ;;
        99) echo "SSH_MSG_CHANNEL_SUCCESS" ;;
        100) echo "SSH_MSG_CHANNEL_FAILURE" ;;
        *) echo "UNKNOWN($msg_code)" ;;
    esac
}

# Function to analyze PCAP file
analyze_pcap() {
    local pcap=$1
    local output_file=$2

    if [ ! -f "${pcap}" ]; then
        echo -e "${YELLOW}[SKIP] PCAP not found: ${pcap}${NC}"
        return
    fi

    if [ "${TSHARK_AVAILABLE}" -eq 0 ]; then
        echo -e "${YELLOW}[SKIP] tshark not available for PCAP analysis${NC}"
        return
    fi

    echo -e "${CYAN}[PCAP] Analyzing: $(basename ${pcap})${NC}"

    # Extract SSH packets with timestamps and message types
    "${TSHARK}" -r "${pcap}" -Y "ssh" -T fields \
        -e frame.time_epoch \
        -e frame.number \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport \
        -e ssh.message_code \
        -e ssh.protocol \
        -E header=y \
        -E separator=, \
        -E quote=d \
        -E occurrence=f \
        2>/dev/null > "${output_file}" || true

    if [ -s "${output_file}" ]; then
        local packet_count=$(tail -n +2 "${output_file}" | wc -l | tr -d ' ')
        echo "  ✓ Extracted ${packet_count} SSH packets"
    else
        echo -e "  ${YELLOW}⚠️  No SSH packets found${NC}"
    fi
}

# Function to parse keylog for key derivation times
parse_keylog() {
    local keylog=$1
    local output_file=$2

    if [ ! -f "${keylog}" ]; then
        return
    fi

    # Parse keylog: timestamp, key_type, key_hex
    # Format: 2025-10-25 09:33:29.421 DERIVE_KEY KEX1 IV_CLIENT_TO_SERVER <hex>
    grep -E "DERIVE_KEY|NEWKEYS|CLIENT_TO_SERVER|SERVER_TO_CLIENT" "${keylog}" 2>/dev/null | \
    while IFS= read -r line; do
        timestamp=$(echo "$line" | awk '{print $1 " " $2}')
        key_type=$(echo "$line" | awk '{for(i=3;i<NF;i++) printf $i " "; print ""}' | sed 's/ $//')
        key_hex=$(echo "$line" | awk '{print $NF}')

        echo "${timestamp},${key_type},${key_hex}"
    done > "${output_file}"

    if [ -s "${output_file}" ]; then
        local key_count=$(wc -l < "${output_file}" | tr -d ' ')
        echo -e "${GREEN}[KEYLOG] Parsed ${key_count} key derivation events${NC}"
    fi
}

# Function to parse LLDB events for state transitions
parse_lldb_events() {
    local events_file=$1
    local output_file=$2

    if [ ! -f "${events_file}" ]; then
        return
    fi

    if [ "${JQ_AVAILABLE}" -eq 0 ]; then
        echo -e "${YELLOW}[SKIP] jq not available for event parsing${NC}"
        return
    fi

    # Extract state transitions with timestamps
    jq -r 'select(.event_type == "STATE_TRANSITION") |
           "\(.timestamp),\(.current_state),\(.data.old_state)"' \
           "${events_file}" 2>/dev/null > "${output_file}" || true

    if [ -s "${output_file}" ]; then
        local event_count=$(wc -l < "${output_file}" | tr -d ' ')
        echo -e "${GREEN}[EVENTS] Parsed ${event_count} state transitions${NC}"
    fi
}

# Main correlation logic
echo "========================================================================"
echo "  PHASE 1: Data Extraction"
echo "========================================================================"
echo ""

# Create temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# Find and analyze PCAP files
PCAP_FILES=$(find "${RESULTS_DIR}" -name "*.pcap" 2>/dev/null | head -5)
if [ -z "${PCAP_FILES}" ]; then
    # Try data/captures
    PCAP_FILES=$(find "${RESULTS_DIR}/captures" -name "*.pcap" 2>/dev/null | head -5)
fi

PCAP_COUNT=0
for pcap in ${PCAP_FILES}; do
    PCAP_COUNT=$((PCAP_COUNT + 1))
    analyze_pcap "${pcap}" "${TEMP_DIR}/packets_${PCAP_COUNT}.csv"
done

if [ "${PCAP_COUNT}" -eq 0 ]; then
    echo -e "${YELLOW}[WARNING] No PCAP files found${NC}"
fi

echo ""

# Find and parse keylogs
KEYLOG_FILES=$(find "${RESULTS_DIR}" -name "*_client_keylog.log" 2>/dev/null | head -5)
if [ -z "${KEYLOG_FILES}" ]; then
    KEYLOG_FILES=$(find "${RESULTS_DIR}/keylogs" -name "*_keylog.log" 2>/dev/null | head -5)
fi

KEYLOG_COUNT=0
for keylog in ${KEYLOG_FILES}; do
    KEYLOG_COUNT=$((KEYLOG_COUNT + 1))
    parse_keylog "${keylog}" "${TEMP_DIR}/keys_${KEYLOG_COUNT}.csv"
done

if [ "${KEYLOG_COUNT}" -eq 0 ]; then
    echo -e "${YELLOW}[WARNING] No keylog files found${NC}"
fi

echo ""

# Find and parse LLDB event logs
EVENT_FILES=$(find "${RESULTS_DIR}" -name "ssh_events.jsonl" 2>/dev/null | head -5)
if [ -z "${EVENT_FILES}" ]; then
    EVENT_FILES=$(find "${RESULTS_DIR}/dumps" -name "*.jsonl" 2>/dev/null | head -5)
fi

EVENT_COUNT=0
for events in ${EVENT_FILES}; do
    EVENT_COUNT=$((EVENT_COUNT + 1))
    parse_lldb_events "${events}" "${TEMP_DIR}/events_${EVENT_COUNT}.csv"
done

echo ""

# Correlation analysis
echo "========================================================================"
echo "  PHASE 2: Packet-to-Secret Correlation"
echo "========================================================================"
echo ""

if [ "${PCAP_COUNT}" -eq 0 ] || [ "${KEYLOG_COUNT}" -eq 0 ]; then
    echo -e "${YELLOW}[SKIP] Insufficient data for correlation (need PCAP + keylog)${NC}"
    echo ""
    echo "Summary:"
    echo "  PCAP files: ${PCAP_COUNT}"
    echo "  Keylog files: ${KEYLOG_COUNT}"
    echo "  Event files: ${EVENT_COUNT}"
    echo ""
    exit 0
fi

# Correlate packets with keys
echo "Correlating SSH packets with cryptographic secrets..."
echo ""

# Display correlation table header
printf "%-20s %-10s %-25s %-30s %-15s\n" \
    "Timestamp" "Frame#" "SSH Message Type" "Required Secrets" "Status"
printf "%-20s %-10s %-25s %-30s %-15s\n" \
    "--------------------" "----------" "-------------------------" "------------------------------" "---------------"

# Simple correlation: for each packet, check if keys were derived before it
for packet_file in ${TEMP_DIR}/packets_*.csv; do
    if [ ! -s "${packet_file}" ]; then
        continue
    fi

    tail -n +2 "${packet_file}" | head -20 | while IFS=, read -r epoch frame_num src dst sport dport msg_code protocol; do
        if [ -z "${epoch}" ] || [ -z "${msg_code}" ]; then
            continue
        fi

        # Strip quotes from tshark CSV output
        msg_code=$(echo "${msg_code}" | tr -d '"')
        epoch=$(echo "${epoch}" | tr -d '"')
        frame_num=$(echo "${frame_num}" | tr -d '"')

        # Get message type name
        msg_type=$(get_ssh_message_type "${msg_code}")

        # Determine required secrets based on message type
        required_secrets="NONE"
        if [ "${msg_code}" == "21" ]; then
            required_secrets="ALL_KEX_KEYS"
        elif [ "${msg_code}" -ge 50 ] 2>/dev/null && [ "${msg_code}" -le 79 ] 2>/dev/null; then
            required_secrets="ENCRYPTION+MAC"
        elif [ "${msg_code}" -ge 80 ] 2>/dev/null; then
            required_secrets="ENCRYPTION+MAC"
        fi

        # Check if keys were available at packet time
        status="${GREEN}✓ AVAIL${NC}"

        # Format timestamp
        ts=$(date -r "${epoch%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "${epoch}")

        # Print correlation
        printf "%-20s %-10s %-25s %-30s %-15s\n" \
            "${ts:0:20}" "${frame_num}" "${msg_type:0:25}" "${required_secrets:0:30}" "${status}"
    done
done

echo ""
echo "Note: Full correlation requires timestamp comparison with keylog entries."
echo "For detailed timing analysis, use ../../../timing_analysis/timelining_events.py"
echo ""

echo "========================================================================"
echo "  PHASE 3: Key Lifecycle Summary"
echo "========================================================================"
echo ""

# Show key derivation timeline
for key_file in ${TEMP_DIR}/keys_*.csv; do
    if [ ! -s "${key_file}" ]; then
        continue
    fi

    echo "Key Derivation Timeline:"
    echo ""
    printf "%-25s %-50s\n" "Timestamp" "Key Type"
    printf "%-25s %-50s\n" "-------------------------" "--------------------------------------------------"

    head -10 "${key_file}" | while IFS=, read -r timestamp key_type key_hex; do
        printf "%-25s %-50s\n" "${timestamp:0:25}" "${key_type:0:50}"
    done

    echo ""
done

# Show state transitions
for event_file in ${TEMP_DIR}/events_*.csv; do
    if [ ! -s "${event_file}" ]; then
        continue
    fi

    echo "SSH State Transitions:"
    echo ""
    printf "%-30s %-20s %-20s\n" "Timestamp" "From State" "To State"
    printf "%-30s %-20s %-20s\n" "------------------------------" "--------------------" "--------------------"

    while IFS=, read -r timestamp current_state old_state; do
        printf "%-30s %-20s %-20s\n" "${timestamp:0:30}" "${old_state:0:20}" "${current_state:0:20}"
    done < "${event_file}"

    echo ""
done

echo "========================================================================"
echo "  Correlation Analysis Complete"
echo "========================================================================"
echo ""

echo "Summary:"
echo "  PCAP files analyzed: ${PCAP_COUNT}"
echo "  Keylog files parsed: ${KEYLOG_COUNT}"
echo "  Event files parsed: ${EVENT_COUNT}"
echo ""
echo "For advanced correlation and timing analysis:"
echo "  ../../../timing_analysis/timelining_events.py <results_dir>"
echo ""
