#!/bin/bash
#
# SSH Lifecycle Analysis - Comparison Report Generator
#
# Analyzes SSH lifecycle experiment results and generates comprehensive
# comparison reports across different implementations.
#
# Usage:
#   ./analyze_ssh_lifecycle.sh [results_directory]
#
# If no directory is specified, analyzes the most recent results/ output.
#
# Generates:
#   - Comparative key extraction statistics
#   - Memory dump analysis
#   - Packet capture summaries
#   - Implementation differences and recommendations
#

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
RESULTS_DIR="${1}"
DATA_DIR="./data"

# Auto-detect most recent results directory if not specified
if [ -z "${RESULTS_DIR}" ] || [ ! -d "${RESULTS_DIR}" ]; then
    echo -e "${YELLOW}[INFO] No results directory specified or not found${NC}"
    echo -e "${YELLOW}[INFO] Searching for most recent experiment results...${NC}"

    # Check for results/ directory
    if [ -d "./results" ]; then
        RESULTS_DIR=$(ls -td ./results/ssh_lifecycle_* 2>/dev/null | head -1)
    fi

    # If still not found, analyze data/ directory instead
    if [ -z "${RESULTS_DIR}" ] || [ ! -d "${RESULTS_DIR}" ]; then
        echo -e "${YELLOW}[INFO] No results/ found, analyzing data/ directory instead${NC}"
        RESULTS_DIR="${DATA_DIR}"
    fi
fi

# If analyzing a custom results directory, prioritize it over DATA_DIR
# This allows analyzing archived results like "old_research_working_result/"
if [ "${RESULTS_DIR}" != "${DATA_DIR}" ]; then
    # Custom results directory - look for files within it first
    USE_CUSTOM_RESULTS=true
else
    # Using default data/ directory
    USE_CUSTOM_RESULTS=false
fi

if [ ! -d "${RESULTS_DIR}" ]; then
    echo -e "${RED}[ERROR] Results directory not found: ${RESULTS_DIR}${NC}"
    echo ""
    echo "Usage: $0 [results_directory]"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Analyze most recent results"
    echo "  $0 ./results/ssh_lifecycle_20251025_123456"
    echo "  $0 ./data                             # Analyze current data/ directory"
    echo ""
    exit 1
fi

echo ""
echo "========================================================================"
echo "  SSH Lifecycle Analysis - Comparison Report"
echo "========================================================================"
echo ""
echo "Results directory: ${RESULTS_DIR}"
echo ""

# Function to count keys in keylog file
# Supports multiple formats:
#   - OpenSSH: "CLIENT A_IV_CLIENT_TO_SERVER: <hex>"
#   - wolfSSH legacy: "NEWKEYS MODE IN TYPE IV VALUE <hex>"
#   - wolfSSH new: "CLIENT A_IV_CLIENT_TO_SERVER_KEX1: <hex>"
#   - Dropbear: "DERIVE_KEY ..."
count_keys() {
    local keylog=$1
    if [ -f "${keylog}" ] && [ -s "${keylog}" ]; then
        grep -c "CLIENT [A-F]_\|NEWKEYS.*TYPE.*VALUE\|DERIVE_KEY" "${keylog}" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Function to count memory dumps
count_dumps() {
    local pattern=$1
    local count=$(find "${RESULTS_DIR}" -name "${pattern}" 2>/dev/null | wc -l | tr -d ' ')
    echo "${count}"
}

# Function to get file size
get_size() {
    local file=$1
    if [ -f "${file}" ]; then
        stat -f%z "${file}" 2>/dev/null || stat -c%s "${file}" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Function to format bytes
format_bytes() {
    local bytes=$1
    if [ "${bytes}" -ge 1073741824 ]; then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f GB", b/1073741824}'
    elif [ "${bytes}" -ge 1048576 ]; then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f MB", b/1048576}'
    elif [ "${bytes}" -ge 1024 ]; then
        awk -v b="${bytes}" 'BEGIN {printf "%.2f KB", b/1024}'
    else
        echo "${bytes} bytes"
    fi
}

# Analyze each implementation
echo "========================================================================"
echo "  KEY EXTRACTION COMPARISON"
echo "========================================================================"
echo ""

# Bash 3.x compatible - no associative arrays
impl_keys_wolfssh=0
impl_keys_dropbear=0
impl_keys_openssh=0
impl_status_wolfssh=""
impl_status_dropbear=""
impl_status_openssh=""

# wolfSSH
WOLFSSH_KEYLOG="${RESULTS_DIR}/wolfssh_client_keylog.log"
if [ ! -f "${WOLFSSH_KEYLOG}" ]; then
    WOLFSSH_KEYLOG="${DATA_DIR}/keylogs/wolfssh_client_keylog.log"
fi
WOLFSSH_KEYS=$(count_keys "${WOLFSSH_KEYLOG}")
impl_keys_wolfssh=$WOLFSSH_KEYS
if [ "${WOLFSSH_KEYS}" -eq 4 ]; then
    impl_status_wolfssh="✓ PASS (AEAD cipher)"
    echo -e "${GREEN}wolfSSH:  ${WOLFSSH_KEYS} keys extracted ✓ (AEAD cipher - ChaCha20-Poly1305)${NC}"
elif [ "${WOLFSSH_KEYS}" -gt 0 ]; then
    impl_status_wolfssh="⚠️  PARTIAL"
    echo -e "${YELLOW}wolfSSH:  ${WOLFSSH_KEYS} keys extracted ⚠️  (expected 4 for AEAD)${NC}"
else
    impl_status_wolfssh="✗ FAIL"
    echo -e "${RED}wolfSSH:  No keys extracted ✗${NC}"
fi

# Dropbear
DROPBEAR_KEYLOG="${RESULTS_DIR}/dropbear_client_keylog.log"
if [ ! -f "${DROPBEAR_KEYLOG}" ]; then
    DROPBEAR_KEYLOG="${DATA_DIR}/keylogs/dropbear_client_keylog.log"
fi
DROPBEAR_KEYS=$(count_keys "${DROPBEAR_KEYLOG}")
impl_keys_dropbear=$DROPBEAR_KEYS
if [ "${DROPBEAR_KEYS}" -ge 1 ]; then
    impl_status_dropbear="✓ PASS"
    echo -e "${GREEN}Dropbear: ${DROPBEAR_KEYS} key(s) extracted ✓${NC}"
else
    impl_status_dropbear="✗ FAIL"
    echo -e "${RED}Dropbear: No keys extracted ✗${NC}"
fi

# OpenSSH (future)
OPENSSH_KEYLOG="${RESULTS_DIR}/openssh_client_keylog.log"
if [ ! -f "${OPENSSH_KEYLOG}" ]; then
    OPENSSH_KEYLOG="${DATA_DIR}/keylogs/openssh_client_keylog.log"
fi
OPENSSH_KEYS=$(count_keys "${OPENSSH_KEYLOG}")
if [ "${OPENSSH_KEYS}" -gt 0 ]; then
    impl_keys_openssh=$OPENSSH_KEYS
    if [ "${OPENSSH_KEYS}" -eq 6 ]; then
        impl_status_openssh="✓ PASS"
        echo -e "${GREEN}OpenSSH:  ${OPENSSH_KEYS} keys extracted ✓${NC}"
    else
        impl_status_openssh="⚠️  PARTIAL"
        echo -e "${YELLOW}OpenSSH:  ${OPENSSH_KEYS} keys extracted ⚠️  (expected 6)${NC}"
    fi
else
    echo -e "${CYAN}OpenSSH:  Not tested yet (FUTURE)${NC}"
fi

echo ""

# Memory dumps analysis
echo "========================================================================"
echo "  MEMORY DUMPS ANALYSIS"
echo "========================================================================"
echo ""

WOLFSSH_DUMPS=$(count_dumps "*wolfssh*.dump")
DROPBEAR_DUMPS=$(count_dumps "*dropbear*.dump")
OPENSSH_DUMPS=$(count_dumps "*openssh*.dump")

echo "Memory dumps captured:"
echo "  wolfSSH:  ${WOLFSSH_DUMPS} dumps"
echo "  Dropbear: ${DROPBEAR_DUMPS} dumps"
if [ "${OPENSSH_DUMPS}" -gt 0 ]; then
    echo "  OpenSSH:  ${OPENSSH_DUMPS} dumps"
fi
echo ""

# Calculate total dump size
TOTAL_DUMP_SIZE=0
for dump in $(find "${RESULTS_DIR}" -name "*.dump" 2>/dev/null); do
    size=$(get_size "${dump}")
    TOTAL_DUMP_SIZE=$((TOTAL_DUMP_SIZE + size))
done

echo "Total dump storage: $(format_bytes ${TOTAL_DUMP_SIZE})"
echo ""

# Packet capture analysis
echo "========================================================================"
echo "  PACKET CAPTURE ANALYSIS"
echo "========================================================================"
echo ""

CAPTURES_FOUND=0
for pcap in "${RESULTS_DIR}"/*.pcap "${DATA_DIR}/captures"/*.pcap; do
    if [ -f "${pcap}" ]; then
        CAPTURES_FOUND=$((CAPTURES_FOUND + 1))
        size=$(get_size "${pcap}")
        basename_pcap=$(basename "${pcap}")
        echo "  ${basename_pcap}: $(format_bytes ${size})"
    fi
done

if [ "${CAPTURES_FOUND}" -eq 0 ]; then
    echo -e "${YELLOW}  No packet captures found${NC}"
fi
echo ""

# Key lifecycle persistence analysis
echo "========================================================================"
echo "  KEY LIFECYCLE PERSISTENCE ANALYSIS"
echo "========================================================================"
echo ""
echo "Analyzing when secrets were last observed in memory dumps..."
echo ""

# Function to extract hex keys from keylog
extract_keys_from_log() {
    local keylog=$1
    if [ ! -f "${keylog}" ] || [ ! -s "${keylog}" ]; then
        return
    fi

    # Extract keys (last field on each line, should be hex)
    awk '{print $NF}' "${keylog}" 2>/dev/null | grep -E '^[0-9a-fA-F]{16,}$' || true
}

# Function to search for key in all dumps and find last occurrence
find_last_occurrence() {
    local key=$1
    local key_name=$2
    local dumps_dir=$3

    # Get first 16 hex chars as search pattern (sufficient for uniqueness)
    local search_pattern=$(echo "$key" | cut -c1-16)

    # Find all dump files sorted by timestamp (filename contains timestamp)
    local last_seen="NEVER"
    local last_dump="NONE"

    for dump in $(find "${dumps_dir}" -name "*.dump" 2>/dev/null | sort); do
        if [ -f "${dump}" ] && [ -s "${dump}" ]; then
            # Search dump for key pattern (case-insensitive hex search)
            if grep -qai "${search_pattern}" "${dump}" 2>/dev/null; then
                last_seen=$(basename "${dump}" | grep -oE '[0-9]{8}_[0-9]{6}' || echo "FOUND")
                last_dump=$(basename "${dump}")
            fi
        fi
    done

    if [ "${last_seen}" != "NEVER" ]; then
        echo -e "${GREEN}  ${key_name}: Last seen @ ${last_seen}${NC}"
        echo "    Dump: ${last_dump}"
    else
        echo -e "${YELLOW}  ${key_name}: NOT FOUND in any dump${NC}"
    fi
}

# Analyze OpenSSH keys (most complete dataset)
if [ -f "${OPENSSH_KEYLOG}" ] && [ -s "${OPENSSH_KEYLOG}" ]; then
    echo "OpenSSH Key Persistence:"

    # Parse keylog for individual keys with names
    grep -E "DERIVE_KEY|CLIENT_TO_SERVER|SERVER_TO_CLIENT" "${OPENSSH_KEYLOG}" 2>/dev/null | \
    while IFS= read -r line; do
        key_hex=$(echo "$line" | awk '{print $NF}')
        key_name=$(echo "$line" | awk '{for(i=3;i<NF;i++) printf $i " "; print ""}' | sed 's/ $//')

        if [ -n "${key_hex}" ] && [ -n "${key_name}" ]; then
            find_last_occurrence "${key_hex}" "${key_name}" "${DATA_DIR}/dumps"
        fi
    done
    echo ""
fi

# Analyze Dropbear keys
if [ -f "${DROPBEAR_KEYLOG}" ] && [ -s "${DROPBEAR_KEYLOG}" ]; then
    echo "Dropbear Key Persistence:"

    extract_keys_from_log "${DROPBEAR_KEYLOG}" | \
    while IFS= read -r key_hex; do
        if [ -n "${key_hex}" ]; then
            find_last_occurrence "${key_hex}" "Cipher Key" "${DATA_DIR}/dumps"
        fi
    done
    echo ""
fi

# Analyze wolfSSH keys
if [ -f "${WOLFSSH_KEYLOG}" ] && [ -s "${WOLFSSH_KEYLOG}" ]; then
    echo "wolfSSH Key Persistence:"

    extract_keys_from_log "${WOLFSSH_KEYLOG}" | \
    while IFS= read -r key_hex; do
        if [ -n "${key_hex}" ]; then
            find_last_occurrence "${key_hex}" "AEAD Key" "${DATA_DIR}/dumps"
        fi
    done
    echo ""
fi

echo "Note: Key persistence shows WHEN secrets were last observed in memory."
echo "Keys not found in dumps may have been cleared immediately or dumps may"
echo "have been taken before/after key usage."
echo ""

# Watchpoint timing analysis
echo "========================================================================"
echo "  WATCHPOINT TIMING ANALYSIS (Hardware Watchpoints)"
echo "========================================================================"
echo ""
echo "Analyzing hardware watchpoint data (key overwrite detection)..."
echo ""

# Function to analyze timing CSV
analyze_timing_csv() {
    local csv_file=$1
    local impl_name=$2

    if [ ! -f "${csv_file}" ] || [ ! -s "${csv_file}" ]; then
        return
    fi

    echo "${impl_name} Watchpoint Events:"

    # Count overwrite events per key
    local key_c_overwrites=$(grep -c ",C,overwritten," "${csv_file}" 2>/dev/null || echo "0")
    local key_d_overwrites=$(grep -c ",D,overwritten," "${csv_file}" 2>/dev/null || echo "0")

    if [ "${key_c_overwrites}" -gt 0 ] || [ "${key_d_overwrites}" -gt 0 ]; then
        echo -e "${GREEN}  ✓ Watchpoint tracking active${NC}"
        echo "    Key C (client→server) overwrites: ${key_c_overwrites}"
        echo "    Key D (server→client) overwrites: ${key_d_overwrites}"

        # Extract first overwrite timestamp for each key
        local key_c_time=$(grep ",C,overwritten," "${csv_file}" 2>/dev/null | head -1 | cut -d',' -f3)
        local key_d_time=$(grep ",D,overwritten," "${csv_file}" 2>/dev/null | head -1 | cut -d',' -f3)

        if [ -n "${key_c_time}" ]; then
            echo "    Key C first overwrite: ${key_c_time}s (UNIX timestamp)"
        fi
        if [ -n "${key_d_time}" ]; then
            echo "    Key D first overwrite: ${key_d_time}s (UNIX timestamp)"
        fi

        # Calculate delta if both keys present
        if [ -n "${key_c_time}" ] && [ -n "${key_d_time}" ]; then
            local delta=$(awk "BEGIN {printf \"%.6f\", ${key_d_time} - ${key_c_time}}")
            echo "    Delta (D - C): ${delta}s"
        fi
    else
        echo -e "${YELLOW}  ⚠️  No watchpoint events recorded${NC}"
        echo "    (Watchpoints may be disabled or keys not yet overwritten)"
    fi
    echo ""
}

# Function to cross-reference extracted keys with watchpoint events (per-key analysis)
analyze_per_key_lifecycle() {
    local keylog_file=$1
    local timing_csv=$2
    local impl_name=$3

    if [ ! -f "${keylog_file}" ] || [ ! -s "${keylog_file}" ]; then
        return
    fi

    echo "${impl_name} Per-Key Lifecycle Analysis:"
    echo ""

    # Check metadata JSON for watchpoint configuration
    local metadata_json=""
    if [ -f "${RESULTS_DIR}/${impl_name}/${impl_name}_info.json" ]; then
        metadata_json="${RESULTS_DIR}/${impl_name}/${impl_name}_info.json"
    elif [ -f "${RESULTS_DIR}/${impl_name}_info.json" ]; then
        metadata_json="${RESULTS_DIR}/${impl_name}_info.json"
    fi

    # Determine watchpoint status from metadata or timing CSV
    local watchpoints_enabled="false"
    local timing_csv_exists="false"

    if [ -n "${metadata_json}" ] && [ -f "${metadata_json}" ]; then
        # Read watchpoints_enabled from JSON
        watchpoints_enabled=$(grep -o '"watchpoints_enabled": *[a-z]*' "${metadata_json}" | awk '{print $2}' | tr -d ',')
    fi

    if [ -f "${timing_csv}" ] && [ -s "${timing_csv}" ]; then
        timing_csv_exists="true"
    fi

    # Parse keylog and analyze each key
    local keys_total=0
    local keys_overwritten=0
    local keys_persistent=0

    while IFS= read -r line; do
        # Extract key name and hex value from keylog
        # Expected formats:
        # [timestamp] CLIENT C_ENCRYPTION_KEY_CLIENT_TO_SERVER: <hex>
        # [timestamp] CLIENT D_ENCRYPTION_KEY_SERVER_TO_CLIENT: <hex>

        if echo "$line" | grep -q "CLIENT.*_KEY"; then
            keys_total=$((keys_total + 1))

            # Extract key name (e.g., "C_ENCRYPTION_KEY_CLIENT_TO_SERVER")
            local key_name=$(echo "$line" | sed -E 's/.*CLIENT ([A-Z_]+): .*/\1/')

            # Extract short identifier (C or D)
            local key_id=$(echo "$key_name" | cut -c1)

            # Extract key hex value (first 16 chars for display)
            local key_hex=$(echo "$line" | grep -oE '[0-9a-fA-F]{64,}' | head -1)
            local key_preview=$(echo "$key_hex" | cut -c1-16)

            # Check if key was overwritten (search timing CSV)
            local was_overwritten="false"
            if [ "${watchpoints_enabled}" = "true" ] && [ "${timing_csv_exists}" = "true" ]; then
                if grep -q ",${key_id},overwritten," "${timing_csv}" 2>/dev/null; then
                    was_overwritten="true"
                    keys_overwritten=$((keys_overwritten + 1))
                else
                    keys_persistent=$((keys_persistent + 1))
                fi
            elif [ "${watchpoints_enabled}" = "true" ] && [ "${timing_csv_exists}" = "false" ]; then
                # Watchpoints enabled but no CSV = keys never overwritten
                keys_persistent=$((keys_persistent + 1))
            fi

            # Report per-key status
            if [ "${watchpoints_enabled}" = "false" ]; then
                echo -e "${CYAN}  ${key_name}: ${key_preview}... [WATCHPOINTS DISABLED]${NC}"
            elif [ "${watchpoints_enabled}" = "true" ] && [ "${timing_csv_exists}" = "false" ]; then
                # Watchpoints enabled but no overwrites detected
                echo -e "${RED}  ${key_name}: ${key_preview}... ⚠️  NOT OVERWRITTEN (persists in memory)${NC}"
            elif [ "${was_overwritten}" = "true" ]; then
                echo -e "${GREEN}  ${key_name}: ${key_preview}... ✓ OVERWRITTEN${NC}"
            else
                echo -e "${RED}  ${key_name}: ${key_preview}... ⚠️  NOT OVERWRITTEN (persists in memory)${NC}"
            fi
        fi
    done < "${keylog_file}"

    # Summary
    echo ""
    if [ "${watchpoints_enabled}" = "true" ]; then
        echo "  Summary:"
        echo "    Total keys extracted: ${keys_total}"
        echo "    Keys overwritten:     ${keys_overwritten}"
        echo -e "    ${RED}Keys persistent:      ${keys_persistent}${NC}"

        if [ "${keys_persistent}" -gt 0 ]; then
            echo ""
            echo -e "${RED}  ⚠️  SECURITY FINDING: ${keys_persistent} key(s) remain in memory after session close${NC}"
            echo "     This represents a potential security vulnerability where cryptographic"
            echo "     material persists in process memory and could be recovered by an attacker."
        fi
    else
        echo "  Total keys extracted: ${keys_total}"
        echo "  Watchpoint tracking: DISABLED (cannot determine if keys were overwritten)"
    fi
    echo ""
}

# Search for timing CSV files
TIMING_FILES_FOUND=0

# Prioritize custom results directory if specified
if [ "${USE_CUSTOM_RESULTS}" = "true" ]; then
    # Check in custom results directory first
    # Try both RESULTS_DIR/lldb_results/ and RESULTS_DIR/ directly
    for timing_csv in "${RESULTS_DIR}/lldb_results"/timing_*.csv "${RESULTS_DIR}"/timing_*.csv; do
        if [ -f "${timing_csv}" ]; then
            TIMING_FILES_FOUND=$((TIMING_FILES_FOUND + 1))
            impl=$(basename "${timing_csv}" .csv | sed 's/timing_//')
            analyze_timing_csv "${timing_csv}" "${impl}"

            # Add per-key analysis (cross-reference with keylog)
            # Find corresponding keylog file
            keylog_file=""
            if [ -f "${RESULTS_DIR}/${impl}/${impl}_client_keylog.log" ]; then
                keylog_file="${RESULTS_DIR}/${impl}/${impl}_client_keylog.log"
            elif [ -f "${RESULTS_DIR}/${impl}_client_keylog.log" ]; then
                keylog_file="${RESULTS_DIR}/${impl}_client_keylog.log"
            elif [ -f "${RESULTS_DIR}/keylogs/${impl}_client_keylog.log" ]; then
                keylog_file="${RESULTS_DIR}/keylogs/${impl}_client_keylog.log"
            elif [ -f "${DATA_DIR}/keylogs/${impl}_client_keylog.log" ]; then
                keylog_file="${DATA_DIR}/keylogs/${impl}_client_keylog.log"
            fi

            if [ -n "${keylog_file}" ] && [ -f "${keylog_file}" ]; then
                analyze_per_key_lifecycle "${keylog_file}" "${timing_csv}" "${impl}"
            fi
        fi
    done
else
    # Using default data/ directory structure
    # Check in data/lldb_results/
    if [ -d "${DATA_DIR}/lldb_results" ]; then
        for timing_csv in "${DATA_DIR}/lldb_results"/timing_*.csv; do
            if [ -f "${timing_csv}" ]; then
                TIMING_FILES_FOUND=$((TIMING_FILES_FOUND + 1))
                impl=$(basename "${timing_csv}" .csv | sed 's/timing_//')
                analyze_timing_csv "${timing_csv}" "${impl}"

                # Add per-key analysis (cross-reference with keylog)
                # Find corresponding keylog file
                keylog_file=""
                if [ -f "${RESULTS_DIR}/${impl}/${impl}_client_keylog.log" ]; then
                    keylog_file="${RESULTS_DIR}/${impl}/${impl}_client_keylog.log"
                elif [ -f "${RESULTS_DIR}/${impl}_client_keylog.log" ]; then
                    keylog_file="${RESULTS_DIR}/${impl}_client_keylog.log"
                elif [ -f "${DATA_DIR}/keylogs/${impl}_client_keylog.log" ]; then
                    keylog_file="${DATA_DIR}/keylogs/${impl}_client_keylog.log"
                fi

                if [ -n "${keylog_file}" ] && [ -f "${keylog_file}" ]; then
                    analyze_per_key_lifecycle "${keylog_file}" "${timing_csv}" "${impl}"
                fi
            fi
        done
    fi

    # Check in results directory
    for timing_csv in "${RESULTS_DIR}"/timing_*.csv; do
        if [ -f "${timing_csv}" ]; then
            TIMING_FILES_FOUND=$((TIMING_FILES_FOUND + 1))
            impl=$(basename "${timing_csv}" .csv | sed 's/timing_//')
            analyze_timing_csv "${timing_csv}" "${impl}"

            # Add per-key analysis (cross-reference with keylog)
            # Find corresponding keylog file
            keylog_file=""
            if [ -f "${RESULTS_DIR}/${impl}/${impl}_client_keylog.log" ]; then
                keylog_file="${RESULTS_DIR}/${impl}/${impl}_client_keylog.log"
            elif [ -f "${RESULTS_DIR}/${impl}_client_keylog.log" ]; then
                keylog_file="${RESULTS_DIR}/${impl}_client_keylog.log"
            elif [ -f "${DATA_DIR}/keylogs/${impl}_client_keylog.log" ]; then
                keylog_file="${DATA_DIR}/keylogs/${impl}_client_keylog.log"
            fi

            if [ -n "${keylog_file}" ] && [ -f "${keylog_file}" ]; then
                analyze_per_key_lifecycle "${keylog_file}" "${timing_csv}" "${impl}"
            fi
        fi
    done
fi

if [ "${TIMING_FILES_FOUND}" -eq 0 ]; then
    echo -e "${YELLOW}No watchpoint timing data found${NC}"
    echo "  Location checked: ${DATA_DIR}/lldb_results/timing_*.csv"
    echo "  Watchpoint tracking requires:"
    echo "    - LLDB_ENABLE_WATCHPOINTS=true (default)"
    echo "    - Hardware watchpoint support (CPU feature)"
    echo "    - Keys must be overwritten during session"
    echo ""
fi

echo "Note: Watchpoint timing shows WHEN encryption keys were first overwritten."
echo "This helps measure key lifecycle duration (derivation → first overwrite)."
echo ""

# Detailed per-key lifecycle timeline
echo "========================================================================"
echo "  DETAILED KEY LIFECYCLE TIMELINE"
echo "========================================================================"
echo ""
echo "Per-key analysis showing creation, overwrite, lifespan, and memory state."
echo ""

# Function to generate detailed key lifecycle report for one implementation
generate_key_lifecycle_report() {
    local impl=$1
    local keylog_file=$2
    local timing_csv=$3
    local dumps_dir=$4

    if [ ! -f "${keylog_file}" ] || [ ! -s "${keylog_file}" ]; then
        echo -e "${YELLOW}${impl}: No keylog file found${NC}"
        echo ""
        return
    fi

    echo "${impl} Key Lifecycle Timeline:"
    echo ""

    # Check if timing CSV exists
    local has_timing_data="false"
    if [ -f "${timing_csv}" ] && [ -s "${timing_csv}" ]; then
        has_timing_data="true"
    fi

    # Parse keylog and analyze each key
    local key_count=0

    # Support multiple formats:
    # - OpenSSH/wolfSSH new: "[timestamp] CLIENT A_IV_CLIENT_TO_SERVER_KEX1: <hex>"
    # - wolfSSH legacy: "NEWKEYS MODE IN TYPE IV_KEX0 VALUE <hex>"
    grep -E "CLIENT [A-F]_|NEWKEYS.*TYPE.*(IV|KEY)" "${keylog_file}" 2>/dev/null | while IFS= read -r line; do
        key_count=$((key_count + 1))

        # Extract key name and ID - detect format
        local key_name=""
        local key_id=""

        if echo "$line" | grep -q "CLIENT [A-F]_"; then
            # OpenSSH/wolfSSH new format: "CLIENT A_IV_CLIENT_TO_SERVER_KEX1: <hex>"
            key_name=$(echo "$line" | sed -E 's/.*CLIENT ([A-F][A-Z0-9_]*): .*/\1/')
            key_id=$(echo "$key_name" | cut -c1)
        elif echo "$line" | grep -q "NEWKEYS MODE"; then
            # wolfSSH legacy format: "NEWKEYS MODE IN TYPE IV_KEX0 VALUE <hex>"
            # Map to standard naming
            if echo "$line" | grep -q "MODE IN.*TYPE IV"; then
                key_name="A_IV_CLIENT_TO_SERVER"
                key_id="A"
            elif echo "$line" | grep -q "MODE OUT.*TYPE IV"; then
                key_name="B_IV_SERVER_TO_CLIENT"
                key_id="B"
            elif echo "$line" | grep -q "MODE IN.*TYPE KEY"; then
                key_name="C_ENCRYPTION_KEY_CLIENT_TO_SERVER"
                key_id="C"
            elif echo "$line" | grep -q "MODE OUT.*TYPE KEY"; then
                key_name="D_ENCRYPTION_KEY_SERVER_TO_CLIENT"
                key_id="D"
            else
                key_name="UNKNOWN"
                key_id="?"
            fi
        fi

        # Extract hex key value
        local key_hex=$(echo "$line" | grep -oE '[0-9a-fA-F]{32,}' | head -1)
        local key_preview=""
        if [ -n "${key_hex}" ]; then
            key_preview=$(echo "$key_hex" | cut -c1-16)
        fi

        # Extract created timestamp from timing CSV
        # Support both "created" and "derived" events
        local created_time=""
        local created_unix=""
        if [ "${has_timing_data}" = "true" ]; then
            # Look for "created" or "derived" event for this key ID
            # Format: timestamp,key_id,event,details
            # Example: 1730107234.567890,C,created,C_ENCRYPTION_KEY_CLIENT_TO_SERVER
            # Example: 1730107234.567890,C,derived,C_ENCRYPTION_KEY_CLIENT_TO_SERVER
            created_line=$(grep -E ",${key_id},(created|derived)," "${timing_csv}" 2>/dev/null | head -1)
            if [ -n "${created_line}" ]; then
                created_unix=$(echo "$created_line" | cut -d',' -f1)
                created_time=$(date -u -r "${created_unix%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "${created_unix}")
            fi
        fi

        # Extract overwritten timestamp from timing CSV
        local overwritten_time=""
        local overwritten_unix=""
        local lifespan_seconds=""
        if [ "${has_timing_data}" = "true" ]; then
            # Look for "overwritten" event
            overwritten_line=$(grep ",${key_id},overwritten," "${timing_csv}" 2>/dev/null | head -1)
            if [ -n "${overwritten_line}" ]; then
                overwritten_unix=$(echo "$overwritten_line" | cut -d',' -f1)
                overwritten_time=$(date -u -r "${overwritten_unix%.*}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "${overwritten_unix}")

                # Calculate lifespan if both timestamps exist
                if [ -n "${created_unix}" ] && [ -n "${overwritten_unix}" ]; then
                    lifespan_seconds=$(awk "BEGIN {printf \"%.3f\", ${overwritten_unix} - ${created_unix}}")
                fi
            fi
        fi

        # Search for key in memory dumps (find last occurrence)
        local last_dump=""
        local last_dump_time=""
        local key_state="UNKNOWN"

        if [ -n "${key_hex}" ] && [ ${#key_hex} -ge 16 ]; then
            # Use first 16 hex chars as search pattern
            local search_pattern=$(echo "$key_hex" | cut -c1-16)

            # Find all dumps sorted by timestamp, search for key
            for dump in $(find "${dumps_dir}" -name "*${impl}*.dump" 2>/dev/null | sort -r); do
                if [ -f "${dump}" ] && [ -s "${dump}" ]; then
                    # Search dump for key pattern (case-insensitive hex)
                    if grep -qai "${search_pattern}" "${dump}" 2>/dev/null; then
                        last_dump=$(basename "${dump}")
                        # Extract timestamp from filename (format: YYYYmmdd_HHMMSS)
                        last_dump_time=$(echo "$last_dump" | grep -oE '[0-9]{8}_[0-9]{6}' | head -1)
                        key_state="PLAINTEXT"
                        break  # Found in most recent dump
                    fi
                fi
            done

            # If not found in any dump, key may have been cleared before first dump
            if [ -z "${last_dump}" ]; then
                key_state="CLEARED"
                last_dump="NONE (cleared before dumps)"
            fi
        fi

        # Output formatted timeline for this key
        echo "  Key: ${key_name} (ID: ${key_id})"
        echo "    Preview: ${key_preview}..."

        if [ -n "${created_time}" ]; then
            echo -e "${GREEN}    ✓ Created:     ${created_time}${NC}"
        else
            echo -e "${YELLOW}    ? Created:     UNKNOWN (no timing data)${NC}"
        fi

        if [ -n "${overwritten_time}" ]; then
            echo -e "${GREEN}    ✓ Overwritten: ${overwritten_time}${NC}"
            if [ -n "${lifespan_seconds}" ]; then
                echo -e "${CYAN}    ⏱  Lifespan:    ${lifespan_seconds} seconds${NC}"
            fi
        else
            if [ "${has_timing_data}" = "true" ]; then
                echo -e "${RED}    ✗ Overwritten: NOT DETECTED (key persists in memory)${NC}"
            else
                echo -e "${YELLOW}    ? Overwritten: UNKNOWN (no timing data)${NC}"
            fi
        fi

        if [ "${key_state}" = "PLAINTEXT" ]; then
            echo -e "${YELLOW}    Last dump:   ${last_dump} (@ ${last_dump_time})${NC}"
            echo -e "${RED}    State:       PLAINTEXT (found in memory)${NC}"
        elif [ "${key_state}" = "CLEARED" ]; then
            echo -e "${GREEN}    Last dump:   ${last_dump}${NC}"
            echo -e "${GREEN}    State:       CLEARED${NC}"
        else
            echo -e "${YELLOW}    Last dump:   UNKNOWN${NC}"
            echo -e "${YELLOW}    State:       UNKNOWN${NC}"
        fi

        echo ""
    done

    echo ""
}

# Generate reports for each implementation
for impl in wolfssh dropbear openssh; do
    # Find keylog file (check custom results directory first if applicable)
    keylog_file=""
    if [ "${USE_CUSTOM_RESULTS}" = "true" ]; then
        # Check within custom results directory first
        if [ -f "${RESULTS_DIR}/${impl}_client_keylog.log" ]; then
            keylog_file="${RESULTS_DIR}/${impl}_client_keylog.log"
        elif [ -f "${RESULTS_DIR}/keylogs/${impl}_client_keylog.log" ]; then
            keylog_file="${RESULTS_DIR}/keylogs/${impl}_client_keylog.log"
        elif [ -f "${DATA_DIR}/keylogs/${impl}_client_keylog.log" ]; then
            keylog_file="${DATA_DIR}/keylogs/${impl}_client_keylog.log"
        fi
    else
        # Default data/ structure
        if [ -f "${RESULTS_DIR}/${impl}_client_keylog.log" ]; then
            keylog_file="${RESULTS_DIR}/${impl}_client_keylog.log"
        elif [ -f "${DATA_DIR}/keylogs/${impl}_client_keylog.log" ]; then
            keylog_file="${DATA_DIR}/keylogs/${impl}_client_keylog.log"
        fi
    fi

    # Find timing CSV (check custom results directory first if applicable)
    timing_csv=""
    if [ "${USE_CUSTOM_RESULTS}" = "true" ]; then
        # Check within custom results directory first
        if [ -f "${RESULTS_DIR}/lldb_results/timing_${impl}.csv" ]; then
            timing_csv="${RESULTS_DIR}/lldb_results/timing_${impl}.csv"
        elif [ -f "${RESULTS_DIR}/timing_${impl}.csv" ]; then
            timing_csv="${RESULTS_DIR}/timing_${impl}.csv"
        elif [ -f "${DATA_DIR}/lldb_results/timing_${impl}.csv" ]; then
            timing_csv="${DATA_DIR}/lldb_results/timing_${impl}.csv"
        fi
    else
        # Default data/ structure
        if [ -f "${DATA_DIR}/lldb_results/timing_${impl}.csv" ]; then
            timing_csv="${DATA_DIR}/lldb_results/timing_${impl}.csv"
        elif [ -f "${RESULTS_DIR}/timing_${impl}.csv" ]; then
            timing_csv="${RESULTS_DIR}/timing_${impl}.csv"
        fi
    fi

    # Dumps directory (check custom results directory first if applicable)
    dumps_dir="${DATA_DIR}/dumps"
    if [ "${USE_CUSTOM_RESULTS}" = "true" ]; then
        # Check within custom results directory first
        if [ -d "${RESULTS_DIR}/dumps" ]; then
            dumps_dir="${RESULTS_DIR}/dumps"
        elif [ -d "${DATA_DIR}/dumps" ]; then
            dumps_dir="${DATA_DIR}/dumps"
        fi
    else
        # Default data/ structure
        if [ -d "${RESULTS_DIR}/dumps" ]; then
            dumps_dir="${RESULTS_DIR}/dumps"
        elif [ -d "${DATA_DIR}/dumps" ]; then
            dumps_dir="${DATA_DIR}/dumps"
        fi
    fi

    # Generate report if keylog exists
    if [ -n "${keylog_file}" ] && [ -f "${keylog_file}" ]; then
        generate_key_lifecycle_report "${impl}" "${keylog_file}" "${timing_csv}" "${dumps_dir}"
    fi
done

# Base vs Key Update (KU) comparison
echo "========================================================================"
echo "  BASE VS KEY UPDATE COMPARISON"
echo "========================================================================"
echo ""

# Function to compare base vs ku for one implementation
compare_base_ku() {
    local impl=$1
    local base_keylog="${RESULTS_DIR}/base/${impl}/${impl}_client_keylog.log"
    local ku_keylog="${RESULTS_DIR}/ku/${impl}/${impl}_client_keylog.log"

    # Check if base/ku structure exists
    if [ ! -d "${RESULTS_DIR}/base" ] && [ ! -d "${RESULTS_DIR}/ku" ]; then
        return  # Not a base/ku experiment
    fi

    echo "${impl} Base vs KU Comparison:"
    echo ""

    # Count keys extracted in each mode (use universal count_keys function)
    local base_keys=0
    local ku_keys=0

    if [ -f "$base_keylog" ]; then
        base_keys=$(count_keys "$base_keylog")
    fi

    if [ -f "$ku_keylog" ]; then
        ku_keys=$(count_keys "$ku_keylog")
    fi

    echo "  Keys extracted:"
    echo "    Base lifecycle: ${base_keys} keys"
    echo "    KU lifecycle:   ${ku_keys} keys"

    if [ "$ku_keys" -gt "$base_keys" ]; then
        echo -e "${GREEN}    ✓ KU extracted $((ku_keys - base_keys)) additional keys (expected for rekey)${NC}"
    elif [ "$ku_keys" -eq "$base_keys" ]; then
        echo -e "${YELLOW}    ⚠️  KU extracted same number of keys as base (rekey may not have occurred)${NC}"
    else
        echo -e "${RED}    ✗ KU extracted FEWER keys than base (unexpected)${NC}"
    fi

    # Check for timing data (rekey events)
    local base_timing="${RESULTS_DIR}/base/${impl}/timing_${impl}.csv"
    local ku_timing="${RESULTS_DIR}/ku/${impl}/timing_${impl}.csv"

    if [ -f "$base_timing" ] || [ -f "$ku_timing" ]; then
        echo ""
        echo "  Timing data:"

        if [ -f "$base_timing" ]; then
            local base_kex=$(grep -c "kex\|derive" "$base_timing" 2>/dev/null || echo 0)
            echo "    Base KEX cycles: ${base_kex}"
        fi

        if [ -f "$ku_timing" ]; then
            local ku_kex=$(grep -c "kex\|derive" "$ku_timing" 2>/dev/null || echo 0)
            echo "    KU KEX cycles:   ${ku_kex}"

            if [ "$ku_kex" -ge 2 ]; then
                echo -e "${GREEN}    ✓ Multiple KEX cycles detected (rekey successful)${NC}"
            elif [ "$ku_kex" -eq 1 ]; then
                echo -e "${YELLOW}    ⚠️  Only 1 KEX cycle (rekey did not occur)${NC}"
            fi
        fi
    fi

    # Calculate average key lifespan for base vs KU
    if [ -f "$base_timing" ] || [ -f "$ku_timing" ]; then
        echo ""
        echo "  Key Lifespan Analysis:"

        # Function to calculate average lifespan from timing CSV
        calculate_avg_lifespan() {
            local timing_csv=$1

            if [ ! -f "$timing_csv" ] || [ ! -s "$timing_csv" ]; then
                echo "N/A"
                return
            fi

            # Extract key IDs that have both 'created' and 'overwritten' events
            # Format: timestamp,key_id,event,details
            local key_ids=$(awk -F',' '$3 == "created" {print $2}' "$timing_csv" | sort -u)

            local total_lifespan=0
            local count=0

            for key_id in $key_ids; do
                # Get created timestamp for this key
                local created=$(awk -F',' -v id="$key_id" '$2 == id && $3 == "created" {print $1; exit}' "$timing_csv")

                # Get overwritten timestamp for this key
                local overwritten=$(awk -F',' -v id="$key_id" '$2 == id && $3 == "overwritten" {print $1; exit}' "$timing_csv")

                # Calculate lifespan if both timestamps exist
                if [ -n "$created" ] && [ -n "$overwritten" ]; then
                    local lifespan=$(awk "BEGIN {printf \"%.3f\", $overwritten - $created}")
                    total_lifespan=$(awk "BEGIN {printf \"%.3f\", $total_lifespan + $lifespan}")
                    count=$((count + 1))
                fi
            done

            # Calculate average
            if [ "$count" -gt 0 ]; then
                awk "BEGIN {printf \"%.3f\", $total_lifespan / $count}"
            else
                echo "N/A"
            fi
        }

        # Calculate base mode average lifespan
        local base_avg_lifespan="N/A"
        local base_overwritten_count=0
        if [ -f "$base_timing" ]; then
            base_avg_lifespan=$(calculate_avg_lifespan "$base_timing")
            base_overwritten_count=$(grep -c ",overwritten," "$base_timing" 2>/dev/null || echo 0)
        fi

        # Calculate KU mode average lifespan
        local ku_avg_lifespan="N/A"
        local ku_overwritten_count=0
        if [ -f "$ku_timing" ]; then
            ku_avg_lifespan=$(calculate_avg_lifespan "$ku_timing")
            ku_overwritten_count=$(grep -c ",overwritten," "$ku_timing" 2>/dev/null || echo 0)
        fi

        echo "    Base mode:"
        echo "      Keys overwritten: ${base_overwritten_count}"
        if [ "$base_avg_lifespan" != "N/A" ]; then
            echo -e "      Avg lifespan:     ${CYAN}${base_avg_lifespan}s${NC}"
        else
            echo -e "      Avg lifespan:     ${YELLOW}N/A (no overwrites detected)${NC}"
        fi

        echo ""
        echo "    KU mode (with rekey):"
        echo "      Keys overwritten: ${ku_overwritten_count}"
        if [ "$ku_avg_lifespan" != "N/A" ]; then
            echo -e "      Avg lifespan:     ${CYAN}${ku_avg_lifespan}s${NC}"
        else
            echo -e "      Avg lifespan:     ${YELLOW}N/A (no overwrites detected)${NC}"
        fi

        # Compare lifespans
        if [ "$base_avg_lifespan" != "N/A" ] && [ "$ku_avg_lifespan" != "N/A" ]; then
            echo ""
            local lifespan_diff=$(awk "BEGIN {printf \"%.3f\", $base_avg_lifespan - $ku_avg_lifespan}")
            local lifespan_pct=$(awk "BEGIN {printf \"%.1f\", (($base_avg_lifespan - $ku_avg_lifespan) / $base_avg_lifespan) * 100}")

            if (( $(echo "$ku_avg_lifespan < $base_avg_lifespan" | awk '{print ($1 < $2)}') )); then
                echo -e "${GREEN}    ✓ KU reduces key lifespan by ${lifespan_diff}s (${lifespan_pct}% shorter)${NC}"
                echo "      Better security: Keys are cleared sooner with rekey enabled"
            elif (( $(echo "$ku_avg_lifespan > $base_avg_lifespan" | awk '{print ($1 > $2)}') )); then
                echo -e "${YELLOW}    ⚠️  KU increases key lifespan by ${lifespan_diff}s (unexpected)${NC}"
            else
                echo -e "${CYAN}    → KU has same average lifespan as base${NC}"
            fi
        elif [ "$base_avg_lifespan" = "N/A" ] && [ "$ku_avg_lifespan" = "N/A" ]; then
            echo ""
            echo -e "${YELLOW}    ⚠️  Cannot compare: No overwrite events detected in either mode${NC}"
            echo "       Watchpoints may be disabled or keys persist in memory"
        fi
    fi

    echo ""
}

# Check if this is a base/ku experiment structure
if [ -d "${RESULTS_DIR}/base" ] || [ -d "${RESULTS_DIR}/ku" ]; then
    echo "Detected base/ku experiment structure"
    echo ""

    # Compare all implementations
    for impl in openssh dropbear wolfssh; do
        if [ -d "${RESULTS_DIR}/base/${impl}" ] || [ -d "${RESULTS_DIR}/ku/${impl}" ]; then
            compare_base_ku "$impl"
        fi
    done
else
    echo -e "${CYAN}Single-mode experiment (not base/ku comparison)${NC}"
    echo ""
fi

# Implementation comparison
echo "========================================================================"
echo "  IMPLEMENTATION COMPARISON"
echo "========================================================================"
echo ""

# Create comparison table
printf "%-15s %-15s %-15s %-25s\n" "Implementation" "Keys Extracted" "Memory Dumps" "Status"
printf "%-15s %-15s %-15s %-25s\n" "---------------" "---------------" "---------------" "-------------------------"
printf "%-15s %-15s %-15s %-25s\n" "wolfSSH" "${impl_keys_wolfssh}" "${WOLFSSH_DUMPS}" "${impl_status_wolfssh}"
printf "%-15s %-15s %-15s %-25s\n" "Dropbear" "${impl_keys_dropbear}" "${DROPBEAR_DUMPS}" "${impl_status_dropbear}"
if [ "${OPENSSH_KEYS}" -gt 0 ]; then
    printf "%-15s %-15s %-15s %-25s\n" "OpenSSH" "${impl_keys_openssh}" "${OPENSSH_DUMPS}" "${impl_status_openssh}"
fi
echo ""

# Key differences and notes
echo "========================================================================"
echo "  KEY DIFFERENCES & NOTES"
echo "========================================================================"
echo ""

echo "wolfSSH:"
echo "  - Uses AEAD cipher (ChaCha20-Poly1305)"
echo "  - Extracts 4 keys (A-D): IV and encryption keys only"
echo "  - No separate MAC keys (E-F) - authentication integrated into cipher"
echo "  - Rekey: NOT SUPPORTED"
echo ""

echo "Dropbear:"
echo "  - Lightweight implementation"
echo "  - Extracts 1 key (transmit cipher key for ChaCha20)"
echo "  - Optimized for embedded systems"
echo "  - Rekey: SUPPORTED but not tested in simple scenario"
echo ""

echo "OpenSSH:"
echo "  - Full-featured implementation"
echo "  - Extracts all 6 keys (A-F): IVs, encryption keys, MAC keys"
echo "  - Industry standard reference"
echo "  - Rekey: FULLY SUPPORTED (FUTURE testing)"
echo ""

# Recommendations
echo "========================================================================"
echo "  RECOMMENDATIONS"
echo "========================================================================"
echo ""

echo "Next steps:"
echo "  1. Implement OpenSSH lifecycle test with rekey support"
echo "  2. Test Dropbear rekey scenario (separate experiment)"
echo "  3. Validate key extraction against ground-truth (openssh_groundtruth)"
echo "  4. Compare memory dump timing across implementations"
echo "  5. Analyze PCAP files with extracted keys (Wireshark decryption)"
echo ""

echo "For detailed analysis of timing and memory persistence:"
echo "  - Use ../../../timing_analysis/timelining_events.py"
echo "  - Feed keylog + PCAP + memory dumps for correlation"
echo ""

# Generate report file
REPORT_FILE="${RESULTS_DIR}/analysis_report.txt"
echo "Saving detailed report to: ${REPORT_FILE}"
echo ""

# Redirect all above output to report file (using same logic)
cat > "${REPORT_FILE}" << EOF
SSH Lifecycle Analysis - Comparison Report
==========================================
Generated: $(date)
Results directory: ${RESULTS_DIR}

KEY EXTRACTION COMPARISON
=========================
wolfSSH:  ${impl_keys_wolfssh} keys - ${impl_status_wolfssh}
Dropbear: ${impl_keys_dropbear} keys - ${impl_status_dropbear}
EOF

if [ "${OPENSSH_KEYS}" -gt 0 ]; then
    echo "OpenSSH:  ${impl_keys_openssh} keys - ${impl_status_openssh}" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << EOF

MEMORY DUMPS ANALYSIS
=====================
wolfSSH:  ${WOLFSSH_DUMPS} dumps
Dropbear: ${DROPBEAR_DUMPS} dumps
EOF

if [ "${OPENSSH_DUMPS}" -gt 0 ]; then
    echo "OpenSSH:  ${OPENSSH_DUMPS} dumps" >> "${REPORT_FILE}"
fi

cat >> "${REPORT_FILE}" << EOF

Total storage: $(format_bytes ${TOTAL_DUMP_SIZE})

PACKET CAPTURES
===============
Captures found: ${CAPTURES_FOUND}

IMPLEMENTATION NOTES
====================
wolfSSH:
  - AEAD cipher (ChaCha20-Poly1305)
  - 4 keys (A-D only, no MAC keys E-F)
  - No rekey support

Dropbear:
  - Lightweight implementation
  - 1 key extraction (transmit cipher)
  - Rekey supported but not tested

OpenSSH:
  - Full implementation (FUTURE)
  - 6 keys (A-F)
  - Rekey fully supported

For more details, see experiment logs in:
  ${RESULTS_DIR}/
EOF

# Run packet-to-secret correlation
echo "========================================================================"
echo "  PACKET-TO-SECRET CORRELATION"
echo "========================================================================"
echo ""

if [ -f "./correlate_ssh_packets.sh" ]; then
    echo -e "${CYAN}[CORRELATION] Running packet analysis...${NC}"
    echo ""
    ./correlate_ssh_packets.sh "${RESULTS_DIR}" || true
else
    echo -e "${YELLOW}[SKIP] correlate_ssh_packets.sh not found${NC}"
    echo "For packet correlation, ensure correlate_ssh_packets.sh is in the same directory."
    echo ""
fi

# Optional: Run timelining analysis
TIMELINING_SCRIPT="../../timing_analysis/timelining_events.py"
if [ -f "${TIMELINING_SCRIPT}" ]; then
    echo "========================================================================"
    echo "  TIMELINING ANALYSIS (Optional)"
    echo "========================================================================"
    echo ""
    echo "Timelining script detected: ${TIMELINING_SCRIPT}"
    echo ""
    echo "This script correlates keylogs, packet captures, and memory dumps"
    echo "to create a comprehensive timeline of key lifecycle events."
    echo ""

    # Check if we have the necessary data for timelining
    KEYLOG_COUNT=$(find "${RESULTS_DIR}" -name "*_client_keylog.log" 2>/dev/null | wc -l | tr -d ' ')
    PCAP_COUNT=$(find "${RESULTS_DIR}" "${DATA_DIR}/captures" -name "*.pcap" 2>/dev/null | wc -l | tr -d ' ')

    if [ "${KEYLOG_COUNT}" -gt 0 ]; then
        echo "Found ${KEYLOG_COUNT} keylog file(s) and ${PCAP_COUNT} PCAP file(s)."
        echo ""
        echo -e "${YELLOW}To run timelining analysis, use:${NC}"
        echo "  python3 ${TIMELINING_SCRIPT} ${RESULTS_DIR}"
        echo ""
        echo "Options:"
        echo "  --keylog <file>    Specify keylog file"
        echo "  --pcap <file>      Specify PCAP file"
        echo "  --dumps <dir>      Specify memory dumps directory"
        echo "  --output <dir>     Output directory for timeline files"
        echo ""
        echo -e "${CYAN}Note: Timelining is optional and not run automatically.${NC}"
        echo "      Run manually if detailed timeline correlation is needed."
    else
        echo -e "${YELLOW}Insufficient data for timelining (no keylogs found).${NC}"
        echo "Timelining requires at least one keylog file."
    fi
    echo ""
else
    echo "========================================================================"
    echo "  TIMELINING ANALYSIS"
    echo "========================================================================"
    echo ""
    echo -e "${YELLOW}Timelining script not found: ${TIMELINING_SCRIPT}${NC}"
    echo "For detailed timeline analysis, ensure timelining_events.py exists in:"
    echo "  ../../timing_analysis/timelining_events.py"
    echo ""
fi

echo -e "${GREEN}[SUCCESS] Analysis complete!${NC}"
echo ""
echo "Report saved to: ${REPORT_FILE}"
echo ""
