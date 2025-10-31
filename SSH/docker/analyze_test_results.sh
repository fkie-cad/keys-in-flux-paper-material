#!/bin/bash

###############################################################################
# SSH Test Results Analysis Tool
# Analyzes captured data from test_ssh_complete.sh runs
###############################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[ANALYSIS]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if test results directory is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <test_results_directory>"
    echo ""
    echo "Example: $0 test_results_20251015_102030"
    echo ""
    echo "Available test result directories:"
    ls -dt test_results_* 2>/dev/null | head -5
    exit 1
fi

TEST_DIR="$1"

if [ ! -d "$TEST_DIR" ]; then
    error "Directory not found: $TEST_DIR"
    exit 1
fi

log "Analyzing test results in: $TEST_DIR"

###############################################################################
# Section 1: Overview
###############################################################################

section1_overview() {
    log "=== Section 1: Test Overview ==="

    echo -e "\n${CYAN}Test Timestamp:${NC} $(basename $TEST_DIR | sed 's/test_results_//')"
    echo -e "${CYAN}Test Directory:${NC} $TEST_DIR"

    echo -e "\n${CYAN}Directory Structure:${NC}"
    tree -L 2 "$TEST_DIR" 2>/dev/null || find "$TEST_DIR" -maxdepth 2 -type f -o -type d

    echo -e "\n${CYAN}File Count by Type:${NC}"
    echo "  PCAP files: $(find "$TEST_DIR/captures" -name "*.pcap" 2>/dev/null | wc -l)"
    echo "  Keylog files: $(find "$TEST_DIR/keys" -name "*.log" 2>/dev/null | wc -l)"
    echo "  Analysis files: $(find "$TEST_DIR/analysis" -name "*.txt" -o -name "*.csv" 2>/dev/null | wc -l)"
    echo "  Log files: $(find "$TEST_DIR/logs" -name "*.log" 2>/dev/null | wc -l)"
}

###############################################################################
# Section 2: Key Format Comparison
###############################################################################

section2_key_comparison() {
    log "=== Section 2: Key Format Comparison ==="

    for server in dropbear wolfssh; do
        lldb_keys="${TEST_DIR}/keys/${server}_lldb.log"
        gt_keys="${TEST_DIR}/keys/${server}_groundtruth.log"

        if [ -f "$lldb_keys" ]; then
            echo -e "\n${CYAN}=== ${server} Keys ===${NC}"

            echo -e "\n${YELLOW}LLDB Extracted Keys:${NC}"
            cat "$lldb_keys"

            if [ -f "$gt_keys" ]; then
                echo -e "\n${YELLOW}Groundtruth Keys:${NC}"
                cat "$gt_keys"

                # Compare OUT keys
                lldb_out=$(grep "MODE OUT" "$lldb_keys" | awk '{print $7}')
                gt_out=$(grep "MODE OUT" "$gt_keys" | awk '{print $7}')

                echo -e "\n${YELLOW}OUT Key Comparison:${NC}"
                if [ -n "$lldb_out" ] && [ -n "$gt_out" ]; then
                    if [ "$lldb_out" == "$gt_out" ]; then
                        echo -e "  ${GREEN}✓ MATCH${NC}"
                    else
                        echo -e "  ${RED}✗ MISMATCH${NC}"
                        echo "  LLDB: $lldb_out"
                        echo "  GT:   $gt_out"
                    fi
                else
                    echo -e "  ${YELLOW}? Cannot compare (missing data)${NC}"
                fi

                # Compare IN keys
                lldb_in=$(grep "MODE IN" "$lldb_keys" | awk '{print $7}')
                gt_in=$(grep "MODE IN" "$gt_keys" | awk '{print $7}')

                echo -e "\n${YELLOW}IN Key Comparison:${NC}"
                if [ -n "$lldb_in" ] && [ -n "$gt_in" ]; then
                    if [ "$lldb_in" == "$gt_in" ]; then
                        echo -e "  ${GREEN}✓ MATCH${NC}"
                    else
                        echo -e "  ${RED}✗ MISMATCH${NC}"
                        echo "  LLDB: $lldb_in"
                        echo "  GT:   $gt_in"
                    fi
                else
                    echo -e "  ${YELLOW}? Cannot compare (missing data)${NC}"
                fi
            else
                warn "No groundtruth keys found for $server"
            fi
        else
            warn "No LLDB keys found for $server"
        fi
    done
}

###############################################################################
# Section 3: Key Lifecycle Visualization
###############################################################################

section3_lifecycle() {
    log "=== Section 3: Key Lifecycle Timeline ==="

    for server in dropbear wolfssh; do
        timing_csv="${TEST_DIR}/analysis/${server}_timing.csv"

        if [ -f "$timing_csv" ]; then
            echo -e "\n${CYAN}=== ${server} Lifecycle ===${NC}"

            # Show raw timing data
            echo -e "\n${YELLOW}Timing Data:${NC}"
            column -t -s',' "$timing_csv"

            # Calculate and visualize timeline
            echo -e "\n${YELLOW}Timeline Visualization:${NC}"
            python3 - "$timing_csv" << 'PYEOF'
import sys
import csv

csv_file = sys.argv[1]

try:
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print("  No timing data")
        sys.exit(0)

    # Group by key_id
    keys = {}
    for row in rows:
        key_id = row['key_id']
        if key_id not in keys:
            keys[key_id] = []
        keys[key_id].append(row)

    # Process each key
    for key_id, events in keys.items():
        print(f"\n  Key: {key_id}")

        # Get base timestamp
        base_ts = float(events[0]['timestamp'])

        # Sort by timestamp
        events.sort(key=lambda x: float(x['timestamp']))

        # Print timeline
        for event in events:
            ts = float(event['timestamp'])
            delta = ts - base_ts
            event_name = event['event']

            # Visual timeline
            bar_length = int(delta * 100)  # Scale for visualization
            bar = '─' * bar_length + '●'

            print(f"  {event_name:25} {delta:8.4f}s  {bar}")

        # Calculate durations
        event_dict = {e['event']: float(e['timestamp']) for e in events}

        if 'generated' in event_dict and 'activated' in event_dict:
            duration = event_dict['activated'] - event_dict['generated']
            print(f"\n  ⏱ Generation → Activation: {duration:.6f}s")

        cleared_events = [k for k in event_dict.keys() if 'cleared' in k]
        if cleared_events and 'activated' in event_dict:
            clear_time = max(event_dict[e] for e in cleared_events)
            duration = clear_time - event_dict['activated']
            print(f"  ⏱ Activation → Clearing: {duration:.6f}s")

        if 'generated' in event_dict and cleared_events:
            clear_time = max(event_dict[e] for e in cleared_events)
            duration = clear_time - event_dict['generated']
            print(f"  ⏱ Total Lifespan: {duration:.6f}s")

except Exception as e:
    print(f"Error processing timeline: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
PYEOF
        else
            warn "No timing data found for $server"
        fi
    done
}

###############################################################################
# Section 4: PCAP Traffic Summary
###############################################################################

section4_pcap_analysis() {
    log "=== Section 4: PCAP Traffic Analysis ==="

    for pcap in "$TEST_DIR"/captures/*.pcap; do
        if [ -f "$pcap" ]; then
            pcap_name=$(basename "$pcap")
            echo -e "\n${CYAN}=== ${pcap_name} ===${NC}"

            # Basic statistics
            total_packets=$(tshark -r "$pcap" 2>/dev/null | wc -l)
            ssh_packets=$(tshark -r "$pcap" -Y "ssh" 2>/dev/null | wc -l)
            tcp_packets=$(tshark -r "$pcap" -Y "tcp" 2>/dev/null | wc -l)

            echo -e "${YELLOW}Packet Statistics:${NC}"
            echo "  Total packets: $total_packets"
            echo "  TCP packets: $tcp_packets"
            echo "  SSH packets: $ssh_packets"

            # TCP conversations
            echo -e "\n${YELLOW}TCP Conversations:${NC}"
            tshark -r "$pcap" -q -z conv,tcp 2>/dev/null | tail -n +6

            # SSH protocol versions
            echo -e "\n${YELLOW}SSH Protocol Exchange:${NC}"
            tshark -r "$pcap" -Y "ssh" -T fields -e ssh.protocol 2>/dev/null | sort -u

            # Key exchange algorithms
            echo -e "\n${YELLOW}Key Exchange Info:${NC}"
            tshark -r "$pcap" -Y "ssh.kex_algorithms" -T fields -e ssh.kex_algorithms 2>/dev/null | head -1

            # Encryption algorithms
            echo -e "\n${YELLOW}Encryption Algorithms:${NC}"
            tshark -r "$pcap" -Y "ssh.encryption_algorithms_client_to_server" \
                -T fields -e ssh.encryption_algorithms_client_to_server 2>/dev/null | head -1
        fi
    done
}

###############################################################################
# Section 5: LLDB Event Log Analysis
###############################################################################

section5_lldb_events() {
    log "=== Section 5: LLDB Event Log Analysis ==="

    for server in dropbear wolfssh; do
        events_log="${TEST_DIR}/logs/${server}_lldb_events.log"

        if [ -f "$events_log" ]; then
            echo -e "\n${CYAN}=== ${server} LLDB Events ===${NC}"

            # Count event types
            echo -e "\n${YELLOW}Event Type Summary:${NC}"
            grep -oP '\[[\w_]+\]' "$events_log" | sort | uniq -c | sort -rn | \
                awk '{printf "  %20s: %d\n", $2, $1}'

            # Show critical events
            echo -e "\n${YELLOW}Critical Events:${NC}"
            grep -E '\[(KEY_EXTRACT|WATCHPOINT|KEY_CLEARED)\]' "$events_log" | tail -20

            # Check for errors
            echo -e "\n${YELLOW}Errors/Warnings:${NC}"
            if grep -qi "error\|fail\|warn" "$events_log"; then
                grep -i "error\|fail\|warn" "$events_log" | tail -10
            else
                echo "  No errors or warnings found"
            fi
        else
            warn "No LLDB event log found for $server"
        fi
    done
}

###############################################################################
# Section 6: Key Statistics
###############################################################################

section6_statistics() {
    log "=== Section 6: Key Statistics ==="

    for server in dropbear wolfssh; do
        lldb_keys="${TEST_DIR}/keys/${server}_lldb.log"

        if [ -f "$lldb_keys" ]; then
            echo -e "\n${CYAN}=== ${server} Key Statistics ===${NC}"

            # Count keys
            out_keys=$(grep -c "MODE OUT" "$lldb_keys" 2>/dev/null || echo 0)
            in_keys=$(grep -c "MODE IN" "$lldb_keys" 2>/dev/null || echo 0)

            echo -e "${YELLOW}Key Counts:${NC}"
            echo "  OUT (client→server) keys: $out_keys"
            echo "  IN (server→client) keys: $in_keys"
            echo "  Total keys extracted: $((out_keys + in_keys))"

            # Cipher types
            echo -e "\n${YELLOW}Cipher Types:${NC}"
            grep "CIPHER" "$lldb_keys" | awk '{print $6}' | sort -u | \
                awk '{printf "  %s\n", $1}'

            # Key lengths
            echo -e "\n${YELLOW}Key Lengths:${NC}"
            grep "KEY" "$lldb_keys" | awk '{print $7}' | \
                awk '{printf "  %d bytes (%d bits)\n", length($1)/2, length($1)*4}'
        fi
    done
}

###############################################################################
# Section 7: Comparison Summary
###############################################################################

section7_comparison_summary() {
    log "=== Section 7: Overall Comparison Summary ==="

    echo -e "\n${CYAN}Implementation Comparison:${NC}\n"

    printf "%-15s %-15s %-15s %-20s %-15s\n" \
        "Server" "LLDB Keys" "Groundtruth" "Lifecycle Data" "PCAP Captured"
    printf "%-15s %-15s %-15s %-20s %-15s\n" \
        "───────────────" "─────────────" "─────────────" "──────────────────" "─────────────"

    for server in dropbear wolfssh; do
        # Check LLDB keys
        if [ -f "${TEST_DIR}/keys/${server}_lldb.log" ]; then
            lldb_status="${GREEN}✓ Yes${NC}"
        else
            lldb_status="${RED}✗ No${NC}"
        fi

        # Check groundtruth
        if [ -f "${TEST_DIR}/keys/${server}_groundtruth.log" ]; then
            gt_status="${GREEN}✓ Yes${NC}"
        else
            gt_status="${YELLOW}○ N/A${NC}"
        fi

        # Check lifecycle
        if [ -f "${TEST_DIR}/analysis/${server}_timing.csv" ]; then
            lifecycle_status="${GREEN}✓ Yes${NC}"
        else
            lifecycle_status="${RED}✗ No${NC}"
        fi

        # Check PCAP
        pcap_count=$(ls "${TEST_DIR}/captures/${server}"_*.pcap 2>/dev/null | wc -l)
        if [ $pcap_count -gt 0 ]; then
            pcap_status="${GREEN}✓ ${pcap_count} files${NC}"
        else
            pcap_status="${RED}✗ None${NC}"
        fi

        printf "%-15s " "$server"
        printf "%-24b " "$lldb_status"
        printf "%-24b " "$gt_status"
        printf "%-29b " "$lifecycle_status"
        printf "%-24b\n" "$pcap_status"
    done
}

###############################################################################
# Section 8: Recommendations
###############################################################################

section8_recommendations() {
    log "=== Section 8: Recommendations & Next Steps ==="

    echo -e "\n${CYAN}Suggested Next Steps:${NC}\n"

    # Check what's available and suggest actions
    echo "1. ${YELLOW}Decrypt and analyze traffic:${NC}"
    for server in dropbear wolfssh; do
        if [ -f "${TEST_DIR}/keys/${server}_lldb.log" ] && \
           [ -f "${TEST_DIR}/captures/${server}_lldb.pcap" ]; then
            echo "   cd openSSH/research_setup/decryption"
            echo "   python3 read_lldb_keylog.py ${TEST_DIR}/keys/${server}_lldb.log /tmp/${server}_keys.json"
            echo "   python3 decrypt_ssh_pcap.py --pcap ${TEST_DIR}/captures/${server}_lldb.pcap \\"
            echo "       --keys /tmp/${server}_keys.json --out /tmp/${server}_decrypted.pcap"
            echo "   wireshark /tmp/${server}_decrypted.pcap"
            echo ""
        fi
    done

    echo "2. ${YELLOW}Examine key lifecycle in detail:${NC}"
    for server in dropbear wolfssh; do
        if [ -f "${TEST_DIR}/analysis/${server}_timing.csv" ]; then
            echo "   cat ${TEST_DIR}/analysis/${server}_timing.csv"
            echo "   cat ${TEST_DIR}/logs/${server}_lldb_events.log | grep KEY"
            echo ""
        fi
    done

    echo "3. ${YELLOW}Verify key matching:${NC}"
    for server in dropbear wolfssh; do
        if [ -f "${TEST_DIR}/analysis/${server}_comparison.txt" ]; then
            echo "   cat ${TEST_DIR}/analysis/${server}_comparison.txt"
            echo ""
        fi
    done

    echo "4. ${YELLOW}Test rekey functionality:${NC}"
    echo "   # Modify test script to trigger SSH rekey"
    echo "   # For OpenSSH: use ~R escape sequence"
    echo "   # For other implementations: check documentation"
    echo ""

    echo "5. ${YELLOW}Analyze PCAP with Wireshark:${NC}"
    for pcap in "${TEST_DIR}"/captures/*.pcap; do
        if [ -f "$pcap" ]; then
            echo "   wireshark $pcap"
        fi
    done
    echo ""
}

###############################################################################
# Main Execution
###############################################################################

main() {
    section1_overview
    section2_key_comparison
    section3_lifecycle
    section4_pcap_analysis
    section5_lldb_events
    section6_statistics
    section7_comparison_summary
    section8_recommendations

    echo -e "\n${GREEN}═══════════════════════════════════════════════════${NC}"
    log "Analysis Complete"
    echo -e "${GREEN}═══════════════════════════════════════════════════${NC}\n"
}

# Run main
main "$@"
