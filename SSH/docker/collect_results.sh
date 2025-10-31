#!/usr/bin/env bash
###############################################################################
# Collect All Results from Manual LLDB Session
# Copies keylogs, timing data, PCAPs, and dumps from containers to host.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()  { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
info() { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# ── Config ───────────────────────────────────────────────────────────────────
SERVER="${1:-dropbear}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="results_${SERVER}_${TIMESTAMP}"

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

echo "══════════════════════════════════════════════════════════════"
echo "  Collecting Results for ${SERVER}"
echo "══════════════════════════════════════════════════════════════"
echo ""

mkdir -p "${OUTPUT_DIR}"

echo "Copying files from containers..."
echo ""

# Get container IDs
SERVER_ID=$("${COMPOSE[@]}" ps -q "${SERVER}_server")
CLIENT_ID=$("${COMPOSE[@]}" ps -q ssh_client)

# Copy LLDB results
info "LLDB keylog..."
docker cp "${SERVER_ID}:/data/keylogs/ssh_keylog_${SERVER}.log" \
    "${OUTPUT_DIR}/lldb_keys.log" 2>/dev/null || echo "    (not found)"

info "Timing data..."
docker cp "${SERVER_ID}:/data/lldb_results/timing_${SERVER}.csv" \
    "${OUTPUT_DIR}/timing.csv" 2>/dev/null || echo "    (not found)"

info "Events log..."
docker cp "${SERVER_ID}:/data/lldb_results/events_${SERVER}.log" \
    "${OUTPUT_DIR}/events.log" 2>/dev/null || echo "    (not found)"

# Copy groundtruth
info "Groundtruth keylog..."
docker cp "${CLIENT_ID}:/data/keylogs/groundtruth_${SERVER}.log" \
    "${OUTPUT_DIR}/groundtruth_keys.log" 2>/dev/null || echo "    (not found)"

# Copy PCAPs
info "PCAP files..."
docker cp "${CLIENT_ID}:/data/captures/" \
    "${OUTPUT_DIR}/" 2>/dev/null || echo "    (not found)"

# Copy memory dumps
info "Memory dumps..."
docker cp "${SERVER_ID}:/data/dumps/" \
    "${OUTPUT_DIR}/" 2>/dev/null || echo "    (not found)"

echo ""
log "Results collected to: ${OUTPUT_DIR}/"
echo ""
echo "Contents:"
ls -lh "${OUTPUT_DIR}/" | sed 's/^/  /'
echo ""

# Generate summary report
cat > "${OUTPUT_DIR}/SUMMARY.md" << EOF
# SSH Key Extraction Results - ${SERVER}
Generated: $(date)

## Files

- \`lldb_keys.log\` - Keys extracted by LLDB
- \`timing.csv\` - Key lifecycle timing
- \`events.log\` - Detailed LLDB events
- \`groundtruth_keys.log\` - Keys from SSH client
- \`captures/\` - PCAP files
- \`dumps/\` - Memory dumps

## Quick Analysis

### LLDB Keys
\`\`\`
$(cat "${OUTPUT_DIR}/lldb_keys.log" 2>/dev/null || echo "No LLDB keys")
\`\`\`

### Timing Data
\`\`\`
$(cat "${OUTPUT_DIR}/timing.csv" 2>/dev/null || echo "No timing data")
\`\`\`

### Key Lifecycle
$(python3 << 'PYEOF'
import csv
try:
    with open('${OUTPUT_DIR}/timing.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if rows:
        keys = {}
        for row in rows:
            key_id = row['key_id']
            if key_id not in keys:
                keys[key_id] = {}
            keys[key_id][row['event']] = float(row['timestamp'])

        for key_id, events in keys.items():
            print(f"\n**{key_id}:**")
            if 'generated' in events and 'activated' in events:
                delta = events['activated'] - events['generated']
                print(f"- Generation → Activation: {delta:.6f}s")

            cleared = [k for k in events if 'cleared' in k]
            if cleared and 'activated' in events:
                clear_time = max(events[k] for k in cleared)
                delta = clear_time - events['activated']
                print(f"- Activation → Clearing: {delta:.6f}s")

            if 'generated' in events and cleared:
                clear_time = max(events[k] for k in cleared)
                delta = clear_time - events['generated']
                print(f"- Total Lifespan: {delta:.6f}s")
    else:
        print("No timing data")
except:
    print("Error analyzing timing")
PYEOF
)

### PCAP Summary
$(if [[ -d "${OUTPUT_DIR}/captures" ]]; then
    for pcap in "${OUTPUT_DIR}/captures"/*.pcap; do
        if [[ -f "${pcap}" ]]; then
            count=$(tshark -r "${pcap}" 2>/dev/null | wc -l || echo "?")
            echo "- $(basename "${pcap}"): ${count} packets"
        fi
    done
else
    echo "No PCAP files"
fi
)

## Next Steps

1. Compare keys:
   \`\`\`bash
   diff lldb_keys.log groundtruth_keys.log
   \`\`\`

2. Analyze PCAP:
   \`\`\`bash
   tshark -r captures/*.pcap -Y "ssh" -V | less
   \`\`\`

3. Visualize timeline:
   \`\`\`bash
   python3 ../../timing_analysis/timelining_events.py .
   \`\`\`
EOF

echo "Summary report: ${OUTPUT_DIR}/SUMMARY.md"
cat "${OUTPUT_DIR}/SUMMARY.md"
