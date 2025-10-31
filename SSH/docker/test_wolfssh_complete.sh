#!/bin/bash
# wolfSSH Complete Automated Test Suite
#
# Orchestrates both test runs and generates comparison analysis:
#   - Run 1: Basic session (connection → commands → close)
#   - Run 2: Rekey session (connection → commands → rekey → commands → close)
#
# Validates:
#   - Key extraction and keylog generation
#   - Memory dumps at all checkpoints
#   - Event logging with microsecond timestamps
#   - Rekey detection and tracking

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "  wolfSSH Complete Automated Test Suite"
echo "======================================================================"
echo ""
echo "This will run two test scenarios:"
echo "  1. Basic session (single KEX)"
echo "  2. Rekey session (multiple KEX)"
echo ""
echo "Total estimated time: ~5 minutes"
echo ""

# Configuration
MASTER_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MASTER_RESULTS="data/results/wolfssh_complete_${MASTER_TIMESTAMP}"

mkdir -p "$MASTER_RESULTS"

# Create test summary file
SUMMARY_FILE="$MASTER_RESULTS/test_summary.txt"

cat > "$SUMMARY_FILE" <<EOF
====================================================================
  wolfSSH Complete Test Suite - Results Summary
====================================================================

Test Date: $(date)
Master Results: $MASTER_RESULTS

====================================================================
EOF

# Function to log to both console and summary
log_summary() {
    echo "$1"
    echo "$1" >> "$SUMMARY_FILE"
}

echo "======================================================================"
echo "  Run 1: Basic Session"
echo "======================================================================"
echo ""

# Run Test 1
if ./test_wolfssh_run1_basic.sh; then
    RUN1_STATUS="✓ SUCCESS"
    RUN1_EXIT=0
else
    RUN1_STATUS="✗ FAILED"
    RUN1_EXIT=$?
fi

# Save Run 1 results
RUN1_RESULTS=$(find data/results -type d -name "wolfssh_run1_basic_*" | sort | tail -1)
if [ -n "$RUN1_RESULTS" ]; then
    cp -r "$RUN1_RESULTS" "$MASTER_RESULTS/run1_basic"
    log_summary "Run 1: $RUN1_STATUS"
    log_summary "  Results: $MASTER_RESULTS/run1_basic"
else
    log_summary "Run 1: $RUN1_STATUS (no results directory found)"
fi

echo ""
echo "======================================================================"
echo "  Run 2: Rekey Session"
echo "======================================================================"
echo ""

# Wait between runs
sleep 5

# Run Test 2
if ./test_wolfssh_run2_rekey.sh; then
    RUN2_STATUS="✓ SUCCESS"
    RUN2_EXIT=0
else
    RUN2_STATUS="✗ FAILED"
    RUN2_EXIT=$?
fi

# Save Run 2 results
RUN2_RESULTS=$(find data/results -type d -name "wolfssh_run2_rekey_*" | sort | tail -1)
if [ -n "$RUN2_RESULTS" ]; then
    cp -r "$RUN2_RESULTS" "$MASTER_RESULTS/run2_rekey"
    log_summary "Run 2: $RUN2_STATUS"
    log_summary "  Results: $MASTER_RESULTS/run2_rekey"
else
    log_summary "Run 2: $RUN2_STATUS (no results directory found)"
fi

echo ""
echo "======================================================================"
echo "  Comparative Analysis"
echo "======================================================================"
echo ""

log_summary ""
log_summary "======================================================================"
log_summary "  Comparative Analysis"
log_summary "======================================================================"
log_summary ""

# Compare Run 1 vs Run 2
if [ -d "$MASTER_RESULTS/run1_basic" ] && [ -d "$MASTER_RESULTS/run2_rekey" ]; then
    # Count keylogs
    RUN1_KEYLOG="$MASTER_RESULTS/run1_basic/wolfssh_keylog.log"
    RUN2_KEYLOG="$MASTER_RESULTS/run2_rekey/wolfssh_keylog.log"

    if [ -f "$RUN1_KEYLOG" ]; then
        RUN1_KEYS=$(grep -c "NEWKEYS" "$RUN1_KEYLOG" || echo "0")
    else
        RUN1_KEYS="N/A"
    fi

    if [ -f "$RUN2_KEYLOG" ]; then
        RUN2_KEYS=$(grep -c "NEWKEYS" "$RUN2_KEYLOG" || echo "0")
    else
        RUN2_KEYS="N/A"
    fi

    log_summary "Keylog Comparison:"
    log_summary "  Run 1 (Basic):  $RUN1_KEYS NEWKEYS entries"
    log_summary "  Run 2 (Rekey):  $RUN2_KEYS NEWKEYS entries"

    if [ "$RUN2_KEYS" != "N/A" ] && [ "$RUN1_KEYS" != "N/A" ]; then
        if [ "$RUN2_KEYS" -gt "$RUN1_KEYS" ]; then
            log_summary "  ✓ Run 2 has more keys (rekey successful)"
        else
            log_summary "  ⚠️  Run 2 does not have more keys (rekey may not have occurred)"
        fi
    fi

    log_summary ""

    # Count memory dumps
    RUN1_DUMPS=$(find "$MASTER_RESULTS/run1_basic" -name "wolfssh_*.dump" 2>/dev/null | wc -l)
    RUN2_DUMPS=$(find "$MASTER_RESULTS/run2_rekey" -name "wolfssh_*.dump" 2>/dev/null | wc -l)

    log_summary "Memory Dumps Comparison:"
    log_summary "  Run 1 (Basic):  $RUN1_DUMPS dumps"
    log_summary "  Run 2 (Rekey):  $RUN2_DUMPS dumps"

    if [ "$RUN2_DUMPS" -gt "$RUN1_DUMPS" ]; then
        log_summary "  ✓ Run 2 has more dumps (rekey captured)"
    fi

    log_summary ""

    # Check event logs
    RUN1_EVENTS="$MASTER_RESULTS/run1_basic/wolfssh_events.log"
    RUN2_EVENTS="$MASTER_RESULTS/run2_rekey/wolfssh_events.log"

    if [ -f "$RUN1_EVENTS" ]; then
        RUN1_KEX=$(grep -c "KEX_ENTRY\|REKEY_ENTRY" "$RUN1_EVENTS" || echo "0")
    else
        RUN1_KEX="N/A"
    fi

    if [ -f "$RUN2_EVENTS" ]; then
        RUN2_KEX=$(grep -c "KEX_ENTRY\|REKEY_ENTRY" "$RUN2_EVENTS" || echo "0")
        RUN2_REKEY=$(grep -c "REKEY_ENTRY" "$RUN2_EVENTS" || echo "0")
    else
        RUN2_KEX="N/A"
        RUN2_REKEY="N/A"
    fi

    log_summary "KEX Cycles Comparison:"
    log_summary "  Run 1 (Basic):  $RUN1_KEX KEX cycles"
    log_summary "  Run 2 (Rekey):  $RUN2_KEX KEX cycles ($RUN2_REKEY rekeys)"

    if [ "$RUN2_KEX" != "N/A" ] && [ "$RUN1_KEX" != "N/A" ]; then
        if [ "$RUN2_KEX" -gt "$RUN1_KEX" ]; then
            log_summary "  ✓ Run 2 has more KEX cycles (rekey successful)"
        else
            log_summary "  ⚠️  Run 2 does not have more KEX cycles (rekey may not have occurred)"
        fi
    fi
else
    log_summary "⚠️  Could not perform comparison (missing results)"
fi

log_summary ""
log_summary "======================================================================"
log_summary "  Final Summary"
log_summary "======================================================================"
log_summary ""
log_summary "Master Results: $MASTER_RESULTS"
log_summary ""
log_summary "Run 1 Status: $RUN1_STATUS"
log_summary "Run 2 Status: $RUN2_STATUS"
log_summary ""

# Overall status
if [ $RUN1_EXIT -eq 0 ] && [ $RUN2_EXIT -eq 0 ]; then
    OVERALL_STATUS="✓ ALL TESTS PASSED"
    OVERALL_EXIT=0
elif [ $RUN1_EXIT -eq 0 ] || [ $RUN2_EXIT -eq 0 ]; then
    OVERALL_STATUS="⚠️  PARTIAL SUCCESS"
    OVERALL_EXIT=1
else
    OVERALL_STATUS="✗ ALL TESTS FAILED"
    OVERALL_EXIT=2
fi

log_summary "Overall Status: $OVERALL_STATUS"
log_summary ""

echo ""
echo "======================================================================"
echo "  Test Suite Complete"
echo "======================================================================"
echo ""
cat "$SUMMARY_FILE"
echo ""
echo "Detailed Results:"
echo "  Summary:     $SUMMARY_FILE"
echo "  Run 1:       $MASTER_RESULTS/run1_basic/"
echo "  Run 2:       $MASTER_RESULTS/run2_rekey/"
echo ""
echo "Next Steps:"
echo "  - Review summary: cat $SUMMARY_FILE"
echo "  - Compare keylogs:"
echo "      diff $MASTER_RESULTS/run1_basic/wolfssh_keylog.log \\"
echo "           $MASTER_RESULTS/run2_rekey/wolfssh_keylog.log"
echo "  - Analyze timing:"
echo "      cat $MASTER_RESULTS/run1_basic/wolfssh_events.log"
echo "      cat $MASTER_RESULTS/run2_rekey/wolfssh_events.log"
echo "  - Inspect memory dumps:"
echo "      ls -lh $MASTER_RESULTS/run1_basic/wolfssh_*.dump"
echo "      ls -lh $MASTER_RESULTS/run2_rekey/wolfssh_*.dump"
echo ""

# Create README in results directory
cat > "$MASTER_RESULTS/README.md" <<'EOF'
# wolfSSH Complete Test Results

This directory contains results from the complete wolfSSH automated test suite.

## Directory Structure

```
.
├── README.md           # This file
├── test_summary.txt    # Test results summary
├── run1_basic/         # Run 1: Basic session results
│   ├── wolfssh_keylog.log
│   ├── wolfssh_events.log
│   └── wolfssh_*.dump
└── run2_rekey/         # Run 2: Rekey session results
    ├── wolfssh_keylog.log
    ├── wolfssh_events.log
    └── wolfssh_*.dump
```

## Test Scenarios

### Run 1: Basic Session
- Connection establishment
- Predefined commands (ls, hostname, pwd)
- Session close
- **Expected**: 1 KEX cycle, 2-4 memory dumps

### Run 2: Rekey Session
- Connection establishment
- Initial commands
- SSH rekey trigger
- Post-rekey commands
- Session close
- **Expected**: 2+ KEX cycles, 4-8 memory dumps

## Key Files

- **wolfssh_keylog.log**: Extracted encryption keys in NEWKEYS format
- **wolfssh_events.log**: Timestamped LLDB event log (microsecond precision)
- **wolfssh_*.dump**: Memory dumps at key lifecycle checkpoints

## Analysis Commands

```bash
# View key extraction
cat run1_basic/wolfssh_keylog.log
cat run2_rekey/wolfssh_keylog.log

# Compare key counts
wc -l run1_basic/wolfssh_keylog.log run2_rekey/wolfssh_keylog.log

# View event timeline
cat run1_basic/wolfssh_events.log | grep -E "KEX_|REKEY_"
cat run2_rekey/wolfssh_events.log | grep -E "KEX_|REKEY_"

# Count memory dumps
find run1_basic -name "wolfssh_*.dump" | wc -l
find run2_rekey -name "wolfssh_*.dump" | wc -l

# List dump types
find run1_basic -name "wolfssh_*.dump" -exec basename {} \; | sort
find run2_rekey -name "wolfssh_*.dump" -exec basename {} \; | sort
```

## Expected Rekey Indicators

If rekey was successful in Run 2:
- More NEWKEYS entries than Run 1
- REKEY_ENTRY/REKEY_EXIT events in event log
- Additional memory dumps with "rekey" prefix
- KEX counter > 1 in event metadata

## Notes

- wolfSSH may not support OpenSSH ~R escape sequence
- Rekey may require manual triggering or data volume thresholds
- Check wolfSSH documentation for rekey configuration
EOF

echo "✓ Test suite completed with status: $OVERALL_STATUS"
echo ""

exit $OVERALL_EXIT
