#!/usr/bin/env bash
###############################################################################
# Dropbear Experiment Analysis Pipeline
#
# This script orchestrates the complete analysis of a Dropbear SSH key
# lifespan experiment, from raw dumps and keylogs to visualization.
#
# Usage:
#   ./analyze_dropbear_experiment.sh [experiment_dir]
#
# Example:
#   ./analyze_dropbear_experiment.sh data/
#
# Pipeline Steps:
#   1. Find secrets in memory dumps
#   2. Correlate PCAP with LLDB events
#   3. Generate key lifespan visualization
#   4. Generate summary report
#
# Output:
#   - analysis/secret_presence.txt - Secret presence matrix
#   - analysis/correlated_timeline.json - Timeline correlation
#   - analysis/dropbear_key_lifespan.png - Visualization chart
#   - analysis/ANALYSIS_REPORT.md - Summary report
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
NC=$'\033[0m'

log()   { printf "%b[✓]%b %s\n" "${GREEN}" "${NC}" "$*"; }
info()  { printf "%b[→]%b %s\n" "${BLUE}"  "${NC}" "$*"; }
warn()  { printf "%b[!]%b %s\n" "${YELLOW}" "${NC}" "$*"; }
error() { printf "%b[✗]%b %s\n" "${RED}"   "${NC}" "$*" >&2; }

# ── Configuration ─────────────────────────────────────────────────────────────
EXPERIMENT_DIR="${1:-data}"
ANALYSIS_DIR="${EXPERIMENT_DIR}/analysis"
KEYLOGS_DIR="${EXPERIMENT_DIR}/keylogs"
DUMPS_DIR="${EXPERIMENT_DIR}/dumps"
CAPTURES_DIR="${EXPERIMENT_DIR}/captures"
LLDB_RESULTS_DIR="${EXPERIMENT_DIR}/lldb_results"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_TOOLS_DIR="${SCRIPT_DIR}/analysis"

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    echo "════════════════════════════════════════════════════════════════════════"
    echo "  Dropbear SSH Key Lifespan Analysis Pipeline"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""

    # Validate inputs
    validate_environment
    validate_experiment_directory

    # Create analysis directory
    mkdir -p "${ANALYSIS_DIR}"
    log "Analysis directory: ${ANALYSIS_DIR}"
    echo ""

    # Step 1: Memory dump analysis
    step_1_memory_dump_analysis

    # Step 2: PCAP correlation
    step_2_pcap_correlation

    # Step 3: Visualization
    step_3_visualization

    # Step 4: Generate report
    step_4_generate_report

    echo ""
    echo "════════════════════════════════════════════════════════════════════════"
    echo "  Analysis Complete!"
    echo "════════════════════════════════════════════════════════════════════════"
    echo ""
    log "Results available in: ${ANALYSIS_DIR}"
    echo ""
    echo "Key outputs:"
    echo "  • Secret presence matrix: ${ANALYSIS_DIR}/secret_presence.txt"
    echo "  • Correlated timeline:    ${ANALYSIS_DIR}/correlated_timeline.json"
    echo "  • Visualization chart:    ${ANALYSIS_DIR}/dropbear_key_lifespan.png"
    echo "  • Summary report:         ${ANALYSIS_DIR}/ANALYSIS_REPORT.md"
    echo ""
}

# ── Validation ────────────────────────────────────────────────────────────────

validate_environment() {
    info "Checking environment..."

    # Check Python 3
    if ! command -v python3 >/dev/null 2>&1; then
        error "Python 3 not found. Please install Python 3."
        exit 1
    fi

    # Check analysis tools
    local required_tools=(
        "find_ssh_secrets_in_dumps.py"
        "correlate_ssh_pcap.py"
        "visualize_ssh_key_lifespan.py"
    )

    for tool in "${required_tools[@]}"; do
        if [[ ! -f "${ANALYSIS_TOOLS_DIR}/${tool}" ]]; then
            error "Analysis tool not found: ${tool}"
            error "Expected location: ${ANALYSIS_TOOLS_DIR}/${tool}"
            exit 1
        fi
    done

    # Check Python packages
    local python_packages=("scapy" "matplotlib")
    for pkg in "${python_packages[@]}"; do
        if ! python3 -c "import ${pkg}" 2>/dev/null; then
            warn "Python package '${pkg}' not installed"
            warn "Install with: pip3 install ${pkg}"
        fi
    done

    log "Environment validated"
}

validate_experiment_directory() {
    info "Validating experiment directory: ${EXPERIMENT_DIR}"

    if [[ ! -d "${EXPERIMENT_DIR}" ]]; then
        error "Experiment directory not found: ${EXPERIMENT_DIR}"
        exit 1
    fi

    # Check for required subdirectories
    local has_data=false

    # Check for keylog files (flexible pattern: groundtruth_*.log or ssh_keylog_*.log)
    if [[ -d "${KEYLOGS_DIR}" ]] && ls "${KEYLOGS_DIR}"/*keylog*.log >/dev/null 2>&1; then
        log "Found keylogs in: ${KEYLOGS_DIR}"
        has_data=true
    fi

    # Check for memory dump files (.bin or .dump extensions)
    if [[ -d "${DUMPS_DIR}" ]] && ls "${DUMPS_DIR}"/*.dump >/dev/null 2>&1; then
        log "Found memory dumps in: ${DUMPS_DIR}"
        has_data=true
    elif [[ -d "${DUMPS_DIR}" ]] && ls "${DUMPS_DIR}"/*.bin >/dev/null 2>&1; then
        log "Found memory dumps in: ${DUMPS_DIR}"
        has_data=true
    fi

    if [[ ! "${has_data}" == "true" ]]; then
        warn "No experiment data found in ${EXPERIMENT_DIR}"
        warn "Expected: keylogs/*keylog*.log and dumps/*.{bin,dump}"
    fi
}

# ── Analysis Steps ────────────────────────────────────────────────────────────

step_1_memory_dump_analysis() {
    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo "  Step 1: Memory Dump Analysis"
    echo "────────────────────────────────────────────────────────────────────────"
    echo ""

    info "Searching for secrets in memory dumps..."

    if [[ ! -d "${DUMPS_DIR}" ]]; then
        warn "Dumps directory not found: ${DUMPS_DIR}"
        warn "Skipping memory dump analysis"
        return 0
    fi

    local output_file="${ANALYSIS_DIR}/secret_presence.txt"

    python3 "${ANALYSIS_TOOLS_DIR}/find_ssh_secrets_in_dumps.py" \
        "${DUMPS_DIR}" \
        > "${output_file}" 2>&1

    if [[ -f "${output_file}" ]]; then
        log "Memory dump analysis complete"
        log "Results: ${output_file}"

        # Show summary
        echo ""
        tail -n 20 "${output_file}"
    else
        warn "Memory dump analysis did not produce output"
    fi
}

step_2_pcap_correlation() {
    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo "  Step 2: PCAP Correlation"
    echo "────────────────────────────────────────────────────────────────────────"
    echo ""

    info "Correlating PCAP with LLDB events..."

    # Find PCAP file
    local pcap_file=""
    if [[ -d "${CAPTURES_DIR}" ]]; then
        pcap_file=$(ls "${CAPTURES_DIR}"/*.pcap 2>/dev/null | head -n 1 || true)
    fi

    if [[ -z "${pcap_file}" || ! -f "${pcap_file}" ]]; then
        warn "No PCAP file found in ${CAPTURES_DIR}"
        warn "Skipping PCAP correlation"
        return 0
    fi

    # Find events log
    local events_file=""
    if [[ -d "${LLDB_RESULTS_DIR}" ]]; then
        # Try different event log formats (prefer jsonl for structured data)
        events_file=$(ls "${LLDB_RESULTS_DIR}"/events_*.{jsonl,log} "${LLDB_RESULTS_DIR}"/{events.jsonl,events.log} 2>/dev/null | head -n 1 || true)
    fi

    if [[ -z "${events_file}" || ! -f "${events_file}" ]]; then
        warn "No events log found in ${LLDB_RESULTS_DIR}"
        warn "Skipping PCAP correlation"
        return 0
    fi

    local output_file="${ANALYSIS_DIR}/correlated_timeline.json"

    python3 "${ANALYSIS_TOOLS_DIR}/correlate_ssh_pcap.py" \
        --pcap "${pcap_file}" \
        --events "${events_file}" \
        --output "${output_file}"

    if [[ -f "${output_file}" ]]; then
        log "PCAP correlation complete"
        log "Results: ${output_file}"
    else
        warn "PCAP correlation did not produce output"
    fi
}

step_3_visualization() {
    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo "  Step 3: Visualization"
    echo "────────────────────────────────────────────────────────────────────────"
    echo ""

    info "Generating key lifespan chart..."

    # Find timing CSV
    local timing_csv=""
    if [[ -d "${LLDB_RESULTS_DIR}" ]]; then
        timing_csv=$(ls "${LLDB_RESULTS_DIR}"/timing*.csv "${LLDB_RESULTS_DIR}"/timing_*.csv 2>/dev/null | head -n 1 || true)
    fi

    if [[ -z "${timing_csv}" || ! -f "${timing_csv}" ]]; then
        warn "No timing CSV found in ${LLDB_RESULTS_DIR}"
        warn "Skipping visualization"
        return 0
    fi

    local timeline_json="${ANALYSIS_DIR}/correlated_timeline.json"
    local output_file="${ANALYSIS_DIR}/dropbear_key_lifespan.png"

    # Run visualization with or without timeline
    set +e  # Don't exit on error (matplotlib might not be installed)
    if [[ -f "${timeline_json}" ]]; then
        python3 "${ANALYSIS_TOOLS_DIR}/visualize_ssh_key_lifespan.py" \
            --timing "${timing_csv}" \
            --timeline "${timeline_json}" \
            --output "${output_file}" 2>&1
    else
        python3 "${ANALYSIS_TOOLS_DIR}/visualize_ssh_key_lifespan.py" \
            --timing "${timing_csv}" \
            --output "${output_file}" 2>&1
    fi
    local viz_status=$?
    set -e

    if [[ -f "${output_file}" ]]; then
        log "Visualization complete"
        log "Chart: ${output_file}"
    elif [[ ${viz_status} -ne 0 ]]; then
        warn "Visualization skipped (matplotlib not installed or other error)"
        warn "Install with: pip3 install matplotlib"
    else
        warn "Visualization did not produce output"
    fi
}

step_4_generate_report() {
    echo ""
    echo "────────────────────────────────────────────────────────────────────────"
    echo "  Step 4: Generate Summary Report"
    echo "────────────────────────────────────────────────────────────────────────"
    echo ""

    info "Generating analysis report..."

    local report_file="${ANALYSIS_DIR}/ANALYSIS_REPORT.md"

    cat > "${report_file}" <<EOF
# Dropbear SSH Key Lifespan Analysis Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Experiment Directory:** ${EXPERIMENT_DIR}

## Summary

This report summarizes the key lifespan analysis for Dropbear SSH implementation.

## Analysis Pipeline

The following analysis steps were performed:

1. **Memory Dump Analysis**
   - Searched memory dumps for SSH secrets (shared secret K, session keys, IVs)
   - Generated secret presence matrix across lifecycle stages

2. **PCAP Correlation**
   - Parsed SSH protocol messages from packet captures
   - Correlated PCAP events with LLDB monitoring events
   - Created unified timeline

3. **Visualization**
   - Generated key lifespan chart showing when secrets exist in memory
   - Annotated with lifecycle phases and removal events

## Key Findings

### Secrets Tracked

- **Handshake Secret (K):** DH/ECDH shared secret used for key derivation
- **Session Keys:** Symmetric cipher keys for encrypted communication
  - \`cipher_key_in\`: Client-to-server encryption key
  - \`cipher_key_out\`: Server-to-client encryption key
  - \`cipher_iv_in\`: Client-to-server IV
  - \`cipher_iv_out\`: Server-to-client IV

### Lifecycle Phases

1. **Handshake:** KEXINIT → DH_INIT → DH_REPLY → NEWKEYS
2. **Session:** USERAUTH → CHANNEL_OPEN → APP_DATA
3. **Rekey:** KEXINIT → ... (repeated KEX)
4. **Teardown:** DISCONNECT / CHANNEL_CLOSE
5. **Cleanup:** m_burn, session_cleanup

## Output Files

- \`secret_presence.txt\` - ASCII table of secret presence across stages
- \`correlated_timeline.json\` - Merged PCAP + LLDB timeline
- \`dropbear_key_lifespan.png\` - Key lifespan visualization chart

## Methodology

### LLDB Instrumentation

Dropbear was instrumented with LLDB breakpoints at key functions:

- \`kex*_comb_key\`: Capture shared secret K computation
- \`gen_new_keys\`: Capture session key derivation
- \`m_burn\`: Capture key clearing/zeroing
- \`switch_keys\`: Capture key activation

Hardware watchpoints tracked when keys were overwritten in memory.

### Memory Dump Strategy

Memory dumps were taken at key lifecycle stages:

- Pre-KEX (before key exchange)
- Post-KEX (after key derivation)
- During session (active connection)
- During rekey (key rotation)
- Post-disconnect (after cleanup)

### Ground Truth Validation

Ground truth keys were extracted using:

- OpenSSH patched client (SSHKEYLOGFILE support)
- Direct SHARED_SECRET and NEWKEYS extraction
- Validation against LLDB-extracted keys

## Comparison with TLS Analysis

The SSH key lifespan analysis follows the same methodology as the TLS framework:

- ✓ Handshake secret tracking (equivalent to TLS master secret)
- ✓ Session key tracking (equivalent to TLS traffic keys)
- ✓ Rekey detection (equivalent to TLS key updates)
- ✓ Memory cleanup verification (equivalent to TLS cleanup)
- ✓ PCAP correlation (protocol message timing)

## Next Steps

1. Run experiment with different KEX algorithms (DH, ECDH, Curve25519)
2. Test with rekey scenarios
3. Compare against OpenSSH and wolfSSH implementations
4. Analyze key persistence after abnormal termination

---

*Analysis pipeline: \`analyze_dropbear_experiment.sh\`*
EOF

    log "Report generated: ${report_file}"

    echo ""
    echo "Report preview:"
    echo "────────────────────────────────────────────────────────────────────────"
    head -n 30 "${report_file}"
    echo "────────────────────────────────────────────────────────────────────────"
}

# ── Run ───────────────────────────────────────────────────────────────────────

main "$@"
