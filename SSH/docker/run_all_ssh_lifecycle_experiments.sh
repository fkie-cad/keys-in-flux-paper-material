#!/bin/bash
#
# SSH Lifecycle Experiments - Unified Runner
#
# Runs comprehensive SSH key lifecycle experiments across all implementations:
#   - wolfSSH (AEAD cipher, 4 keys, no rekey support)
#   - Dropbear (lightweight, 1-6 keys extraction with toggle)
#   - OpenSSH (full implementation, with optional --with-rekey support)
#
# Each experiment includes:
#   - Key extraction via LLDB hooks
#   - Memory dumps at state transitions
#   - Packet capture for traffic analysis
#   - Validation and reporting
#
# Usage:
#   ./run_all_ssh_lifecycle_experiments.sh [implementation]
#
# Options:
#   all        - Run all implementations (default)
#   wolfssh    - Run wolfSSH only
#   dropbear   - Run Dropbear only
#   openssh    - Run OpenSSH only (FUTURE)
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
IMPLEMENTATIONS="wolfssh dropbear openssh"

# Watchpoint configuration (default: ENABLED)
GLOBAL_WATCHPOINTS="true"
WOLFSSH_WATCHPOINTS="true"  # Disabled due to LLDB exit hang on ARM64/M1
DROPBEAR_WATCHPOINTS="true"  # Disabled due to LLDB exit hang on ARM64/M1
OPENSSH_WATCHPOINTS=""  # Empty means inherit from global

# Experiment mode configuration (default: both base and ku)
EXPERIMENT_MODE="both"  # Options: base, ku, both

# Phase 4: Enhanced monitoring and recovery configuration
ENABLE_RETRY="false"      # Retry failed tests once
MAX_RETRY_ATTEMPTS=1      # Number of retry attempts per test
CLEANUP_TIMEOUT=10        # Seconds to wait for container cleanup verification
CONTAINER_CHECK_RETRIES=3 # Number of retries for stuck container detection

# Parse arguments (flags + positional)
TARGET="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --disable-watchpoints)
            GLOBAL_WATCHPOINTS="false"
            shift
            ;;
        --disable-watchpoints-wolfssh)
            WOLFSSH_WATCHPOINTS="false"
            shift
            ;;
        --disable-watchpoints-dropbear)
            DROPBEAR_WATCHPOINTS="false"
            shift
            ;;
        --disable-watchpoints-openssh)
            OPENSSH_WATCHPOINTS="false"
            shift
            ;;
        --base-only)
            EXPERIMENT_MODE="base"
            shift
            ;;
        --ku-only)
            EXPERIMENT_MODE="ku"
            shift
            ;;
        --with-ku)
            EXPERIMENT_MODE="both"
            shift
            ;;
        --enable-retry)
            ENABLE_RETRY="true"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options] [implementation]"
            echo ""
            echo "Options:"
            echo "  --disable-watchpoints               Disable watchpoints for all clients (global)"
            echo "  --disable-watchpoints-wolfssh       Disable watchpoints for wolfSSH only"
            echo "  --disable-watchpoints-dropbear      Disable watchpoints for Dropbear only"
            echo "  --disable-watchpoints-openssh       Disable watchpoints for OpenSSH only"
            echo "  --base-only                         Run base lifecycle only (no rekey)"
            echo "  --ku-only                           Run key update (rekey) lifecycle only"
            echo "  --with-ku                           Run both base and ku (default)"
            echo "  --enable-retry                      Enable automatic retry for failed tests (Phase 4)"
            echo "  -h, --help                          Show this help message"
            echo ""
            echo "Implementations:"
            echo "  all        - Run all implementations (default)"
            echo "  wolfssh    - Run wolfSSH only"
            echo "  dropbear   - Run Dropbear only"
            echo "  openssh    - Run OpenSSH only"
            echo ""
            echo "Examples:"
            echo "  $0                                  # Run all with watchpoints and both base+ku (default)"
            echo "  $0 --disable-watchpoints all        # Run all without watchpoints"
            echo "  $0 --base-only all                  # Run all implementations, base lifecycle only"
            echo "  $0 --ku-only openssh                # Run OpenSSH only, KU lifecycle only"
            echo "  $0 --disable-watchpoints-dropbear   # Run all, disable watchpoints for Dropbear only"
            echo "  $0 --enable-retry wolfssh           # Run wolfSSH with retry on failure"
            echo "  $0 wolfssh                          # Run wolfSSH only with watchpoints enabled"
            echo ""
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            # Positional argument (implementation target)
            TARGET="$1"
            shift
            ;;
    esac
done

# Apply per-client overrides (if not set, inherit from global)
WOLFSSH_WATCHPOINTS="${WOLFSSH_WATCHPOINTS:-$GLOBAL_WATCHPOINTS}"
DROPBEAR_WATCHPOINTS="${DROPBEAR_WATCHPOINTS:-$GLOBAL_WATCHPOINTS}"
OPENSSH_WATCHPOINTS="${OPENSSH_WATCHPOINTS:-$GLOBAL_WATCHPOINTS}"

# Export for test scripts to use
export LLDB_ENABLE_WATCHPOINTS_WOLFSSH="$WOLFSSH_WATCHPOINTS"
export LLDB_ENABLE_WATCHPOINTS_DROPBEAR="$DROPBEAR_WATCHPOINTS"
export LLDB_ENABLE_WATCHPOINTS_OPENSSH="$OPENSSH_WATCHPOINTS"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="./results/ssh_lifecycle_${TIMESTAMP}"

# Create results directory with base/ and ku/ subdirectories
mkdir -p ${RESULTS_DIR}/base
mkdir -p ${RESULTS_DIR}/ku

echo ""
echo "========================================================================"
echo "  SSH Lifecycle Experiments - Unified Runner"
echo "========================================================================"
echo ""
echo "Timestamp: ${TIMESTAMP}"
echo "Target: ${TARGET}"
echo "Results: ${RESULTS_DIR}"
echo ""
echo "Watchpoint Configuration:"
echo "  wolfSSH:  ${WOLFSSH_WATCHPOINTS}"
echo "  Dropbear: ${DROPBEAR_WATCHPOINTS}"
echo "  OpenSSH:  ${OPENSSH_WATCHPOINTS}"
echo ""
echo "This script runs comprehensive SSH lifecycle experiments with:"
echo "  - Key extraction (LLDB instrumentation)"
echo "  - Memory dumps (pre/post state transitions)"
echo "  - Hardware watchpoints (key overwrite detection)"
echo "  - Packet captures (tcpdump)"
echo "  - Automated validation and reporting"
echo ""
echo "========================================================================"
echo ""

# Cleanup function - run BEFORE each test
cleanup_before_test() {
    local impl=$1
    local mode=$2

    echo -e "${YELLOW}[CLEANUP] Preparing clean environment for ${impl} ${mode}...${NC}"

    # Stop and remove containers for this implementation
    docker compose stop ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true
    docker compose rm -f ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true

    # Clean data directories
    rm -rf data/keylogs/* data/dumps/* data/captures/* data/lldb_results/* 2>/dev/null || true
    mkdir -p data/keylogs data/dumps data/captures data/lldb_results
    chmod -R 777 data

    echo -e "${GREEN}[CLEANUP] ✓ Environment ready${NC}"
}

# Cleanup function - run AFTER each test
cleanup_after_test() {
    local impl=$1
    local mode=$2
    local force=${3:-false}  # Optional: force cleanup even if test succeeded

    echo -e "${YELLOW}[CLEANUP] Cleaning up ${impl} ${mode} containers...${NC}"

    # Stop all containers (give them 5 seconds to stop gracefully)
    docker compose stop ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true
    sleep 1

    # Force remove containers
    docker compose rm -f ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true

    # Remove any orphaned containers from previous runs
    docker ps -a --filter "name=${impl}_client" --filter "status=exited" -q | xargs -r docker rm -f 2>/dev/null || true
    docker ps -a --filter "name=${impl}_server" --filter "status=exited" -q | xargs -r docker rm -f 2>/dev/null || true

    echo -e "${GREEN}[CLEANUP] ✓ Containers removed${NC}"
}

# Trap handler for unexpected errors
cleanup_on_error() {
    local impl=$1
    local mode=$2
    echo -e "${RED}[ERROR] Test interrupted - forcing cleanup...${NC}"
    cleanup_after_test "$impl" "$mode" true
}

# Phase 4: Enhanced health check - verify containers actually stopped
verify_containers_stopped() {
    local impl=$1
    local mode=$2
    local max_retries=${CONTAINER_CHECK_RETRIES}
    local retry=0

    echo -e "${CYAN}[HEALTH CHECK] Verifying containers stopped for ${impl}...${NC}"

    # List of containers to check
    local containers="${impl}_client ${impl}_server openssh_groundtruth"

    while [ $retry -lt $max_retries ]; do
        # Get list of running containers matching our filter
        local running_count=$(docker ps -q --filter "name=${impl}_client" --filter "name=${impl}_server" --filter "name=openssh_groundtruth" | wc -l)

        if [ "$running_count" -eq 0 ]; then
            echo -e "${GREEN}[HEALTH CHECK] ✓ All containers verified stopped${NC}"
            return 0
        else
            echo -e "${YELLOW}[HEALTH CHECK] ⚠️  Attempt $((retry + 1))/${max_retries}: Found ${running_count} running containers${NC}"

            # Force stop remaining containers
            docker compose stop ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true
            sleep 2

            # Force remove if still present
            docker compose rm -f ${impl}_client ${impl}_server openssh_groundtruth 2>/dev/null || true
        fi

        retry=$((retry + 1))
        [ $retry -lt $max_retries ] && sleep ${CLEANUP_TIMEOUT}
    done

    echo -e "${RED}[HEALTH CHECK] ✗ Failed to verify container cleanup after ${max_retries} attempts${NC}"
    return 1
}

# Phase 4: Detect and recover stuck containers
detect_stuck_containers() {
    echo -e "${CYAN}[MONITOR] Scanning for stuck containers...${NC}"

    # Find containers that are in Created or Dead state
    local stuck=$(docker ps -a --filter "status=created" --filter "status=dead" --format "{{.ID}} {{.Names}} {{.Status}}" | grep -E "wolfssh|dropbear|openssh" || echo "")

    if [ -n "$stuck" ]; then
        echo -e "${YELLOW}[MONITOR] ⚠️  Found stuck containers:${NC}"
        echo "$stuck"
        echo -e "${YELLOW}[MONITOR] Cleaning up stuck containers...${NC}"

        # Extract container IDs and remove
        echo "$stuck" | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true

        echo -e "${GREEN}[MONITOR] ✓ Stuck containers removed${NC}"
        return 0
    else
        echo -e "${GREEN}[MONITOR] ✓ No stuck containers detected${NC}"
        return 0
    fi
}

# Phase 4: Enhanced progress logging with timestamps and container status
log_test_status() {
    local impl=$1
    local mode=$2
    local status=$3  # "starting", "running", "completed", "failed"
    local message=${4:-""}

    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$status" in
        starting)
            echo -e "${CYAN}[${timestamp}] [STARTING] ${impl} ${mode} - ${message}${NC}"
            ;;
        running)
            echo -e "${BLUE}[${timestamp}] [RUNNING] ${impl} ${mode} - ${message}${NC}"
            ;;
        completed)
            echo -e "${GREEN}[${timestamp}] [SUCCESS] ${impl} ${mode} - ${message}${NC}"
            ;;
        failed)
            echo -e "${RED}[${timestamp}] [FAILED] ${impl} ${mode} - ${message}${NC}"
            ;;
        retry)
            echo -e "${YELLOW}[${timestamp}] [RETRY] ${impl} ${mode} - ${message}${NC}"
            ;;
        *)
            echo -e "${CYAN}[${timestamp}] [INFO] ${impl} ${mode} - ${message}${NC}"
            ;;
    esac
}

# Phase 4: Get container IDs and status for logging
get_container_status() {
    local impl=$1

    echo ""
    echo -e "${CYAN}[CONTAINER STATUS] ${impl}:${NC}"

    for container in "${impl}_client" "${impl}_server" "openssh_groundtruth"; do
        local cid=$(docker ps -aq --filter "name=^${container}$" --latest)
        if [ -n "$cid" ]; then
            local status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "unknown")
            local created=$(docker inspect -f '{{.Created}}' "$cid" 2>/dev/null | cut -d'T' -f1 || echo "N/A")
            echo "  ${container}: ID=${cid:0:12} Status=${status} Created=${created}"
        else
            echo "  ${container}: Not found"
        fi
    done
    echo ""
}

# ============================================================================
# Event-Based Test Execution with Log Monitoring
# ============================================================================
#
# This function provides event-based monitoring for test execution to handle
# LLDB exit hangs on ARM64/M1. It watches container logs in real-time for
# completion markers and forces cleanup when tests complete successfully but
# LLDB hangs during its own exit phase.
#
# Root cause: SSH sessions complete (keys extracted, logs show "Process exited
# after X stops") but LLDB process hangs during cleanup, causing the container
# to stay alive indefinitely and blocking test orchestration.
#
# Solution: Real-time log monitoring + forced cleanup 2s after completion detection
#
run_test_with_monitoring() {
    local TEST_SCRIPT="$1"
    local IMPL="$2"
    local MODE="$3"
    local COMPLETION_PATTERN="$4"
    local TIMEOUT="${5:-300}"  # Default 5 minutes
    local LOG_FILE="$6"

    echo -e "${CYAN}[MONITOR] Starting monitored test execution${NC}"
    echo -e "${CYAN}[MONITOR] Test: ${TEST_SCRIPT}${NC}"
    echo -e "${CYAN}[MONITOR] Implementation: ${IMPL} (${MODE})${NC}"
    echo -e "${CYAN}[MONITOR] Timeout: ${TIMEOUT}s${NC}"
    echo -e "${CYAN}[MONITOR] Watching for: ${COMPLETION_PATTERN}${NC}"
    echo ""

    # Start test script in background (non-blocking)
    bash "${TEST_SCRIPT}" > "${LOG_FILE}" 2>&1 &
    TEST_PID=$!

    echo -e "${BLUE}[MONITOR] Test script started (PID: ${TEST_PID})${NC}"
    echo -e "${BLUE}[MONITOR] Monitoring test script output in real-time...${NC}"
    echo ""

    # Wait briefly for log file to be created
    sleep 1

    # Real-time log monitoring with completion detection
    # Monitor the test script's output file directly (no need to find ephemeral containers)
    (
        tail -f "${LOG_FILE}" 2>/dev/null | while IFS= read -r line; do
            # Echo the line to display progress in real-time
            echo "$line"

            # Check for completion markers
            if echo "$line" | grep -qE "$COMPLETION_PATTERN"; then
                echo ""
                echo -e "${GREEN}[MONITOR] ✓✓✓ COMPLETION DETECTED! ✓✓✓${NC}"
                echo -e "${GREEN}[MONITOR] Pattern matched: ${COMPLETION_PATTERN}${NC}"
                echo -e "${CYAN}[MONITOR] Waiting 2s grace period for final logs...${NC}"
                sleep 2

                echo -e "${YELLOW}[MONITOR] Forcing test script termination (LLDB exit hang mitigation)...${NC}"

                # Kill the test script process
                kill $TEST_PID 2>/dev/null || true

                # Force cleanup of any lingering containers
                docker compose stop ${IMPL}_client > /dev/null 2>&1 || true
                docker compose rm -f ${IMPL}_client > /dev/null 2>&1 || true

                echo -e "${GREEN}[MONITOR] ✓ Cleanup complete${NC}"

                exit 0
            fi
        done
    ) &
    MONITOR_PID=$!

    # Fallback timeout watcher
    (
        sleep $TIMEOUT

        # Check if monitor is still running
        if ps -p $MONITOR_PID > /dev/null 2>&1; then
            echo ""
            echo -e "${YELLOW}[MONITOR] ⚠️  TIMEOUT reached (${TIMEOUT}s)${NC}"
            echo -e "${YELLOW}[MONITOR] Forcing cleanup...${NC}"

            # Stop monitoring
            kill $MONITOR_PID 2>/dev/null || true

            # Stop container
            if [ -n "$CONTAINER_ID" ]; then
                docker stop $CONTAINER_ID > /dev/null 2>&1 || true
                docker rm -f $CONTAINER_ID > /dev/null 2>&1 || true
            fi

            # Stop test script
            kill $TEST_PID 2>/dev/null || true

            # Check if we got results despite timeout
            local KEYLOG_FILE="data/keylogs/${IMPL}_client_keylog.log"
            if [ -f "$KEYLOG_FILE" ] && [ -s "$KEYLOG_FILE" ]; then
                echo -e "${YELLOW}[MONITOR] ⚠️  Timeout BUT keylog exists - marking as partial success${NC}"
                exit 0
            else
                echo -e "${RED}[MONITOR] ✗ Timeout with no results${NC}"
                exit 1
            fi
        fi
    ) &
    TIMEOUT_PID=$!

    # Wait for either monitor or timeout to finish
    wait $MONITOR_PID 2>/dev/null
    MONITOR_EXIT=$?

    # Kill timeout watcher if monitor finished first
    kill $TIMEOUT_PID 2>/dev/null || true
    wait $TIMEOUT_PID 2>/dev/null || true

    # Wait for test script to finish (if not already killed)
    wait $TEST_PID 2>/dev/null || true

    echo ""
    echo -e "${CYAN}[MONITOR] Monitoring complete (exit: ${MONITOR_EXIT})${NC}"
    echo ""

    return $MONITOR_EXIT
}

# Completion detection patterns per implementation
# These patterns match the log output when LLDB completes monitoring but before exit hang
OPENSSH_COMPLETION_PATTERN="\[OPENSSH_AUTO\] Process exited after.*stops"
DROPBEAR_COMPLETION_PATTERN="\[DROPBEAR_CLIENT_AUTO\] Process exited after.*stops|\[CLIENT_AUTO\] Process exited after.*stops"
WOLFSSH_COMPLETION_PATTERN="\[WOLFSSH_AUTO\] Process exited after.*stops"

# Function to run a single implementation test with watchpoint variant
run_test() {
    local impl=$1
    local mode=$2  # "base" or "ku"
    local watchpoint_variant=$3  # "watchpoints" or "nowatchpoints"
    local test_script=""

    # Select appropriate test script based on mode
    if [ "$mode" = "base" ]; then
        test_script="./test_${impl}_lifecycle.sh"
    elif [ "$mode" = "ku" ]; then
        test_script="./test_${impl}_lifecycle_ku.sh"
    else
        echo -e "${RED}[ERROR] Invalid mode: $mode${NC}"
        return 1
    fi

    # Set trap for cleanup on error
    trap "cleanup_on_error $impl $mode" ERR INT TERM

    # Set watchpoint environment variable based on variant
    # Convert impl to uppercase (Bash 3.x compatible)
    local impl_upper=$(echo "$impl" | tr '[:lower:]' '[:upper:]')

    if [ "$watchpoint_variant" = "watchpoints" ]; then
        export LLDB_ENABLE_WATCHPOINTS_${impl_upper}="true"
        local wp_label="WITH watchpoints"
    else
        export LLDB_ENABLE_WATCHPOINTS_${impl_upper}="false"
        local wp_label="WITHOUT watchpoints"
    fi

    # Directory name includes implementation and watchpoint variant
    local result_dir_name="${impl}_${watchpoint_variant}"

    echo ""
    echo "========================================================================"
    echo -e "${BLUE}  Running ${impl} lifecycle experiment (${mode} mode, ${wp_label})${NC}"
    echo "========================================================================"
    echo ""

    # Phase 4: Enhanced progress logging
    log_test_status "$impl" "$mode" "starting" "Initializing test environment"

    if [ ! -f "${test_script}" ]; then
        echo -e "${RED}[ERROR] Test script not found: ${test_script}${NC}"
        echo -e "${YELLOW}[SKIP] Skipping ${impl} ${mode} ${watchpoint_variant}${NC}"
        echo "skip" > "${RESULTS_DIR}/${mode}/${result_dir_name}_result.txt"
        trap - ERR INT TERM  # Clear trap before returning
        return 1
    fi

    # Phase 4: Detect stuck containers before starting
    detect_stuck_containers

    # PHASE 1: Cleanup before test
    cleanup_before_test "$impl" "$mode"

    # Phase 4: Display container status before test
    get_container_status "$impl"

    # Run test and capture output
    local log_file="${RESULTS_DIR}/${mode}/${result_dir_name}/${impl}_output.log"
    local start_time=$(date +%s)

    # Phase 4: Log test execution
    log_test_status "$impl" "$mode" "running" "Test script: ${test_script}"

    # Create mode/implementation/variant-specific subdirectory
    mkdir -p "${RESULTS_DIR}/${mode}/${result_dir_name}/dumps"

    # Select completion pattern based on implementation
    local completion_pattern=""
    case "$impl" in
        openssh)
            completion_pattern="$OPENSSH_COMPLETION_PATTERN"
            ;;
        dropbear)
            completion_pattern="$DROPBEAR_COMPLETION_PATTERN"
            ;;
        wolfssh)
            completion_pattern="$WOLFSSH_COMPLETION_PATTERN"
            ;;
        *)
            # Fallback generic pattern if implementation is unknown
            completion_pattern="Process exited after.*stops"
            ;;
    esac

    # Use event-based monitoring with LLDB exit hang mitigation
    if run_test_with_monitoring "${test_script}" "${impl}" "${mode}" "${completion_pattern}" 300 "${log_file}"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Phase 4: Enhanced success logging
        log_test_status "$impl" "$mode" "completed" "Duration: ${duration}s"

        echo -e "${GREEN}[SUCCESS] ${impl} (${mode}, ${watchpoint_variant}) completed in ${duration}s${NC}"
        echo "success" > "${RESULTS_DIR}/${mode}/${result_dir_name}_result.txt"
        echo "${duration}" > "${RESULTS_DIR}/${mode}/${result_dir_name}_duration.txt"

        # Copy artifacts to mode/implementation/variant-specific subdirectory
        cp -r ./data/keylogs/${impl}_client_keylog*.log "${RESULTS_DIR}/${mode}/${result_dir_name}/" 2>/dev/null || true
        cp -r ./data/dumps/*.dump "${RESULTS_DIR}/${mode}/${result_dir_name}/dumps/" 2>/dev/null || true
        cp -r ./data/dumps/ssh_events.jsonl "${RESULTS_DIR}/${mode}/${result_dir_name}/" 2>/dev/null || true
        cp -r ./data/captures/${impl}_*.pcap "${RESULTS_DIR}/${mode}/${result_dir_name}/" 2>/dev/null || true

        # Copy timing CSV if it exists (watchpoint-enabled tests only)
        if [ -f "./data/lldb_results/timing_${impl}.csv" ]; then
            cp ./data/lldb_results/timing_${impl}.csv "${RESULTS_DIR}/${mode}/${result_dir_name}/" 2>/dev/null || true
        fi

        # Generate metadata JSON in mode/implementation/variant subdirectory
        bash ./generate_experiment_metadata.sh \
            --implementation "${impl}" \
            --role "client" \
            --start-time "${start_time}" \
            --end-time "${end_time}" \
            --results-dir "${RESULTS_DIR}/${mode}/${result_dir_name}" \
            --status "success" \
            --mode "${mode}" || true

        # PHASE 2: Cleanup after successful test
        cleanup_after_test "$impl" "$mode"

        # Phase 4: Verify containers actually stopped
        verify_containers_stopped "$impl" "$mode"

        trap - ERR INT TERM  # Clear trap after successful completion

        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        # Phase 4: Enhanced failure logging
        log_test_status "$impl" "$mode" "failed" "Duration: ${duration}s"

        echo -e "${RED}[FAILURE] ${impl} (${mode}, ${watchpoint_variant}) failed after ${duration}s${NC}"
        echo "failure" > "${RESULTS_DIR}/${mode}/${result_dir_name}_result.txt"
        echo "${duration}" > "${RESULTS_DIR}/${mode}/${result_dir_name}_duration.txt"

        # Phase 4: Display container status after failure for debugging
        get_container_status "$impl"

        # Generate metadata JSON even for failures (in mode/implementation/variant subdirectory)
        bash ./generate_experiment_metadata.sh \
            --implementation "${impl}" \
            --role "client" \
            --start-time "${start_time}" \
            --end-time "${end_time}" \
            --results-dir "${RESULTS_DIR}/${mode}/${result_dir_name}" \
            --status "failure" \
            --mode "${mode}" || true

        # PHASE 2: Cleanup after failed test
        cleanup_after_test "$impl" "$mode" true

        # Phase 4: Verify cleanup even after failure
        verify_containers_stopped "$impl" "$mode"

        trap - ERR INT TERM  # Clear trap after failure

        return 1
    fi
}

# Main execution logic
if [ "${TARGET}" == "all" ]; then
    # Run all implementations
    echo -e "${CYAN}[INFO] Running all SSH lifecycle experiments...${NC}"
    echo ""

    # Bash 3.x compatible - no associative arrays
    total=0
    success=0
    failed=0
    skipped=0

    # Store results as separate variables
    result_wolfssh=""
    result_dropbear=""
    result_openssh=""

    for impl in ${IMPLEMENTATIONS}; do
        # Run tests based on experiment mode
        case "$EXPERIMENT_MODE" in
            base)
                total=$((total + 1))
                if run_test "${impl}" "base"; then
                    case "${impl}" in
                        wolfssh)   result_wolfssh="✓ PASS (base)" ;;
                        dropbear)  result_dropbear="✓ PASS (base)" ;;
                        openssh)   result_openssh="✓ PASS (base)" ;;
                    esac
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/base/${impl}_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        case "${impl}" in
                            wolfssh)   result_wolfssh="⊘ SKIP (base)" ;;
                            dropbear)  result_dropbear="⊘ SKIP (base)" ;;
                            openssh)   result_openssh="⊘ SKIP (base)" ;;
                        esac
                        skipped=$((skipped + 1))
                    else
                        case "${impl}" in
                            wolfssh)   result_wolfssh="✗ FAIL (base)" ;;
                            dropbear)  result_dropbear="✗ FAIL (base)" ;;
                            openssh)   result_openssh="✗ FAIL (base)" ;;
                        esac
                        failed=$((failed + 1))
                    fi
                fi
                ;;
            ku)
                total=$((total + 1))
                if run_test "${impl}" "ku"; then
                    case "${impl}" in
                        wolfssh)   result_wolfssh="✓ PASS (ku)" ;;
                        dropbear)  result_dropbear="✓ PASS (ku)" ;;
                        openssh)   result_openssh="✓ PASS (ku)" ;;
                    esac
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/ku/${impl}_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        case "${impl}" in
                            wolfssh)   result_wolfssh="⊘ SKIP (ku)" ;;
                            dropbear)  result_dropbear="⊘ SKIP (ku)" ;;
                            openssh)   result_openssh="⊘ SKIP (ku)" ;;
                        esac
                        skipped=$((skipped + 1))
                    else
                        case "${impl}" in
                            wolfssh)   result_wolfssh="✗ FAIL (ku)" ;;
                            dropbear)  result_dropbear="✗ FAIL (ku)" ;;
                            openssh)   result_openssh="✗ FAIL (ku)" ;;
                        esac
                        failed=$((failed + 1))
                    fi
                fi
                ;;
            both)
                # Run both watchpoint variants (nowatchpoints, then watchpoints)
                # This doubles the test count: base+ku with and without watchpoints
                base_nowp_result=""
                base_wp_result=""
                ku_nowp_result=""
                ku_wp_result=""

                # Variant 1: WITHOUT watchpoints (base mode)
                total=$((total + 1))
                if run_test "${impl}" "base" "nowatchpoints"; then
                    base_nowp_result="✓ base-nowp"
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/base/${impl}_nowatchpoints_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        base_nowp_result="⊘ base-nowp"
                        skipped=$((skipped + 1))
                    else
                        base_nowp_result="✗ base-nowp"
                        failed=$((failed + 1))
                    fi
                fi

                # Variant 2: WITH watchpoints (base mode)
                total=$((total + 1))
                if run_test "${impl}" "base" "watchpoints"; then
                    base_wp_result="✓ base-wp"
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/base/${impl}_watchpoints_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        base_wp_result="⊘ base-wp"
                        skipped=$((skipped + 1))
                    else
                        base_wp_result="✗ base-wp"
                        failed=$((failed + 1))
                    fi
                fi

                # Variant 3: WITHOUT watchpoints (ku mode)
                total=$((total + 1))
                if run_test "${impl}" "ku" "nowatchpoints"; then
                    ku_nowp_result="✓ ku-nowp"
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/ku/${impl}_nowatchpoints_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        ku_nowp_result="⊘ ku-nowp"
                        skipped=$((skipped + 1))
                    else
                        ku_nowp_result="✗ ku-nowp"
                        failed=$((failed + 1))
                    fi
                fi

                # Variant 4: WITH watchpoints (ku mode)
                total=$((total + 1))
                if run_test "${impl}" "ku" "watchpoints"; then
                    ku_wp_result="✓ ku-wp"
                    success=$((success + 1))
                else
                    result=$(cat "${RESULTS_DIR}/ku/${impl}_watchpoints_result.txt" 2>/dev/null || echo "failure")
                    if [ "${result}" == "skip" ]; then
                        ku_wp_result="⊘ ku-wp"
                        skipped=$((skipped + 1))
                    else
                        ku_wp_result="✗ ku-wp"
                        failed=$((failed + 1))
                    fi
                fi

                # Combine results (4 tests per implementation)
                case "${impl}" in
                    wolfssh)   result_wolfssh="${base_nowp_result}, ${base_wp_result}, ${ku_nowp_result}, ${ku_wp_result}" ;;
                    dropbear)  result_dropbear="${base_nowp_result}, ${base_wp_result}, ${ku_nowp_result}, ${ku_wp_result}" ;;
                    openssh)   result_openssh="${base_nowp_result}, ${base_wp_result}, ${ku_nowp_result}, ${ku_wp_result}" ;;
                esac
                ;;
        esac

        echo ""
        sleep 2  # Brief pause between tests
    done

    # Generate summary report
    echo ""
    echo "========================================================================"
    echo -e "${CYAN}  EXPERIMENT SUMMARY${NC}"
    echo "========================================================================"
    echo ""
    echo "Total implementations: ${total}"
    echo -e "${GREEN}Success: ${success}${NC}"
    echo -e "${RED}Failed: ${failed}${NC}"
    echo -e "${YELLOW}Skipped: ${skipped}${NC}"
    echo ""
    echo "Results by implementation:"
    for impl in ${IMPLEMENTATIONS}; do
        duration=$(cat "${RESULTS_DIR}/${impl}_duration.txt" 2>/dev/null || echo "N/A")
        case "${impl}" in
            wolfssh)   echo "  ${impl}: ${result_wolfssh} (${duration}s)" ;;
            dropbear)  echo "  ${impl}: ${result_dropbear} (${duration}s)" ;;
            openssh)   echo "  ${impl}: ${result_openssh} (${duration}s)" ;;
        esac
    done
    echo ""
    echo "Detailed results: ${RESULTS_DIR}"
    echo ""

    # Create summary file
    cat > "${RESULTS_DIR}/summary.txt" << EOF
SSH Lifecycle Experiments - Summary
=====================================
Timestamp: ${TIMESTAMP}
Total: ${total}
Success: ${success}
Failed: ${failed}
Skipped: ${skipped}

Results by Implementation:
EOF

    for impl in ${IMPLEMENTATIONS}; do
        duration=$(cat "${RESULTS_DIR}/${impl}_duration.txt" 2>/dev/null || echo "N/A")
        case "${impl}" in
            wolfssh)   echo "  ${impl}: ${result_wolfssh} (${duration}s)" >> "${RESULTS_DIR}/summary.txt" ;;
            dropbear)  echo "  ${impl}: ${result_dropbear} (${duration}s)" >> "${RESULTS_DIR}/summary.txt" ;;
            openssh)   echo "  ${impl}: ${result_openssh} (${duration}s)" >> "${RESULTS_DIR}/summary.txt" ;;
        esac
    done

    echo "" >> "${RESULTS_DIR}/summary.txt"
    echo "Log files available in ${RESULTS_DIR}/" >> "${RESULTS_DIR}/summary.txt"

    # Exit with failure if any tests failed
    if [ ${failed} -gt 0 ]; then
        echo -e "${RED}[OVERALL] Some experiments failed - check ${RESULTS_DIR}/ for details${NC}"
        exit 1
    else
        echo -e "${GREEN}[OVERALL] All experiments completed successfully!${NC}"
        exit 0
    fi

elif [ "${TARGET}" == "wolfssh" ] || [ "${TARGET}" == "dropbear" ] || [ "${TARGET}" == "openssh" ]; then
    # Run single implementation
    echo -e "${CYAN}[INFO] Running ${TARGET} lifecycle experiment (mode: ${EXPERIMENT_MODE})...${NC}"
    echo ""

    overall_success=true

    case "$EXPERIMENT_MODE" in
        base)
            if run_test "${TARGET}" "base"; then
                echo ""
                echo -e "${GREEN}[SUCCESS] ${TARGET} base experiment completed${NC}"
            else
                echo ""
                echo -e "${RED}[FAILURE] ${TARGET} base experiment failed${NC}"
                overall_success=false
            fi
            ;;
        ku)
            if run_test "${TARGET}" "ku"; then
                echo ""
                echo -e "${GREEN}[SUCCESS] ${TARGET} ku experiment completed${NC}"
            else
                echo ""
                echo -e "${RED}[FAILURE] ${TARGET} ku experiment failed${NC}"
                overall_success=false
            fi
            ;;
        both)
            if run_test "${TARGET}" "base"; then
                echo ""
                echo -e "${GREEN}[SUCCESS] ${TARGET} base experiment completed${NC}"
            else
                echo ""
                echo -e "${RED}[FAILURE] ${TARGET} base experiment failed${NC}"
                overall_success=false
            fi

            if run_test "${TARGET}" "ku"; then
                echo ""
                echo -e "${GREEN}[SUCCESS] ${TARGET} ku experiment completed${NC}"
            else
                echo ""
                echo -e "${RED}[FAILURE] ${TARGET} ku experiment failed${NC}"
                overall_success=false
            fi
            ;;
    esac

    echo ""
    echo -e "${CYAN}[INFO] Results saved to: ${RESULTS_DIR}/${NC}"

    if [ "$overall_success" = true ]; then
        exit 0
    else
        exit 1
    fi

else
    echo -e "${RED}[ERROR] Invalid target: ${TARGET}${NC}"
    echo ""
    echo "Usage: $0 [options] [implementation]"
    echo ""
    echo "Run --help for detailed usage information"
    echo ""
    exit 1
fi
