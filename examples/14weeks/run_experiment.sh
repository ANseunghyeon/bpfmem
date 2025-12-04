#!/usr/bin/env bash
# =============================================================================
# run_experiment.sh
# 
# Master script for running the 14weeks cache policy evaluation experiment.
# Runs multi-phase workload under different policies and collects results.
# =============================================================================

# Ensure we're running in bash (not sh/dash)
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Error: This script requires bash. Run with: bash $0" >&2
    exit 1
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# =============================================================================
# Default Configuration
# =============================================================================

# Paths
export CGROUP_PATH="${CGROUP_PATH:-/sys/fs/cgroup/cache_ext_14w}"
export DATA_DIR="${DATA_DIR:-/tmp/14weeks_data}"
export RESULTS_BASE="${RESULTS_BASE:-$ROOT/examples/result/14weeks}"
export RUN_STAMP="${RUN_STAMP:-$(date +%Y%m%d-%H%M%S)}"

# Workload parameters
export FILE_SIZE_MB="${FILE_SIZE_MB:-256}"
export WORKING_SET_MB="${WORKING_SET_MB:-64}"
export PHASE_ITERATIONS="${PHASE_ITERATIONS:-3}"
export MEASURE_LATENCY="${MEASURE_LATENCY:-1}"

# Cgroup memory limit (should be less than working set to induce evictions)
export CGROUP_MEMORY_MB="${CGROUP_MEMORY_MB:-128}"
export CGROUP_SIZE_BYTES=$((CGROUP_MEMORY_MB * 1024 * 1024))

# Policy switching parameters
export MIN_SWITCH_MS="${MIN_SWITCH_MS:-2000}"
export ANALYSIS_WINDOW_MS="${ANALYSIS_WINDOW_MS:-500}"

# Variants to run
export VARIANTS="${VARIANTS:-mglru,fifo,mru,s3fifo,dynamic}"
export DROP_CACHES="${DROP_CACHES:-1}"
export WAIT_BETWEEN_SEC="${WAIT_BETWEEN_SEC:-5}"

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo "[INFO] $(date '+%H:%M:%S') $*"
}

log_error() {
    echo "[ERROR] $(date '+%H:%M:%S') $*" >&2
}

log_section() {
    echo ""
    echo "========================================================================"
    echo "$*"
    echo "========================================================================"
}

# Cleanup handler for script interruption
cleanup_on_exit() {
    log_info "Script interrupted, performing cleanup..."
    kill_policy_loaders 2>/dev/null || true
    cleanup_cgroup 2>/dev/null || true
    log_info "Cleanup complete"
}

trap cleanup_on_exit EXIT INT TERM

check_kernel() {
    if ! uname -r | grep -q "cache-ext"; then
        log_error "This experiment requires a cache_ext kernel (uname -r should contain 'cache-ext')"
        log_error "Current kernel: $(uname -r)"
        exit 1
    fi
    log_info "Kernel check passed: $(uname -r)"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for cgroup management and BPF)"
        exit 1
    fi
}

setup_cgroup() {
    log_info "Setting up cgroup: $CGROUP_PATH"
    
    # Create cgroup if not exists
    if [[ ! -d "$CGROUP_PATH" ]]; then
        mkdir -p "$CGROUP_PATH"
    fi
    
    # Enable memory controller
    if [[ -f "$CGROUP_PATH/../cgroup.subtree_control" ]]; then
        echo "+memory" > "$CGROUP_PATH/../cgroup.subtree_control" 2>/dev/null || true
    fi
    
    # Set memory limit
    local mem_limit=$((CGROUP_MEMORY_MB * 1024 * 1024))
    if [[ -f "$CGROUP_PATH/memory.max" ]]; then
        echo "$mem_limit" > "$CGROUP_PATH/memory.max"
        log_info "Memory limit set to ${CGROUP_MEMORY_MB}MB"
    elif [[ -f "$CGROUP_PATH/memory.limit_in_bytes" ]]; then
        echo "$mem_limit" > "$CGROUP_PATH/memory.limit_in_bytes"
        log_info "Memory limit set to ${CGROUP_MEMORY_MB}MB (v1)"
    else
        log_error "Cannot set memory limit - no memory controller file found"
    fi
}

cleanup_cgroup() {
    log_info "Cleaning up cgroup: $CGROUP_PATH"
    
    # First, try to move all processes to parent cgroup (safer than killing)
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        local parent_cg="$(dirname "$CGROUP_PATH")"
        while read -r pid; do
            if [[ -n "$pid" ]] && [[ "$pid" -gt 0 ]]; then
                echo "$pid" > "$parent_cg/cgroup.procs" 2>/dev/null || true
            fi
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    
    sleep 1
    
    # If any processes still remain, kill them
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r pid; do
            if [[ -n "$pid" ]] && [[ "$pid" -gt 0 ]]; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    
    # Wait for processes to exit
    sleep 1
    
    # Remove cgroup
    rmdir "$CGROUP_PATH" 2>/dev/null || true
}

drop_caches() {
    if [[ "$DROP_CACHES" == "1" ]]; then
        sync
        echo 3 > /proc/sys/vm/drop_caches
        log_info "Page cache dropped"
    fi
}

enable_mglru() {
    if [[ -f /sys/kernel/mm/lru_gen/enabled ]]; then
        echo 7 > /sys/kernel/mm/lru_gen/enabled 2>/dev/null || true
        log_info "MGLRU enabled"
    fi
}

disable_mglru() {
    if [[ -f /sys/kernel/mm/lru_gen/enabled ]]; then
        echo 0 > /sys/kernel/mm/lru_gen/enabled 2>/dev/null || true
        log_info "MGLRU disabled"
    fi
}

kill_policy_loaders() {
    # First try graceful shutdown
    pkill -INT -f 'cache_ext_.*\.out' 2>/dev/null || true
    pkill -INT -f 'dynamic_policy_controller' 2>/dev/null || true
    sleep 2
    
    # Then force kill if still running
    pkill -9 -f 'cache_ext_.*\.out' 2>/dev/null || true
    pkill -9 -f 'dynamic_policy_controller' 2>/dev/null || true
    
    # Kill any fifo keepers
    pkill -9 -f 'sleep infinity' 2>/dev/null || true
    rm -f /tmp/14weeks_loader_fifo_* 2>/dev/null || true
    
    sleep 1
}

# =============================================================================
# Run Single Variant
# =============================================================================

run_variant() {
    local variant="$1"
    local run_dir="$RESULTS_BASE/$RUN_STAMP/$variant"
    
    log_section "Running variant: $variant"
    
    mkdir -p "$run_dir"
    
    # IMPORTANT: First, kill any leftover policy loaders from previous runs
    # This must happen BEFORE we setup the new cgroup
    log_info "Ensuring no stale policy loaders..."
    kill_policy_loaders
    
    # Setup fresh cgroup
    cleanup_cgroup
    
    # Extra wait to let kernel settle after cleanup
    sleep 2
    
    setup_cgroup
    drop_caches
    
    # Start time
    local start_time=$(date +%s.%N)
    local start_ns=$(date +%s%N)
    
    # Save kernel messages before
    dmesg > "$run_dir/kmsg_before.txt" 2>/dev/null || true
    
    case "$variant" in
        mglru)
            run_mglru_variant "$run_dir"
            ;;
        fifo)
            run_single_policy_variant "$run_dir" "fifo"
            ;;
        mru)
            run_single_policy_variant "$run_dir" "mru"
            ;;
        s3fifo)
            run_single_policy_variant "$run_dir" "s3fifo"
            ;;
        lhd)
            run_single_policy_variant "$run_dir" "lhd"
            ;;
        sampling)
            run_single_policy_variant "$run_dir" "sampling"
            ;;
        dynamic)
            run_dynamic_variant "$run_dir"
            ;;
        *)
            log_error "Unknown variant: $variant"
            return 1
            ;;
    esac
    
    local exit_code=$?
    local end_time=$(date +%s.%N)
    local end_ns=$(date +%s%N)
    
    # Save kernel messages after
    dmesg > "$run_dir/kmsg_after.txt" 2>/dev/null || true
    
    # Calculate makespan
    local makespan=$(echo "$end_time - $start_time" | bc)
    
    # Save metadata
    cat > "$run_dir/meta.json" <<EOF
{
    "variant": "$variant",
    "run_stamp": "$RUN_STAMP",
    "start_ns": $start_ns,
    "end_ns": $end_ns,
    "makespan_sec": $makespan,
    "file_size_mb": $FILE_SIZE_MB,
    "working_set_mb": $WORKING_SET_MB,
    "cgroup_memory_mb": $CGROUP_MEMORY_MB,
    "phase_iterations": $PHASE_ITERATIONS,
    "exit_code": $exit_code
}
EOF
    
    log_info "Variant $variant completed in ${makespan}s (exit: $exit_code)"
    
    # Cleanup
    kill_policy_loaders
    cleanup_cgroup
    
    return $exit_code
}

run_mglru_variant() {
    local run_dir="$1"
    
    log_info "Running Linux MGLRU baseline"
    
    # Enable MGLRU
    enable_mglru
    
    # Run workload in a subshell that joins the cgroup
    # This prevents the main script from being killed when cgroup is cleaned up
    (
        echo $BASHPID > "$CGROUP_PATH/cgroup.procs"
        exec "$SCRIPT_DIR/multi_phase_workload" \
            --size "$FILE_SIZE_MB" \
            --working-set "$WORKING_SET_MB" \
            --iterations "$PHASE_ITERATIONS" \
            --data-dir "$DATA_DIR" \
            --output-dir "$run_dir" \
            $([ "$MEASURE_LATENCY" == "1" ] && echo "--latency")
    ) 2>&1 | tee "$run_dir/workload.log"
    
    local wl_exit=${PIPESTATUS[0]}
    
    # Disable MGLRU for next runs
    disable_mglru
    
    return $wl_exit
}

run_single_policy_variant() {
    local run_dir="$1"
    local policy="$2"
    
    log_info "Running single policy: $policy"
    
    # Disable MGLRU (we use BPF policies)
    disable_mglru
    
    # Start policy loader
    local loader="$ROOT/policies/cache_ext_${policy}.out"
    if [[ ! -x "$loader" ]]; then
        log_error "Policy loader not found: $loader"
        return 1
    fi
    
    log_info "Starting policy loader: $loader"
    
    local loader_args=(
        "--watch_dir" "$DATA_DIR"
        "--cgroup_path" "$CGROUP_PATH"
    )
    
    if [[ "$policy" == "s3fifo" ]]; then
        loader_args+=("--cgroup_size" "$CGROUP_SIZE_BYTES")
    fi
    
    # Run loader with stdin from /dev/null to prevent getchar() issues
    # Use a named pipe to keep it running until we explicitly stop it
    local fifo_path="/tmp/14weeks_loader_fifo_$$"
    mkfifo "$fifo_path" 2>/dev/null || true
    
    # Start loader reading from fifo (blocks until we write to it)
    "$loader" "${loader_args[@]}" < "$fifo_path" > "$run_dir/loader.log" 2>&1 &
    local loader_pid=$!
    
    # Keep fifo open with a background cat that we'll kill later
    sleep infinity > "$fifo_path" &
    local fifo_keeper_pid=$!
    
    sleep 3  # Wait for loader to attach
    
    if ! kill -0 $loader_pid 2>/dev/null; then
        log_error "Policy loader died prematurely"
        cat "$run_dir/loader.log"
        kill $fifo_keeper_pid 2>/dev/null || true
        rm -f "$fifo_path"
        return 1
    fi
    
    log_info "Policy loader running (PID: $loader_pid)"
    
    # Run workload in a subshell that joins the cgroup
    (
        echo $BASHPID > "$CGROUP_PATH/cgroup.procs"
        exec "$SCRIPT_DIR/multi_phase_workload" \
            --size "$FILE_SIZE_MB" \
            --working-set "$WORKING_SET_MB" \
            --iterations "$PHASE_ITERATIONS" \
            --data-dir "$DATA_DIR" \
            --output-dir "$run_dir" \
            $([ "$MEASURE_LATENCY" == "1" ] && echo "--latency")
    ) 2>&1 | tee "$run_dir/workload.log"
    
    local wl_exit=${PIPESTATUS[0]}
    
    log_info "Workload completed, stopping policy loader safely..."
    
    # First, make sure no processes are using the cgroup
    # Move any remaining processes out of the cgroup before stopping loader
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r pid; do
            # Try to move process to parent cgroup
            echo "$pid" > "$(dirname "$CGROUP_PATH")/cgroup.procs" 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    
    # Give kernel time to settle
    sleep 1
    
    # Now safely stop the loader by closing the fifo (triggers getchar() to return)
    kill $fifo_keeper_pid 2>/dev/null || true
    
    # Wait for loader to exit gracefully
    local wait_count=0
    while kill -0 $loader_pid 2>/dev/null && [[ $wait_count -lt 10 ]]; do
        sleep 0.5
        wait_count=$((wait_count + 1))
    done
    
    # If still running, send SIGINT
    if kill -0 $loader_pid 2>/dev/null; then
        log_info "Sending SIGINT to loader"
        kill -INT $loader_pid 2>/dev/null || true
        sleep 1
    fi
    
    # Final cleanup
    kill -9 $loader_pid 2>/dev/null || true
    wait $loader_pid 2>/dev/null || true
    rm -f "$fifo_path"
    
    log_info "Policy loader stopped"
    
    return $wl_exit
}

run_dynamic_variant() {
    local run_dir="$1"
    
    log_info "Running dynamic policy switching"
    
    # Disable MGLRU
    disable_mglru
    
    # Start dynamic controller
    local controller="$SCRIPT_DIR/dynamic_policy_controller"
    if [[ ! -x "$controller" ]]; then
        log_error "Dynamic controller not found: $controller"
        return 1
    fi
    
    log_info "Starting dynamic policy controller"
    
    "$controller" \
        --cgroup "$CGROUP_PATH" \
        --watch-dir "$DATA_DIR" \
        --cgroup-size "$CGROUP_SIZE_BYTES" \
        --min-switch "$MIN_SWITCH_MS" \
        --window "$ANALYSIS_WINDOW_MS" \
        --output "$run_dir/controller" \
        --verbose \
        > "$run_dir/controller.log" 2>&1 &
    local ctrl_pid=$!
    
    sleep 3  # Wait for controller to initialize
    
    if ! kill -0 $ctrl_pid 2>/dev/null; then
        log_error "Dynamic controller died prematurely"
        cat "$run_dir/controller.log"
        return 1
    fi
    
    # Run workload in a subshell that joins the cgroup
    (
        echo $BASHPID > "$CGROUP_PATH/cgroup.procs"
        exec "$SCRIPT_DIR/multi_phase_workload" \
            --size "$FILE_SIZE_MB" \
            --working-set "$WORKING_SET_MB" \
            --iterations "$PHASE_ITERATIONS" \
            --data-dir "$DATA_DIR" \
            --output-dir "$run_dir" \
            $([ "$MEASURE_LATENCY" == "1" ] && echo "--latency")
    ) 2>&1 | tee "$run_dir/workload.log"
    
    local wl_exit=${PIPESTATUS[0]}
    
    log_info "Workload completed, stopping dynamic controller safely..."
    
    # First, move processes out of cgroup
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        local parent_cg="$(dirname "$CGROUP_PATH")"
        while read -r pid; do
            if [[ -n "$pid" ]] && [[ "$pid" -gt 0 ]]; then
                echo "$pid" > "$parent_cg/cgroup.procs" 2>/dev/null || true
            fi
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    
    # Give kernel time to settle
    sleep 1
    
    # Stop controller gracefully
    kill -INT $ctrl_pid 2>/dev/null || true
    
    # Wait for controller to exit
    local wait_count=0
    while kill -0 $ctrl_pid 2>/dev/null && [[ $wait_count -lt 10 ]]; do
        sleep 0.5
        wait_count=$((wait_count + 1))
    done
    
    # Force kill if still running
    kill -9 $ctrl_pid 2>/dev/null || true
    wait $ctrl_pid 2>/dev/null || true
    
    log_info "Dynamic controller stopped"
    
    # Copy controller outputs
    if [[ -d "$run_dir/controller" ]]; then
        cp -r "$run_dir/controller/"* "$run_dir/" 2>/dev/null || true
    fi
    
    return $wl_exit
}

# =============================================================================
# Results Collection
# =============================================================================

collect_results() {
    log_section "Collecting Results"
    
    local results_dir="$RESULTS_BASE/$RUN_STAMP"
    
    # Create summary CSV
    local summary_csv="$results_dir/makespan.csv"
    echo "variant,makespan_sec,exit_code" > "$summary_csv"
    
    for variant_dir in "$results_dir"/*/; do
        local variant=$(basename "$variant_dir")
        if [[ -f "$variant_dir/meta.json" ]]; then
            local makespan=$(grep -o '"makespan_sec": [0-9.]*' "$variant_dir/meta.json" | cut -d' ' -f2)
            local exit_code=$(grep -o '"exit_code": [0-9]*' "$variant_dir/meta.json" | cut -d' ' -f2)
            echo "$variant,$makespan,$exit_code" >> "$summary_csv"
        fi
    done
    
    log_info "Summary written to: $summary_csv"
    cat "$summary_csv"
}

plot_results() {
    log_section "Generating Plots"
    
    if command -v python3 &> /dev/null; then
        python3 "$SCRIPT_DIR/plot_results.py" \
            --input "$RESULTS_BASE/$RUN_STAMP" \
            --output "$RESULTS_BASE/$RUN_STAMP" \
            2>&1 || log_error "Plotting failed"
    else
        log_error "python3 not found, skipping plots"
    fi
}

# =============================================================================
# Main
# =============================================================================

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Run the 14weeks cache policy evaluation experiment.

Options:
    -s, --size MB           Data file size in MB (default: $FILE_SIZE_MB)
    -w, --working-set MB    Working set size in MB (default: $WORKING_SET_MB)
    -m, --memory MB         Cgroup memory limit in MB (default: $CGROUP_MEMORY_MB)
    -i, --iterations N      Iterations per phase (default: $PHASE_ITERATIONS)
    -v, --variants LIST     Comma-separated variants (default: $VARIANTS)
    -o, --output DIR        Results output base directory
    -l, --latency           Enable per-access latency measurement
    --no-drop-caches        Don't drop caches between variants
    -h, --help              Show this help

Available variants:
    mglru       - Linux MGLRU baseline
    fifo        - Single FIFO policy
    mru         - Single MRU policy
    s3fifo      - Single S3-FIFO policy
    lhd         - Single LHD policy
    sampling    - Single Sampling policy
    dynamic     - Dynamic policy switching

Example:
    sudo ./run_experiment.sh --size 512 --memory 256 --variants mglru,fifo,dynamic
EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--size)
                FILE_SIZE_MB="$2"; shift 2 ;;
            -w|--working-set)
                WORKING_SET_MB="$2"; shift 2 ;;
            -m|--memory)
                CGROUP_MEMORY_MB="$2"
                CGROUP_SIZE_BYTES=$((CGROUP_MEMORY_MB * 1024 * 1024))
                shift 2 ;;
            -i|--iterations)
                PHASE_ITERATIONS="$2"; shift 2 ;;
            -v|--variants)
                VARIANTS="$2"; shift 2 ;;
            -o|--output)
                RESULTS_BASE="$2"; shift 2 ;;
            -l|--latency)
                MEASURE_LATENCY=1; shift ;;
            --no-drop-caches)
                DROP_CACHES=0; shift ;;
            -h|--help)
                usage; exit 0 ;;
            *)
                log_error "Unknown option: $1"
                usage; exit 1 ;;
        esac
    done
    
    log_section "14weeks Cache Policy Experiment"
    
    # Checks
    check_root
    check_kernel
    
    # Create directories
    mkdir -p "$DATA_DIR"
    mkdir -p "$RESULTS_BASE/$RUN_STAMP"
    
    # Print configuration
    log_info "Configuration:"
    log_info "  Run stamp:     $RUN_STAMP"
    log_info "  File size:     ${FILE_SIZE_MB} MB"
    log_info "  Working set:   ${WORKING_SET_MB} MB"
    log_info "  Memory limit:  ${CGROUP_MEMORY_MB} MB"
    log_info "  Iterations:    $PHASE_ITERATIONS"
    log_info "  Variants:      $VARIANTS"
    log_info "  Results:       $RESULTS_BASE/$RUN_STAMP"
    
    # Build if needed
    if [[ ! -x "$SCRIPT_DIR/multi_phase_workload" ]]; then
        log_info "Building workload..."
        (cd "$SCRIPT_DIR" && make multi_phase_workload)
    fi
    
    if [[ ! -x "$SCRIPT_DIR/dynamic_policy_controller" ]]; then
        log_info "Building dynamic controller..."
        (cd "$SCRIPT_DIR" && make dynamic_policy_controller)
    fi
    
    # Ensure clean start - kill any leftover loaders
    log_info "Ensuring clean state before starting..."
    kill_policy_loaders
    cleanup_cgroup
    sleep 2
    
    # Run variants
    IFS=',' read -ra VARIANT_ARRAY <<< "$VARIANTS"
    local failed_variants=()
    
    for variant in "${VARIANT_ARRAY[@]}"; do
        variant=$(echo "$variant" | tr -d ' ')
        if ! run_variant "$variant"; then
            failed_variants+=("$variant")
            log_error "Variant $variant failed, continuing with cleanup..."
        fi
        
        # Extra cleanup after each variant
        log_info "Post-variant cleanup..."
        kill_policy_loaders
        cleanup_cgroup
        
        # Wait between variants
        if [[ "$variant" != "${VARIANT_ARRAY[-1]}" ]]; then
            log_info "Waiting ${WAIT_BETWEEN_SEC}s before next variant..."
            sleep "$WAIT_BETWEEN_SEC"
        fi
    done
    
    # Final cleanup
    log_info "Final cleanup..."
    kill_policy_loaders
    cleanup_cgroup
    
    # Collect and plot results
    collect_results
    plot_results
    
    log_section "Experiment Complete"
    log_info "Results saved to: $RESULTS_BASE/$RUN_STAMP"
    
    if [[ ${#failed_variants[@]} -gt 0 ]]; then
        log_error "Failed variants: ${failed_variants[*]}"
        exit 1
    fi
}

main "$@"

