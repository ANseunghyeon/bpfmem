#!/bin/bash
# =============================================================================
# run_single_policy.sh
#
# Run experiment with a single fixed cache policy.
# Useful for debugging or quick single-policy tests.
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration (can be overridden by env vars)
POLICY="${POLICY:-s3fifo}"
CGROUP_PATH="${CGROUP_PATH:-/sys/fs/cgroup/cacheext_14w}"
DATA_DIR="${DATA_DIR:-/tmp/14weeks_data}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/14weeks_results/$POLICY}"
FILE_SIZE_MB="${FILE_SIZE_MB:-128}"
WORKING_SET_MB="${WORKING_SET_MB:-32}"
PHASE_ITERATIONS="${PHASE_ITERATIONS:-2}"
CGROUP_MEMORY_MB="${CGROUP_MEMORY_MB:-64}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Run single policy test.

Options:
    -p, --policy NAME     Policy to use (default: $POLICY)
                          Options: fifo, mru, s3fifo, lhd, sampling, mglru
    -s, --size MB         Data file size in MB (default: $FILE_SIZE_MB)
    -w, --working-set MB  Working set size in MB (default: $WORKING_SET_MB)
    -m, --memory MB       Cgroup memory limit (default: $CGROUP_MEMORY_MB)
    -i, --iterations N    Iterations per phase (default: $PHASE_ITERATIONS)
    -o, --output DIR      Results output directory
    -h, --help            Show this help
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--policy) POLICY="$2"; shift 2 ;;
        -s|--size) FILE_SIZE_MB="$2"; shift 2 ;;
        -w|--working-set) WORKING_SET_MB="$2"; shift 2 ;;
        -m|--memory) CGROUP_MEMORY_MB="$2"; shift 2 ;;
        -i|--iterations) PHASE_ITERATIONS="$2"; shift 2 ;;
        -o|--output) RESULTS_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: Must run as root"
    exit 1
fi

# Build if needed
if [[ ! -x "$SCRIPT_DIR/multi_phase_workload" ]]; then
    echo "[INFO] Building workload..."
    (cd "$SCRIPT_DIR" && make multi_phase_workload)
fi

# Setup directories
mkdir -p "$DATA_DIR" "$RESULTS_DIR"

# Setup cgroup
setup_cgroup() {
    mkdir -p "$CGROUP_PATH"
    echo "+memory" > "$(dirname "$CGROUP_PATH")/cgroup.subtree_control" 2>/dev/null || true
    echo "$((CGROUP_MEMORY_MB * 1024 * 1024))" > "$CGROUP_PATH/memory.max" 2>/dev/null || true
}

cleanup() {
    # Kill policy loader
    pkill -f "cache_ext_${POLICY}.out" 2>/dev/null || true
    
    # Kill any remaining cgroup processes
    if [[ -f "$CGROUP_PATH/cgroup.procs" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs"
    fi
    sleep 1
    rmdir "$CGROUP_PATH" 2>/dev/null || true
}

trap cleanup EXIT

# Drop caches
sync
echo 3 > /proc/sys/vm/drop_caches

# Setup cgroup
cleanup  # Clean any previous state
setup_cgroup

echo ""
echo "========================================"
echo "Single Policy Test: $POLICY"
echo "========================================"
echo "File size:     ${FILE_SIZE_MB} MB"
echo "Working set:   ${WORKING_SET_MB} MB"
echo "Memory limit:  ${CGROUP_MEMORY_MB} MB"
echo "Iterations:    $PHASE_ITERATIONS"
echo "Results:       $RESULTS_DIR"
echo ""

# Start policy loader (except for mglru which is kernel-native)
if [[ "$POLICY" != "mglru" ]]; then
    # Disable MGLRU
    echo 0 > /sys/kernel/mm/lru_gen/enabled 2>/dev/null || true
    
    LOADER="$ROOT/policies/cache_ext_${POLICY}.out"
    if [[ ! -x "$LOADER" ]]; then
        echo "Error: Policy loader not found: $LOADER"
        exit 1
    fi
    
    echo "[INFO] Starting policy loader: $POLICY"
    
    LOADER_ARGS=(--watch_dir "$DATA_DIR" --cgroup_path "$CGROUP_PATH")
    if [[ "$POLICY" == "s3fifo" ]]; then
        LOADER_ARGS+=(--cgroup_size "$((CGROUP_MEMORY_MB * 1024 * 1024))")
    fi
    
    # Use named pipe to keep loader running
    FIFO_PATH="/tmp/14weeks_single_policy_fifo_$$"
    mkfifo "$FIFO_PATH" 2>/dev/null || true
    
    "$LOADER" "${LOADER_ARGS[@]}" < "$FIFO_PATH" > "$RESULTS_DIR/loader.log" 2>&1 &
    LOADER_PID=$!
    
    sleep infinity > "$FIFO_PATH" &
    FIFO_KEEPER_PID=$!
    
    sleep 2
    
    if ! kill -0 $LOADER_PID 2>/dev/null; then
        echo "Error: Policy loader died"
        cat "$RESULTS_DIR/loader.log"
        kill $FIFO_KEEPER_PID 2>/dev/null || true
        rm -f "$FIFO_PATH"
        exit 1
    fi
else
    # Enable MGLRU for mglru variant
    echo 7 > /sys/kernel/mm/lru_gen/enabled 2>/dev/null || true
    echo "[INFO] Using kernel MGLRU"
fi

# Join cgroup
echo $$ > "$CGROUP_PATH/cgroup.procs"

# Run workload
echo "[INFO] Running workload..."
"$SCRIPT_DIR/multi_phase_workload" \
    --size "$FILE_SIZE_MB" \
    --working-set "$WORKING_SET_MB" \
    --iterations "$PHASE_ITERATIONS" \
    --data-dir "$DATA_DIR" \
    --output-dir "$RESULTS_DIR" \
    --latency

EXIT_CODE=$?

# Stop loader
if [[ "$POLICY" != "mglru" ]] && [[ -n "${LOADER_PID:-}" ]]; then
    kill $FIFO_KEEPER_PID 2>/dev/null || true
    sleep 1
    kill -INT $LOADER_PID 2>/dev/null || true
    wait $LOADER_PID 2>/dev/null || true
    rm -f "$FIFO_PATH"
fi

# Results
echo ""
echo "[DONE] Results saved to: $RESULTS_DIR"
if [[ -f "$RESULTS_DIR/summary.json" ]]; then
    cat "$RESULTS_DIR/summary.json"
fi

exit $EXIT_CODE

