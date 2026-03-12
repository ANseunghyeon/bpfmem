#!/bin/bash
# Mobibench run script (Option B: Large File I/O for Page Cache Eviction Test)
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
    echo "This script is intended to be run on a cache_ext kernel."
    echo "Please switch to the cache_ext kernel and try again."
    exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
RESULTS_PATH="$BASE_DIR/results/mobibench"
MOBIBENCH_DIR="$BASE_DIR/Mobibench/shell"
MOBIBENCH_BIN="$MOBIBENCH_DIR/mobibench"

TEST_DIR="/mnt/nvme/mobibench_test"
ITERATIONS=1
NUM_THREADS=8

CACHE_SIZE=$((4 * 1024 * 1024 * 1024))

FILE_SIZE_KB=$((5 * 1024 * 1024))
RECORD_SIZE_KB=4

SYNC_MODE_STR="normal"

mkdir -p "$RESULTS_PATH"
mkdir -p "$TEST_DIR"

if [ ! -f "$MOBIBENCH_BIN" ]; then
    echo "Mobibench binary not found at $MOBIBENCH_BIN"
    echo "Please build mobibench first."
    exit 1
fi

POLICIES=(
    "cache_ext_lhd"
    "cache_ext_fifo"
    "cache_ext_s3fifo"
    "cache_ext_sampling"
    "cache_ext_mru"
    "cache_ext_mglru"
)

if ! "$BASE_DIR/utils/disable-mglru.sh"; then
    echo "Failed to disable MGLRU. Please check the script."
    exit 1
fi

run_suite_for_config() {
    local config_name=$1
    local policy_arg=$2
    local policy_loader=$3
    local results_prefix=$4

    echo "Running Suite for $config_name..."

    echo "  [1] Sequential Write Mode (8GB)"
    rm -rf "$TEST_DIR"/*
    python3 "$BENCH_PATH/bench_mobibench.py" \
        --mobibench-binary "$MOBIBENCH_BIN" \
        --test-dir "$TEST_DIR" \
        --policy-loader "$policy_loader" \
        --results-file "$RESULTS_PATH/${results_prefix}_seq_write.json" \
        --file-size-kb "$FILE_SIZE_KB" \
        --record-size-kb "$RECORD_SIZE_KB" \
        --access-mode "write" \
        --sync-mode "$SYNC_MODE_STR" \
        --cgroup-size "$CACHE_SIZE" \
        --iterations "$ITERATIONS" \
        --num-threads "$NUM_THREADS" \
        --cpu "$NUM_THREADS" \
        $policy_arg

    echo "  [2] Random Write Mode (8GB)"
    rm -rf "$TEST_DIR"/*
    python3 "$BENCH_PATH/bench_mobibench.py" \
        --mobibench-binary "$MOBIBENCH_BIN" \
        --test-dir "$TEST_DIR" \
        --policy-loader "$policy_loader" \
        --results-file "$RESULTS_PATH/${results_prefix}_rnd_write.json" \
        --file-size-kb "$FILE_SIZE_KB" \
        --record-size-kb "$RECORD_SIZE_KB" \
        --access-mode "rnd_write" \
        --sync-mode "$SYNC_MODE_STR" \
        --cgroup-size "$CACHE_SIZE" \
        --iterations "$ITERATIONS" \
        --num-threads "$NUM_THREADS" \
        --cpu "$NUM_THREADS" \
        $policy_arg
}

run_suite_for_config "baseline" "--default-only" "$POLICY_PATH/cache_ext_lhd.out" "mobibench_baseline"

for POLICY in "${POLICIES[@]}"; do
    run_suite_for_config "$POLICY" "--cache-ext-only" "$POLICY_PATH/${POLICY}.out" "mobibench_${POLICY}"
done

if ! "$BASE_DIR/utils/enable-mglru.sh"; then
    echo "Failed to enable MGLRU."
    exit 1
fi

run_suite_for_config "mglru" "--default-only" "$POLICY_PATH/cache_ext_lhd.out" "mobibench_mglru"

if ! "$BASE_DIR/utils/disable-mglru.sh"; then
    echo "Failed to disable MGLRU."
    exit 1
fi

echo "Mobibench benchmark completed. Results saved to $RESULTS_PATH."