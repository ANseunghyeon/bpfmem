#!/bin/bash
# LMbench run script
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
RESULTS_PATH="$BASE_DIR/results/lmbench"
LMBENCH_DIR="$BASE_DIR/lmbench"

# Configuration for 8GB RAM / 4GB Cgroup / NVMe environment
DATA_DIR="/mnt/nvme/lmbench_data"
CACHE_SIZE=$((4 * 1024 * 1024 * 1024)) # 4GB cgroup limit
ITERATIONS=3

# Ensure data directory exists
mkdir -p "$DATA_DIR"
mkdir -p "$RESULTS_PATH"

# Build LMbench if needed
if [[ ! -f "$LMBENCH_DIR/bin/x86_64-linux-gnu/lat_mmap" ]] && [[ ! -f "$LMBENCH_DIR/bin/lat_mmap" ]]; then
    echo "Building LMbench..."
    if [[ -d "$LMBENCH_DIR" ]]; then
        cd "$LMBENCH_DIR"
        make results
        cd "$BASE_DIR"
    else
        echo "LMbench directory not found at $LMBENCH_DIR"
        echo "Please install LMbench."
        exit 1
    fi
fi

POLICIES=(
	"cache_ext_lhd"
    "cache_ext_fifo"
	"cache_ext_s3fifo"
	"cache_ext_sampling"
	"cache_ext_mru"
	"cache_ext_mglru"
)

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Run baseline first (without policy)
echo "Running baseline (no policy)"
cmd="python3 $BENCH_PATH/bench_lmbench.py \
	--cpu 8 \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/lmbench_baseline_results.json \
	--lmbench-dir $LMBENCH_DIR \
    --test-name suite \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
    --cgroup-size $CACHE_SIZE \
    --results-dir $RESULTS_PATH"

eval $cmd

# Run cache_ext policies
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	cmd="python3 $BENCH_PATH/bench_lmbench.py \
		--cpu 8 \
		--policy-loader $POLICY_PATH/${POLICY}.out \
		--results-file $RESULTS_PATH/lmbench_${POLICY}_results.json \
		--lmbench-dir $LMBENCH_DIR \
        --test-name suite \
		--fadvise-hints \"\" \
		--iterations $ITERATIONS \
		--cache-ext-only \
        --cgroup-size $CACHE_SIZE \
        --results-dir $RESULTS_PATH"
    eval $cmd
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
echo "Running baseline MGLRU"
cmd="python3 $BENCH_PATH/bench_lmbench.py \
	--cpu 8 \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/lmbench_mglru_results.json \
	--lmbench-dir $LMBENCH_DIR \
    --test-name suite \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
    --cgroup-size $CACHE_SIZE"
eval $cmd

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "LMbench benchmark completed. Results saved to $RESULTS_PATH."
