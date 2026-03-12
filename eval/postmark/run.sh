#!/bin/bash
# Postmark run script
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
RESULTS_PATH="$BASE_DIR/results/postmark"
POSTMARK_BIN=$(which postmark)

WORK_DIR="/mnt/nvme/postmark_data"
CACHE_SIZE=$((4 * 1024 * 1024 * 1024)) 
ITERATIONS=3

PM_FILES=50000
PM_SIZES="20480 204800" 
PM_TRANSACTIONS=200000
PM_SUBDIRS=200

mkdir -p "$WORK_DIR"
mkdir -p "$RESULTS_PATH"

if [ -z "$POSTMARK_BIN" ]; then
    echo "Postmark binary not found. Please install postmark (e.g., sudo apt install postmark)."
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

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Run baseline first (without policy)
echo "Running baseline (no policy)"
cmd="python3 $BENCH_PATH/bench_postmark.py \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/postmark_baseline_results.json \
	--postmark-bin $POSTMARK_BIN \
    --work-dir $WORK_DIR \
    --pm-files $PM_FILES \
    --pm-sizes \"$PM_SIZES\" \
    --pm-transactions $PM_TRANSACTIONS \
    --pm-subdirs $PM_SUBDIRS \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
    --cgroup-size $CACHE_SIZE \
    --results-dir $RESULTS_PATH"

eval $cmd

# Run cache_ext policies
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	cmd="python3 $BENCH_PATH/bench_postmark.py \
		--policy-loader $POLICY_PATH/${POLICY}.out \
		--results-file $RESULTS_PATH/postmark_${POLICY}_results.json \
		--postmark-bin $POSTMARK_BIN \
        --work-dir $WORK_DIR \
        --pm-files $PM_FILES \
        --pm-sizes \"$PM_SIZES\" \
        --pm-transactions $PM_TRANSACTIONS \
        --pm-subdirs $PM_SUBDIRS \
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
cmd="python3 $BENCH_PATH/bench_postmark.py \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/postmark_mglru_results.json \
	--postmark-bin $POSTMARK_BIN \
    --work-dir $WORK_DIR \
    --pm-files $PM_FILES \
    --pm-sizes \"$PM_SIZES\" \
    --pm-transactions $PM_TRANSACTIONS \
    --pm-subdirs $PM_SUBDIRS \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
    --cgroup-size $CACHE_SIZE \
    --results-dir $RESULTS_PATH"
eval $cmd

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "Postmark benchmark completed. Results saved to $RESULTS_PATH."
