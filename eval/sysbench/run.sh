#!/bin/bash
# Sysbench run script
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
RESULTS_PATH="$BASE_DIR/results/sysbench"

# Default values
TEST_DIR="/mnt/nvme/sysbench_test"
ITERATIONS=1
NUM_THREADS=8
FILE_TOTAL_SIZE="5G"
FILE_NUM=128
FILE_TEST_MODE="rndrd,rndwr,rndrw"
CACHE_SIZE=$((4 * 1024 * 1024 * 1024)) # 4GB cgroup limit

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --test-dir <path>        Directory for Sysbench test files. Default: /mnt/nvme/sysbench_test"
    echo "  --iterations <num>       Number of iterations (default: 1)"
    echo "  --threads <num>          Number of threads (default: 1)"
    echo "  --file-total-size <size> Total size of files (default: 8G)"
    echo "  --file-num <num>         Number of files (default: 128)"
    echo "  --file-test-mode <mode>  Test mode (default: rndrd)"
    echo "  --cgroup-size <bytes>    Cgroup memory limit (default: 4GB)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test-dir)
            TEST_DIR="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --threads)
            NUM_THREADS="$2"
            shift 2
            ;;
        --file-total-size)
            FILE_TOTAL_SIZE="$2"
            shift 2
            ;;
        --file-num)
            FILE_NUM="$2"
            shift 2
            ;;
        --file-test-mode)
            FILE_TEST_MODE="$2"
            shift 2
            ;;
        --cgroup-size)
            CACHE_SIZE="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if ! command -v sysbench &> /dev/null; then
    echo "sysbench binary not found in PATH"
    echo "Please install sysbench first."
    exit 1
fi

mkdir -p "$RESULTS_PATH"
mkdir -p "$TEST_DIR"

# Prepare files once
echo "Preparing Sysbench files in $TEST_DIR..."
cd "$TEST_DIR"
sysbench fileio --file-total-size="$FILE_TOTAL_SIZE" --file-num="$FILE_NUM" prepare

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
# Random I/O (4K block size)
python3 "$BENCH_PATH/bench_sysbench.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_lhd.out" \
	--results-file "$RESULTS_PATH/sysbench_baseline_random_results.json" \
	--sysbench-test-dir "$TEST_DIR" \
    --file-total-size "$FILE_TOTAL_SIZE" \
    --file-num "$FILE_NUM" \
    --file-test-mode "rndrd,rndwr,rndrw" \
    --file-block-size "4K" \
    --num-threads "$NUM_THREADS" \
    --cgroup-size "$CACHE_SIZE" \
    --prepare-once \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--default-only

# Sequential I/O (1M block size)
python3 "$BENCH_PATH/bench_sysbench.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_lhd.out" \
	--results-file "$RESULTS_PATH/sysbench_baseline_seq_results.json" \
	--sysbench-test-dir "$TEST_DIR" \
    --file-total-size "$FILE_TOTAL_SIZE" \
    --file-num "$FILE_NUM" \
    --file-test-mode "seqrd,seqwr" \
    --file-block-size "1M" \
    --num-threads "$NUM_THREADS" \
    --cgroup-size "$CACHE_SIZE" \
    --prepare-once \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--default-only

# Run cache_ext policies
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
    # Random I/O (4K block size)
	python3 "$BENCH_PATH/bench_sysbench.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS_PATH/sysbench_${POLICY}_random_results.json" \
		--sysbench-test-dir "$TEST_DIR" \
        --file-total-size "$FILE_TOTAL_SIZE" \
        --file-num "$FILE_NUM" \
        --file-test-mode "rndrd,rndwr,rndrw" \
        --file-block-size "4K" \
        --num-threads "$NUM_THREADS" \
        --cgroup-size "$CACHE_SIZE" \
        --prepare-once \
		--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cache-ext-only
    
    # Sequential I/O (1M block size)
	python3 "$BENCH_PATH/bench_sysbench.py" \
		--cpu 8 \
		--policy-loader "$POLICY_PATH/${POLICY}.out" \
		--results-file "$RESULTS_PATH/sysbench_${POLICY}_seq_results.json" \
		--sysbench-test-dir "$TEST_DIR" \
    --file-total-size "$FILE_TOTAL_SIZE" \
    --file-num "$FILE_NUM" \
    --file-test-mode "seqrd,seqwr" \
    --file-block-size "1M" \
    --num-threads "$NUM_THREADS" \
    --cgroup-size "$CACHE_SIZE" \
    --prepare-once \
	--fadvise-hints "" \
		--iterations "$ITERATIONS" \
		--cache-ext-only
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
echo "Running baseline MGLRU"
# Random I/O (4K block size)
python3 "$BENCH_PATH/bench_sysbench.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_lhd.out" \
	--results-file "$RESULTS_PATH/sysbench_mglru_random_results.json" \
	--sysbench-test-dir "$TEST_DIR" \
    --file-total-size "$FILE_TOTAL_SIZE" \
    --file-num "$FILE_NUM" \
    --file-test-mode "rndrd,rndwr,rndrw" \
    --file-block-size "4K" \
    --num-threads "$NUM_THREADS" \
    --cgroup-size "$CACHE_SIZE" \
    --prepare-once \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--default-only

# Sequential I/O (1M block size)
python3 "$BENCH_PATH/bench_sysbench.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_lhd.out" \
	--results-file "$RESULTS_PATH/sysbench_mglru_seq_results.json" \
	--sysbench-test-dir "$TEST_DIR" \
    --file-total-size "$FILE_TOTAL_SIZE" \
    --file-num "$FILE_NUM" \
    --file-test-mode "seqrd,seqwr" \
    --file-block-size "1M" \
    --num-threads "$NUM_THREADS" \
    --cgroup-size "$CACHE_SIZE" \
    --prepare-once \
	--fadvise-hints "" \
	--iterations "$ITERATIONS" \
	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Cleanup
echo "Cleaning up Sysbench files..."
cd "$TEST_DIR"
sysbench fileio --file-total-size="$FILE_TOTAL_SIZE" --file-num="$FILE_NUM" cleanup

echo "Sysbench benchmark completed. Results saved to $RESULTS_PATH."
