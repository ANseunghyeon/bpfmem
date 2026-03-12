#!/bin/bash
# Fxmark benchmark run script
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
RESULTS_PATH="$BASE_DIR/results/fxmark"
WORKLOAD_DIR="/mnt/nvme/fxmark_test"

# Ensure results directory exists
mkdir -p "$RESULTS_PATH"

CORES=$(nproc)

ITERATIONS=3

POLICIES=(
	"cache_ext_fifo"
	"cache_ext_mru"
	#"cache_ext_mglru"
    "cache_ext_s3fifo"
	#"cache_ext_sampling"
    #"cache_ext_lhd"
)

WORKLOADS=(
    "MWCL"
    "DWAL"
    #"DRBH"
    #"filebench_varmail"
    #"dbench_client"
)

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

for POLICY in "${POLICIES[@]}"; do
    for WORKLOAD in "${WORKLOADS[@]}"; do
        echo "Running policy: ${POLICY} with workload: ${WORKLOAD}"
        
        POLICY_LOADER="$POLICY_PATH/${POLICY}.out"
        if [ ! -f "$POLICY_LOADER" ]; then
            echo "Policy loader not found: $POLICY_LOADER"
            exit 1
        fi

        python3 "$BENCH_PATH/bench_fxmark.py" \
            --cpu "$CORES" \
            --policy-loader "$POLICY_LOADER" \
            --results-file "$RESULTS_PATH/fxmark_${WORKLOAD}_results.json" \
            --workload-dir "$WORKLOAD_DIR" \
            --benchmark-type "$WORKLOAD" \
            --duration 600 \
            --iterations "$ITERATIONS" \
            --fs-type "ext4"
    done
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# Run baseline MGLRU
for WORKLOAD in "${WORKLOADS[@]}"; do
    echo "Running baseline MGLRU with workload: ${WORKLOAD}"
    python3 "$BENCH_PATH/bench_fxmark.py" \
        --cpu "$CORES" \
        --policy-loader "$POLICY_PATH/${POLICIES[0]}.out" \
        --results-file "$RESULTS_PATH/fxmark_${WORKLOAD}_results_mglru.json" \
        --workload-dir "$WORKLOAD_DIR" \
        --benchmark-type "$WORKLOAD" \
        --duration 600 \
        --iterations "$ITERATIONS" \
        --fs-type "ext4" \
        --default-only
done

# Disable MGLRU again to leave system in clean state
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "Fxmark benchmark completed. Results saved to $RESULTS_PATH."