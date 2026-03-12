#!/bin/bash
# LinkBench run script
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
RESULTS_PATH="$BASE_DIR/results/linkbench"
LINKBENCH_DIR="$BASE_DIR/linkbench"
CONFIG_FILE="$LINKBENCH_DIR/config/LinkConfigMysql.properties"

# Default values
DB_DATA_DIR="/var/lib/mysql" # Default MySQL data dir, user should override if different
ITERATIONS=3
REQUESTERS=10
REQUESTS=10000000
CACHE_SIZE=$((4 * 1024 * 1024 * 1024)) # 4GB cgroup limit
SKIP_LOAD=false

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --config <file>          LinkBench config file (default: $CONFIG_FILE)"
    echo "  --db-data-dir <path>     MySQL data directory (default: /var/lib/mysql)"
    echo "  --iterations <num>       Number of iterations (default: 1)"
    echo "  --requesters <num>       Number of requester threads (default: 10)"
    echo "  --requests <num>         Number of requests per thread (default: 100000)"
    echo "  --maxid1 <num>           Max ID1 (database size, default: 10000001)"
    echo "  --cgroup-size <bytes>    Cgroup memory limit (default: 4GB)"
    echo "  --paper-config           Use standard paper configuration (10x RAM dataset, long runtime)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --db-data-dir)
            DB_DATA_DIR="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --requesters)
            REQUESTERS="$2"
            shift 2
            ;;
        --requests)
            REQUESTS="$2"
            shift 2
            ;;
        --maxid1)
            MAXID1="$2"
            shift 2
            ;;
        --cgroup-size)
            CACHE_SIZE="$2"
            shift 2
            ;;
        --skip-load)
            SKIP_LOAD=true
            shift 1
            ;;
        --paper-config)
            PAPER_CONFIG=true
            shift 1
            ;;
        *)
            usage
            ;;
    esac
done

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Config file not found: $CONFIG_FILE"
    echo "Please copy linkbench/config/LinkConfigMysql.properties to a new file and configure it."
    exit 1
fi


# Find mysqld PID
MYSQLD_PID=$(pgrep -x mysqld | head -n 1 || true)
if [[ -z "$MYSQLD_PID" ]]; then
    echo "mysqld process not found. Please start MySQL server."
    exit 1
fi
echo "Found mysqld PID: $MYSQLD_PID"

mkdir -p "$RESULTS_PATH"

# Build LinkBench if needed (check for jar)
if [[ ! -f "$LINKBENCH_DIR/target/FacebookLinkBench.jar" ]]; then
    echo "Building LinkBench..."
    cd "$LINKBENCH_DIR"
    if command -v mvn &> /dev/null; then
        mvn clean package -DskipTests
    else
        echo "Maven (mvn) not found. Please install Maven to build LinkBench."
        exit 1
    fi
    cd "$BASE_DIR"
fi

# Load phase
if [[ "$SKIP_LOAD" != "true" ]]; then
    echo "Running LinkBench load phase..."
    LOAD_CMD="$LINKBENCH_DIR/bin/linkbench -c $CONFIG_FILE -l"
    if [[ -n "${MAXID1:-}" ]]; then
        LOAD_CMD="$LOAD_CMD -D maxid1=$MAXID1"
    fi
    $LOAD_CMD
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
cmd="python3 $BENCH_PATH/bench_linkbench.py \
	--cpu 8 \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/linkbench_baseline_results.json \
	--linkbench-bin $LINKBENCH_DIR/bin/linkbench \
    --config-file $CONFIG_FILE \
    --db-data-dir $DB_DATA_DIR \
    --mysqld-pid $MYSQLD_PID \
    --requesters $REQUESTERS \
    --requests $REQUESTS \
    ${MAXID1:+--maxid1 $MAXID1} \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
	--cgroup-size $CACHE_SIZE \
    --results-dir $RESULTS_PATH"

if [[ "${PAPER_CONFIG:-false}" == "true" ]]; then
    cmd="$cmd --paper-config"
fi
eval $cmd

# Run cache_ext policies
for POLICY in "${POLICIES[@]}"; do
	echo "Running policy: ${POLICY}"
	cmd="python3 $BENCH_PATH/bench_linkbench.py \
		--cpu 8 \
		--policy-loader $POLICY_PATH/${POLICY}.out \
		--results-file $RESULTS_PATH/linkbench_${POLICY}_results.json \
		--linkbench-bin $LINKBENCH_DIR/bin/linkbench \
        --config-file $CONFIG_FILE \
        --db-data-dir $DB_DATA_DIR \
        --mysqld-pid $MYSQLD_PID \
        --requesters $REQUESTERS \
        --requests $REQUESTS \
		--fadvise-hints \"\" \
		--iterations $ITERATIONS \
		--cache-ext-only
		--cgroup-size $CACHE_SIZE \
        --results-dir $RESULTS_PATH"
    if [[ "${PAPER_CONFIG:-false}" == "true" ]]; then
        cmd="$cmd --paper-config"
    fi
    eval $cmd
done

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# MGLRU
echo "Running baseline MGLRU"
cmd="python3 $BENCH_PATH/bench_linkbench.py \
	--cpu 8 \
	--policy-loader $POLICY_PATH/cache_ext_lhd.out \
	--results-file $RESULTS_PATH/linkbench_mglru_results.json \
	--linkbench-bin $LINKBENCH_DIR/bin/linkbench \
    --config-file $CONFIG_FILE \
    --db-data-dir $DB_DATA_DIR \
    --mysqld-pid $MYSQLD_PID \
    --requesters $REQUESTERS \
    --requests $REQUESTS \
    ${MAXID1:+--maxid1 $MAXID1} \
	--fadvise-hints \"\" \
	--iterations $ITERATIONS \
	--default-only \
	--cgroup-size $CACHE_SIZE \
	--results-dir $RESULTS_PATH"
if [[ "${PAPER_CONFIG:-false}" == "true" ]]; then
    cmd="$cmd --paper-config"
fi
eval $cmd

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "LinkBench benchmark completed. Results saved to $RESULTS_PATH."
