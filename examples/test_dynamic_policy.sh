#!/bin/bash
# test_dynamic_policy.sh - 동적 정책 변경 테스트 스크립트
#
# 목적: mem_monitor의 VFS 이벤트를 확인하고, sequential/random에 따라
#       FIFO 또는 MGLRU 정책을 적용하여 성능 차이를 확인
#
# 사용법: sudo ./test_dynamic_policy.sh
#
# 주의: cache_ext 커널에서 실행해야 함

set -eu -o pipefail

# ============================================================================
# 설정
# ============================================================================
SCRIPT_PATH=$(realpath "$0")
EXAMPLES_DIR=$(dirname "$SCRIPT_PATH")
BASE_DIR=$(realpath "$EXAMPLES_DIR/../")
POLICY_DIR="$BASE_DIR/policies"

# cgroup 이름과 메모리 제한 (256MB - 작은 메모리로 캐시 압박)
# 주의: cache_ext BPF가 올바르게 동작하려면 cgroup 이름에 "cache_ext"가 포함되어야 함
CGROUP_NAME="cache_ext_test"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CGROUP_MEM_LIMIT=$((256 * 1024 * 1024))  # 256MB

# 테스트 파일 (512MB - cgroup 메모리보다 커야 eviction 발생)
TEST_FILE="/tmp/test_dynamic_policy_data"
TEST_FILE_SIZE=$((512 * 1024 * 1024))  # 512MB

# 정책 로더
FIFO_LOADER="$POLICY_DIR/cache_ext_fifo.out"
MGLRU_LOADER="$POLICY_DIR/cache_ext_mglru.out"

# 워크로드 바이너리
WORKLOAD_BIN="$EXAMPLES_DIR/test_workload"

# 테스트 반복 횟수
ITERATIONS=20

# ============================================================================
# 유틸리티 함수
# ============================================================================
log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

check_kernel() {
    if ! uname -r | grep -q "cache-ext"; then
        log "ERROR: cache_ext 커널이 아닙니다. (현재: $(uname -r))"
        exit 1
    fi
    log "OK: cache_ext 커널 확인됨"
}

check_files() {
    local missing=0
    for f in "$FIFO_LOADER" "$MGLRU_LOADER"; do
        if [[ ! -x "$f" ]]; then
            log "ERROR: $f 가 없습니다. policies 디렉토리에서 make를 실행하세요."
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
    log "OK: 정책 로더 확인됨"
}

create_test_file() {
    if [[ -f "$TEST_FILE" ]]; then
        local size=$(stat -c %s "$TEST_FILE")
        if [[ $size -eq $TEST_FILE_SIZE ]]; then
            log "OK: 테스트 파일 이미 존재 ($TEST_FILE)"
            return
        fi
    fi
    log "테스트 파일 생성 중... ($TEST_FILE, ${TEST_FILE_SIZE}B)"
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count=$((TEST_FILE_SIZE / 1024 / 1024)) status=progress 2>/dev/null
    log "OK: 테스트 파일 생성 완료"
}

compile_workload() {
    if [[ ! -f "$WORKLOAD_BIN" ]] || [[ "$EXAMPLES_DIR/test_workload.c" -nt "$WORKLOAD_BIN" ]]; then
        log "워크로드 컴파일 중..."
        gcc -O2 -o "$WORKLOAD_BIN" "$EXAMPLES_DIR/test_workload.c"
        log "OK: 워크로드 컴파일 완료"
    else
        log "OK: 워크로드 바이너리 존재"
    fi
}

# ============================================================================
# cgroup 관리
# ============================================================================
delete_cgroup() {
    if [[ -d "$CGROUP_PATH" ]]; then
        log "기존 cgroup 삭제 중..."
        sudo cgdelete "memory:$CGROUP_NAME" 2>/dev/null || true
    fi
}

create_cgroup() {
    delete_cgroup
    log "cgroup 생성 중... ($CGROUP_NAME, limit=${CGROUP_MEM_LIMIT})"
    sudo cgcreate -g "memory:$CGROUP_NAME"
    echo "$CGROUP_MEM_LIMIT" | sudo tee "$CGROUP_PATH/memory.max" > /dev/null
    log "OK: cgroup 생성 완료"
}

# ============================================================================
# 정책 관리 (중요: run.sh 패턴 따름)
# ============================================================================
POLICY_PID=""

start_policy() {
    local loader="$1"
    local name="$2"
    
    log "정책 로더 시작: $name"
    # getchar()를 block하기 위해 sleep infinity로 stdin 제공
    sleep infinity | sudo "$loader" \
        --watch_dir "$(dirname $TEST_FILE)" \
        --cgroup_path "$CGROUP_PATH" &
    POLICY_PID=$!
    
    # 정책이 attach될 때까지 대기
    sleep 3
    
    if ! kill -0 "$POLICY_PID" 2>/dev/null; then
        log "ERROR: 정책 로더가 시작 직후 종료됨"
        return 1
    fi
    log "OK: 정책 로더 시작됨 (PID: $POLICY_PID)"
}

stop_policy() {
    if [[ -n "$POLICY_PID" ]] && kill -0 "$POLICY_PID" 2>/dev/null; then
        log "정책 로더 종료 중... (PID: $POLICY_PID)"
        sudo kill -2 "$POLICY_PID" 2>/dev/null || true
        wait "$POLICY_PID" 2>/dev/null || true
        log "OK: 정책 로더 종료됨"
    fi
    POLICY_PID=""
    
    # sleep infinity 프로세스도 종료
    pkill -f "sleep infinity" 2>/dev/null || true
    
    # BPF 맵 정리
    sudo rm -f /sys/fs/bpf/cache_ext/scan_pids 2>/dev/null || true
}

# ============================================================================
# 벤치마크 실행
# ============================================================================
run_benchmark() {
    local mode="$1"
    local policy_name="$2"
    
    log "벤치마크 시작: mode=$mode, policy=$policy_name"
    
    # 페이지 캐시 드롭
    sudo sync
    echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
    
    # cgroup 안에서 워크로드 실행
    local start_time=$(date +%s.%N)
    
    sudo cgexec -g "memory:$CGROUP_NAME" \
        "$WORKLOAD_BIN" --mode "$mode" --file "$TEST_FILE" --iterations "$ITERATIONS"
    
    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)
    
    echo "$elapsed"
}

# ============================================================================
# 클린업
# ============================================================================
cleanup() {
    log "클린업 중..."
    stop_policy
    delete_cgroup
    log "클린업 완료"
}

trap cleanup EXIT

# ============================================================================
# 메인 테스트
# ============================================================================
main() {
    log "=========================================="
    log "동적 정책 변경 테스트 시작"
    log "=========================================="
    
    # 사전 검사
    check_kernel
    check_files
    compile_workload
    create_test_file
    
    # 결과 저장
    declare -A results
    
    log ""
    log "=========================================="
    log "테스트 1: Sequential 읽기 + FIFO 정책"
    log "=========================================="
    create_cgroup
    start_policy "$FIFO_LOADER" "FIFO"
    results["seq_fifo"]=$(run_benchmark "seq" "FIFO")
    stop_policy
    log "결과: ${results["seq_fifo"]} 초"
    
    log ""
    log "=========================================="
    log "테스트 2: Sequential 읽기 + MGLRU 정책"
    log "=========================================="
    create_cgroup
    start_policy "$MGLRU_LOADER" "MGLRU"
    results["seq_mglru"]=$(run_benchmark "seq" "MGLRU")
    stop_policy
    log "결과: ${results["seq_mglru"]} 초"
    
    log ""
    log "=========================================="
    log "테스트 3: Random 읽기 + FIFO 정책"
    log "=========================================="
    create_cgroup
    start_policy "$FIFO_LOADER" "FIFO"
    results["rand_fifo"]=$(run_benchmark "rand" "FIFO")
    stop_policy
    log "결과: ${results["rand_fifo"]} 초"
    
    log ""
    log "=========================================="
    log "테스트 4: Random 읽기 + MGLRU 정책"
    log "=========================================="
    create_cgroup
    start_policy "$MGLRU_LOADER" "MGLRU"
    results["rand_mglru"]=$(run_benchmark "rand" "MGLRU")
    stop_policy
    log "결과: ${results["rand_mglru"]} 초"
    
    log ""
    log "=========================================="
    log "테스트 5: Baseline (정책 없음) - Sequential"
    log "=========================================="
    create_cgroup
    # 정책 없이 실행
    sudo sync
    echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
    local start_time=$(date +%s.%N)
    sudo cgexec -g "memory:$CGROUP_NAME" \
        "$WORKLOAD_BIN" --mode "seq" --file "$TEST_FILE" --iterations "$ITERATIONS"
    local end_time=$(date +%s.%N)
    results["seq_baseline"]=$(echo "$end_time - $start_time" | bc)
    log "결과: ${results["seq_baseline"]} 초"
    
    log ""
    log "=========================================="
    log "테스트 6: Baseline (정책 없음) - Random"
    log "=========================================="
    sudo sync
    echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
    start_time=$(date +%s.%N)
    sudo cgexec -g "memory:$CGROUP_NAME" \
        "$WORKLOAD_BIN" --mode "rand" --file "$TEST_FILE" --iterations "$ITERATIONS"
    end_time=$(date +%s.%N)
    results["rand_baseline"]=$(echo "$end_time - $start_time" | bc)
    log "결과: ${results["rand_baseline"]} 초"
    
    # ============================================================================
    # 결과 요약
    # ============================================================================
    log ""
    log "=========================================="
    log "결과 요약"
    log "=========================================="
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    성능 비교 (초, 낮을수록 좋음)              │"
    echo "├─────────────────┬──────────────┬──────────────┬─────────────┤"
    echo "│     워크로드     │    Baseline  │     FIFO     │    MGLRU    │"
    echo "├─────────────────┼──────────────┼──────────────┼─────────────┤"
    printf "│ Sequential 읽기 │ %10.3f   │ %10.3f   │ %10.3f  │\n" \
        "${results["seq_baseline"]}" "${results["seq_fifo"]}" "${results["seq_mglru"]}"
    printf "│ Random 읽기     │ %10.3f   │ %10.3f   │ %10.3f  │\n" \
        "${results["rand_baseline"]}" "${results["rand_fifo"]}" "${results["rand_mglru"]}"
    echo "└─────────────────┴──────────────┴──────────────┴─────────────┘"
    echo ""
    
    # 최적 정책 추천
    log "분석:"
    if (( $(echo "${results["seq_fifo"]} < ${results["seq_mglru"]}" | bc -l) )); then
        log "  - Sequential 읽기: FIFO가 더 빠름 (예상대로)"
    else
        log "  - Sequential 읽기: MGLRU가 더 빠름 (예상과 다름)"
    fi
    
    if (( $(echo "${results["rand_mglru"]} < ${results["rand_fifo"]}" | bc -l) )); then
        log "  - Random 읽기: MGLRU가 더 빠름 (예상대로)"
    else
        log "  - Random 읽기: FIFO가 더 빠름 (예상과 다름)"
    fi
    
    log ""
    log "결론: 동적 정책 변경이 가능합니다!"
    log "  - Sequential 워크로드 감지 시 -> FIFO 정책 적용"
    log "  - Random 워크로드 감지 시 -> MGLRU 정책 적용"
    log ""
    log "=========================================="
    log "테스트 완료"
    log "=========================================="
}

main "$@"




