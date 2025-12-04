#!/bin/bash
# dynamic_policy_with_monitor.sh - mem_monitor를 이용한 동적 정책 변경 데모
#
# 목적: 
#   1. mem_monitor로 VFS 이벤트의 seq 필드를 모니터링
#   2. sequential 비율이 높으면 FIFO, 낮으면 MGLRU 정책 적용
#   3. 동적 정책 변경이 실제로 작동하는지 확인
#
# 사용법: sudo ./dynamic_policy_with_monitor.sh
#
# 주의: cache_ext 커널에서 실행해야 함

set -eu -o pipefail

# ============================================================================
# 설정
# ============================================================================
SCRIPT_PATH=$(realpath "$0")
EXAMPLES_DIR=$(dirname "$SCRIPT_PATH")
BASE_DIR=$(realpath "$EXAMPLES_DIR/../")
IRP_DIR="$BASE_DIR/IRP"
POLICY_DIR="$BASE_DIR/policies"

# cgroup 설정
CGROUP_NAME="cache_ext_test"
CGROUP_PATH="/sys/fs/cgroup/$CGROUP_NAME"
CGROUP_MEM_LIMIT=$((256 * 1024 * 1024))  # 256MB

# 테스트 파일
TEST_FILE="/tmp/test_dynamic_monitor_data"
TEST_FILE_SIZE=$((512 * 1024 * 1024))  # 512MB

# 바이너리 경로
MEM_MONITOR="$IRP_DIR/mem_monitor"
FIFO_LOADER="$POLICY_DIR/cache_ext_fifo.out"
MGLRU_LOADER="$POLICY_DIR/cache_ext_mglru.out"
WORKLOAD_BIN="$EXAMPLES_DIR/test_workload"

# Sequential 판정 임계값 (50% 이상이면 sequential)
SEQ_THRESHOLD=50
MONITOR_DURATION=5  # 모니터링 시간 (초)

# ============================================================================
# 유틸리티 함수
# ============================================================================
log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

check_kernel() {
    if ! uname -r | grep -q "cache-ext"; then
        log "ERROR: cache_ext 커널이 아닙니다."
        exit 1
    fi
}

check_files() {
    for f in "$MEM_MONITOR" "$FIFO_LOADER" "$MGLRU_LOADER"; do
        if [[ ! -x "$f" ]]; then
            log "ERROR: $f 가 없습니다."
            log "  - IRP 디렉토리에서 make 실행: cd $IRP_DIR && make"
            log "  - policies 디렉토리에서 make 실행: cd $POLICY_DIR && make"
            exit 1
        fi
    done
}

create_test_file() {
    if [[ ! -f "$TEST_FILE" ]] || [[ $(stat -c %s "$TEST_FILE") -ne $TEST_FILE_SIZE ]]; then
        log "테스트 파일 생성 중..."
        dd if=/dev/urandom of="$TEST_FILE" bs=1M count=$((TEST_FILE_SIZE / 1024 / 1024)) status=none
        log "OK: 테스트 파일 생성 완료"
    fi
}

compile_workload() {
    if [[ ! -f "$WORKLOAD_BIN" ]] || [[ "$EXAMPLES_DIR/test_workload.c" -nt "$WORKLOAD_BIN" ]]; then
        make -C "$EXAMPLES_DIR" > /dev/null
    fi
}

# ============================================================================
# cgroup 관리
# ============================================================================
delete_cgroup() {
    sudo cgdelete "memory:$CGROUP_NAME" 2>/dev/null || true
}

create_cgroup() {
    delete_cgroup
    sudo cgcreate -g "memory:$CGROUP_NAME"
    echo "$CGROUP_MEM_LIMIT" | sudo tee "$CGROUP_PATH/memory.max" > /dev/null
}

# ============================================================================
# 정책 관리
# ============================================================================
POLICY_PID=""
CURRENT_POLICY=""

start_policy() {
    local loader="$1"
    local name="$2"
    
    stop_policy
    
    log "정책 시작: $name"
    sudo "$loader" \
        --watch_dir "$(dirname $TEST_FILE)" \
        --cgroup_path "$CGROUP_PATH" &
    POLICY_PID=$!
    CURRENT_POLICY="$name"
    sleep 3
    
    if ! kill -0 "$POLICY_PID" 2>/dev/null; then
        log "ERROR: 정책 로더 시작 실패"
        return 1
    fi
}

stop_policy() {
    if [[ -n "$POLICY_PID" ]] && kill -0 "$POLICY_PID" 2>/dev/null; then
        log "정책 종료: $CURRENT_POLICY (PID: $POLICY_PID)"
        sudo kill -2 "$POLICY_PID" 2>/dev/null || true
        wait "$POLICY_PID" 2>/dev/null || true
    fi
    POLICY_PID=""
    CURRENT_POLICY=""
    sudo rm -f /sys/fs/bpf/cache_ext/scan_pids 2>/dev/null || true
}

# ============================================================================
# mem_monitor를 이용한 워크로드 패턴 감지
# ============================================================================
detect_workload_pattern() {
    local workload_pid="$1"
    local duration="$2"
    local temp_file=$(mktemp)
    
    log "mem_monitor로 VFS 이벤트 모니터링 중... (${duration}초)"
    
    # mem_monitor 실행 (VFS 이벤트만, verbose 모드)
    timeout "$duration" sudo "$MEM_MONITOR" \
        -p "$workload_pid" \
        -t vfs \
        -v 2>&1 | tee "$temp_file" &
    local monitor_pid=$!
    
    # 모니터링 완료 대기
    wait "$monitor_pid" 2>/dev/null || true
    
    # VFS 이벤트에서 seq 비율 계산
    local total_events=$(grep -c "^\[VFS" "$temp_file" 2>/dev/null || echo "0")
    local seq_events=$(grep "^\[VFS" "$temp_file" | grep "SEQ:1" | wc -l 2>/dev/null || echo "0")
    
    rm -f "$temp_file"
    
    if [[ "$total_events" -eq 0 ]]; then
        log "VFS 이벤트 없음, 기본값: random"
        echo "random"
        return
    fi
    
    local seq_ratio=$((seq_events * 100 / total_events))
    log "VFS 이벤트 분석: total=$total_events, seq=$seq_events, ratio=${seq_ratio}%"
    
    if [[ "$seq_ratio" -ge "$SEQ_THRESHOLD" ]]; then
        echo "sequential"
    else
        echo "random"
    fi
}

# ============================================================================
# 워크로드 실행 (백그라운드)
# ============================================================================
run_workload_bg() {
    local mode="$1"
    local iterations="$2"
    
    sudo cgexec -g "memory:$CGROUP_NAME" \
        "$WORKLOAD_BIN" --mode "$mode" --file "$TEST_FILE" --iterations "$iterations" &
    echo $!
}

# ============================================================================
# 클린업
# ============================================================================
cleanup() {
    log "클린업..."
    stop_policy
    delete_cgroup
    # 백그라운드 프로세스 정리
    jobs -p | xargs -r sudo kill 2>/dev/null || true
}

trap cleanup EXIT

# ============================================================================
# 메인 데모
# ============================================================================
main() {
    log "=========================================="
    log "mem_monitor를 이용한 동적 정책 변경 데모"
    log "=========================================="
    
    check_kernel
    check_files
    compile_workload
    create_test_file
    create_cgroup
    
    # 페이지 캐시 초기화
    sudo sync
    echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    
    log ""
    log "=========================================="
    log "시나리오 1: Sequential 워크로드 감지 -> FIFO 적용"
    log "=========================================="
    
    # 초기에 MGLRU로 시작 (또는 정책 없이)
    log "1. 워크로드 시작 (sequential 모드, 백그라운드)"
    workload_pid=$(run_workload_bg "seq" 100)
    sleep 1  # 워크로드가 시작될 때까지 대기
    
    log "2. mem_monitor로 패턴 감지"
    detected_pattern=$(detect_workload_pattern "$workload_pid" "$MONITOR_DURATION")
    log "   감지된 패턴: $detected_pattern"
    
    log "3. 감지된 패턴에 따라 정책 선택"
    if [[ "$detected_pattern" == "sequential" ]]; then
        log "   -> Sequential 감지! FIFO 정책 적용"
        start_policy "$FIFO_LOADER" "FIFO"
    else
        log "   -> Random 감지! MGLRU 정책 적용"
        start_policy "$MGLRU_LOADER" "MGLRU"
    fi
    
    log "4. 워크로드 완료 대기..."
    wait "$workload_pid" 2>/dev/null || true
    stop_policy
    
    log ""
    log "=========================================="
    log "시나리오 2: Random 워크로드 감지 -> MGLRU 적용"
    log "=========================================="
    
    # 페이지 캐시 초기화
    create_cgroup
    sudo sync
    echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    
    log "1. 워크로드 시작 (random 모드, 백그라운드)"
    workload_pid=$(run_workload_bg "rand" 100)
    sleep 1
    
    log "2. mem_monitor로 패턴 감지"
    detected_pattern=$(detect_workload_pattern "$workload_pid" "$MONITOR_DURATION")
    log "   감지된 패턴: $detected_pattern"
    
    log "3. 감지된 패턴에 따라 정책 선택"
    if [[ "$detected_pattern" == "sequential" ]]; then
        log "   -> Sequential 감지! FIFO 정책 적용"
        start_policy "$FIFO_LOADER" "FIFO"
    else
        log "   -> Random 감지! MGLRU 정책 적용"
        start_policy "$MGLRU_LOADER" "MGLRU"
    fi
    
    log "4. 워크로드 완료 대기..."
    wait "$workload_pid" 2>/dev/null || true
    stop_policy
    
    log ""
    log "=========================================="
    log "데모 완료"
    log "=========================================="
    log ""
    log "결론:"
    log "  - mem_monitor의 VFS 이벤트 SEQ 필드로 워크로드 패턴 감지 가능"
    log "  - 감지된 패턴에 따라 런타임에 정책 변경 가능"
    log "  - Sequential -> FIFO, Random -> MGLRU 정책 적용"
    log ""
    log "주의사항:"
    log "  - 정책 변경 전 기존 정책 로더를 반드시 종료해야 함"
    log "  - cgroup 단위로 정책이 적용됨"
}

main "$@"


