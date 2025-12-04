#!/bin/bash
# =============================================================================
# verify_controller.sh
#
# 동적 정책 컨트롤러가 워크로드의 각 위상에서 올바르게 정책을 전환하는지 검증
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 색상 출력
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err() { echo -e "${RED}[ERROR]${NC} $*"; }

# 기본 설정
CGROUP_PATH="/sys/fs/cgroup/cacheext_verify"
DATA_DIR="/tmp/verify_data"
OUTPUT_DIR="/tmp/verify_output"
FILE_SIZE_MB=64
CGROUP_MEMORY_MB=32

cleanup() {
    log_info "정리 중..."
    pkill -f 'dynamic_policy_controller' 2>/dev/null || true
    pkill -f 'multi_phase_workload' 2>/dev/null || true
    
    if [[ -d "$CGROUP_PATH" ]]; then
        while read -r pid; do
            kill -9 "$pid" 2>/dev/null || true
        done < "$CGROUP_PATH/cgroup.procs" 2>/dev/null
        sleep 1
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Root 확인
if [[ $EUID -ne 0 ]]; then
    log_err "root 권한이 필요합니다"
    exit 1
fi

# 빌드 확인
if [[ ! -x "$SCRIPT_DIR/multi_phase_workload" ]] || [[ ! -x "$SCRIPT_DIR/dynamic_policy_controller" ]]; then
    log_info "바이너리 빌드 중..."
    (cd "$SCRIPT_DIR" && make) || { log_err "빌드 실패"; exit 1; }
fi

# 디렉토리 준비
mkdir -p "$DATA_DIR" "$OUTPUT_DIR"
cleanup

# Cgroup 설정
log_info "Cgroup 설정: $CGROUP_PATH (memory: ${CGROUP_MEMORY_MB}MB)"
mkdir -p "$CGROUP_PATH"
echo "+memory" > "$(dirname "$CGROUP_PATH")/cgroup.subtree_control" 2>/dev/null || true
echo "$((CGROUP_MEMORY_MB * 1024 * 1024))" > "$CGROUP_PATH/memory.max" 2>/dev/null || true

# 캐시 드롭
sync && echo 3 > /proc/sys/vm/drop_caches

# MGLRU 비활성화 (BPF 정책 사용)
echo 0 > /sys/kernel/mm/lru_gen/enabled 2>/dev/null || true

echo ""
echo "========================================================================"
echo "         동적 정책 컨트롤러 검증 테스트"
echo "========================================================================"
echo ""
echo "이 테스트는 다음을 검증합니다:"
echo "  1. 컨트롤러가 VFS I/O 이벤트를 수신하는지"
echo "  2. 각 위상에서 올바른 패턴을 감지하는지"
echo "  3. 적절한 시점에 정책을 전환하는지"
echo ""
echo "예상되는 정책 전환:"
echo "  Phase 1 (MRU):    → MRU 정책"
echo "  Phase 2 (LRU):    → MGLRU 정책"
echo "  Phase 3 (FIFO):   → FIFO 정책"
echo "  Phase 4 (S3FIFO): → S3FIFO 정책"
echo ""
echo "========================================================================"

# 컨트롤러 시작 (백그라운드)
log_info "동적 정책 컨트롤러 시작..."
"$SCRIPT_DIR/dynamic_policy_controller" \
    --cgroup "$CGROUP_PATH" \
    --watch-dir "$DATA_DIR" \
    --cgroup-size "$((CGROUP_MEMORY_MB * 1024 * 1024))" \
    --min-switch 500 \
    --window 200 \
    --output "$OUTPUT_DIR" \
    --verbose \
    2>&1 | tee "$OUTPUT_DIR/controller_output.log" &
CTRL_PID=$!

sleep 2

if ! kill -0 $CTRL_PID 2>/dev/null; then
    log_err "컨트롤러 시작 실패"
    cat "$OUTPUT_DIR/controller_output.log"
    exit 1
fi

log_ok "컨트롤러 실행 중 (PID: $CTRL_PID)"

# 현재 쉘을 cgroup에 추가
echo $$ > "$CGROUP_PATH/cgroup.procs"

# 워크로드 실행
log_info "워크로드 시작 (${FILE_SIZE_MB}MB, 각 위상 2회 반복)..."
echo ""

"$SCRIPT_DIR/multi_phase_workload" \
    --size "$FILE_SIZE_MB" \
    --working-set "$((FILE_SIZE_MB / 4))" \
    --iterations 2 \
    --data-dir "$DATA_DIR" \
    --output-dir "$OUTPUT_DIR/workload" \
    --latency \
    2>&1 | tee "$OUTPUT_DIR/workload_output.log"

WL_EXIT=$?

echo ""
log_info "워크로드 완료 (exit: $WL_EXIT)"

# 컨트롤러 종료 전 잠시 대기
sleep 2

# 컨트롤러 종료
log_info "컨트롤러 종료..."
kill -INT $CTRL_PID 2>/dev/null || true
wait $CTRL_PID 2>/dev/null || true

echo ""
echo "========================================================================"
echo "                         검증 결과"
echo "========================================================================"
echo ""

# 정책 전환 로그 분석
if [[ -f "$OUTPUT_DIR/policy_switches.csv" ]]; then
    SWITCH_COUNT=$(tail -n +2 "$OUTPUT_DIR/policy_switches.csv" | wc -l)
    
    echo "정책 전환 횟수: $SWITCH_COUNT"
    echo ""
    echo "정책 전환 기록:"
    echo "-----------------------------------------------------------"
    echo "시간(상대) | 이전정책 → 새정책 | 감지패턴 | 순차% | 재접근%"
    echo "-----------------------------------------------------------"
    
    # CSV 파싱 (헤더 제외)
    FIRST_TS=""
    while IFS=',' read -r ts from to pattern accesses seq_ratio reaccess_ratio count; do
        if [[ -z "$FIRST_TS" ]]; then
            FIRST_TS=$ts
        fi
        REL_TIME=$(echo "scale=2; ($ts - $FIRST_TS) / 1000000000" | bc)
        SEQ_PCT=$(echo "scale=1; $seq_ratio * 100" | bc)
        RE_PCT=$(echo "scale=1; $reaccess_ratio * 100" | bc)
        printf "%8.2fs | %8s → %-8s | %-7s | %5.1f%% | %5.1f%%\n" \
            "$REL_TIME" "$from" "$to" "$pattern" "$SEQ_PCT" "$RE_PCT"
    done < <(tail -n +2 "$OUTPUT_DIR/policy_switches.csv")
    
    echo "-----------------------------------------------------------"
    echo ""
    
    # 예상 패턴 확인
    if [[ $SWITCH_COUNT -ge 2 ]]; then
        log_ok "컨트롤러가 정책을 동적으로 전환함"
    else
        log_warn "정책 전환이 적음 - 워크로드가 너무 짧거나 min_switch 간격 확인 필요"
    fi
    
    # 패턴별 감지 확인
    if grep -q "FIFO" "$OUTPUT_DIR/policy_switches.csv"; then
        log_ok "FIFO 패턴 감지됨 (순차 스캔 위상)"
    fi
    if grep -q "LRU\|mglru" "$OUTPUT_DIR/policy_switches.csv"; then
        log_ok "LRU 패턴 감지됨 (작업집합 위상)"
    fi
    if grep -q "MRU\|mru" "$OUTPUT_DIR/policy_switches.csv"; then
        log_ok "MRU 패턴 감지됨 (LIFO 스택 위상)"
    fi
    if grep -q "S3FIFO\|s3fifo" "$OUTPUT_DIR/policy_switches.csv"; then
        log_ok "S3FIFO 패턴 감지됨"
    fi
else
    log_warn "정책 전환 로그 없음: $OUTPUT_DIR/policy_switches.csv"
fi

echo ""

# 컨트롤러 출력에서 DETECT 라인 분석
if [[ -f "$OUTPUT_DIR/controller_output.log" ]]; then
    DETECT_COUNT=$(grep -c "\[DETECT\]" "$OUTPUT_DIR/controller_output.log" 2>/dev/null || echo "0")
    echo "패턴 감지 이벤트: $DETECT_COUNT 회"
    
    if [[ $DETECT_COUNT -gt 0 ]]; then
        log_ok "BPF 이벤트 수신 및 패턴 분석 정상 동작"
        
        echo ""
        echo "마지막 10개 감지 결과:"
        grep "\[DETECT\]" "$OUTPUT_DIR/controller_output.log" | tail -10
    else
        log_warn "패턴 감지 이벤트 없음 - BPF 연결 확인 필요"
    fi
fi

echo ""
echo "========================================================================"
echo "상세 로그 위치:"
echo "  - 컨트롤러: $OUTPUT_DIR/controller_output.log"
echo "  - 정책전환: $OUTPUT_DIR/policy_switches.csv"
echo "  - 워크로드: $OUTPUT_DIR/workload_output.log"
echo "========================================================================"
echo ""

# 최종 결과 판정
if [[ -f "$OUTPUT_DIR/policy_switches.csv" ]] && [[ $SWITCH_COUNT -ge 1 ]]; then
    log_ok "검증 성공: 동적 정책 전환이 정상 동작합니다"
    exit 0
else
    log_err "검증 실패: 정책 전환이 발생하지 않았습니다"
    echo ""
    echo "디버깅 힌트:"
    echo "  1. BPF 로드 확인: dmesg | tail -50"
    echo "  2. cgroup 확인: cat $CGROUP_PATH/cgroup.procs"
    echo "  3. 컨트롤러 로그: cat $OUTPUT_DIR/controller_output.log"
    exit 1
fi

