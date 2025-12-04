#!/usr/bin/env python3
"""
debug_pattern_detection.py

컨트롤러의 패턴 감지 로직을 시각화하고 분석하는 도구.
policy_switches.csv와 controller_output.log를 분석하여
각 위상에서 감지된 패턴이 올바른지 검증합니다.
"""

import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


@dataclass
class DetectionEvent:
    """패턴 감지 이벤트"""
    line_num: int
    seq_ratio: float
    reaccess_ratio: float
    recent_re_ratio: float
    ws_hit_ratio: float


@dataclass
class SwitchEvent:
    """정책 전환 이벤트"""
    timestamp_ns: int
    from_policy: str
    to_policy: str
    pattern: str
    total_accesses: int
    seq_ratio: float
    reaccess_ratio: float


def parse_controller_log(log_path: Path) -> List[DetectionEvent]:
    """컨트롤러 로그에서 DETECT 이벤트 파싱"""
    events = []
    pattern = re.compile(
        r'\[DETECT\] seq=([\d.]+) reaccess=([\d.]+) recent_re=([\d.]+) ws_hit=([\d.]+)'
    )
    
    with open(log_path) as f:
        for i, line in enumerate(f, 1):
            m = pattern.search(line)
            if m:
                events.append(DetectionEvent(
                    line_num=i,
                    seq_ratio=float(m.group(1)),
                    reaccess_ratio=float(m.group(2)),
                    recent_re_ratio=float(m.group(3)),
                    ws_hit_ratio=float(m.group(4))
                ))
    
    return events


def parse_switches_csv(csv_path: Path) -> List[SwitchEvent]:
    """policy_switches.csv 파싱"""
    events = []
    
    with open(csv_path) as f:
        header = f.readline()  # Skip header
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 7:
                events.append(SwitchEvent(
                    timestamp_ns=int(parts[0]),
                    from_policy=parts[1],
                    to_policy=parts[2],
                    pattern=parts[3],
                    total_accesses=int(parts[4]),
                    seq_ratio=float(parts[5]),
                    reaccess_ratio=float(parts[6])
                ))
    
    return events


def classify_expected_pattern(seq: float, reaccess: float, recent_re: float, ws_hit: float) -> str:
    """주어진 통계에서 예상되는 패턴 분류"""
    SEQ_THRESHOLD = 0.70
    REACCESS_LOW = 0.15
    REACCESS_MED = 0.35
    RECENCY_HIGH = 0.50
    LOCALITY_HIGH = 0.60
    
    if seq > SEQ_THRESHOLD:
        if reaccess < REACCESS_LOW:
            return "FIFO"
        elif reaccess < REACCESS_MED:
            return "S3FIFO"
    
    if recent_re > RECENCY_HIGH and reaccess > 0.2:
        return "MRU"
    
    if ws_hit > LOCALITY_HIGH and reaccess > 0.3:
        return "LRU"
    
    return "S3FIFO"  # default


def analyze_detections(events: List[DetectionEvent]) -> None:
    """감지 이벤트 분석 및 출력"""
    print("\n" + "=" * 70)
    print("패턴 감지 분석")
    print("=" * 70)
    
    if not events:
        print("감지 이벤트가 없습니다.")
        return
    
    print(f"\n총 {len(events)}개의 감지 이벤트")
    print("\n샘플 이벤트 (처음 5개, 마지막 5개):")
    print("-" * 70)
    print(f"{'#':>5} | {'seq%':>6} | {'reac%':>6} | {'recent%':>7} | {'ws_hit%':>8} | 예상패턴")
    print("-" * 70)
    
    for e in events[:5]:
        expected = classify_expected_pattern(e.seq_ratio, e.reaccess_ratio, 
                                              e.recent_re_ratio, e.ws_hit_ratio)
        print(f"{e.line_num:>5} | {e.seq_ratio*100:>5.1f}% | {e.reaccess_ratio*100:>5.1f}% | "
              f"{e.recent_re_ratio*100:>6.1f}% | {e.ws_hit_ratio*100:>7.1f}% | {expected}")
    
    if len(events) > 10:
        print("  ...")
    
    for e in events[-5:]:
        expected = classify_expected_pattern(e.seq_ratio, e.reaccess_ratio,
                                              e.recent_re_ratio, e.ws_hit_ratio)
        print(f"{e.line_num:>5} | {e.seq_ratio*100:>5.1f}% | {e.reaccess_ratio*100:>5.1f}% | "
              f"{e.recent_re_ratio*100:>6.1f}% | {e.ws_hit_ratio*100:>7.1f}% | {expected}")
    
    print("-" * 70)
    
    # 통계 요약
    avg_seq = sum(e.seq_ratio for e in events) / len(events)
    avg_reaccess = sum(e.reaccess_ratio for e in events) / len(events)
    
    print(f"\n평균 순차 비율: {avg_seq*100:.1f}%")
    print(f"평균 재접근 비율: {avg_reaccess*100:.1f}%")


def analyze_switches(events: List[SwitchEvent]) -> None:
    """정책 전환 이벤트 분석"""
    print("\n" + "=" * 70)
    print("정책 전환 분석")
    print("=" * 70)
    
    if not events:
        print("정책 전환이 없습니다.")
        return
    
    print(f"\n총 {len(events)}번의 정책 전환")
    print("\n전환 상세:")
    print("-" * 70)
    
    t0 = events[0].timestamp_ns
    for i, e in enumerate(events, 1):
        rel_time = (e.timestamp_ns - t0) / 1e9
        print(f"{i}. [{rel_time:7.2f}s] {e.from_policy:>8} → {e.to_policy:<8} "
              f"(감지: {e.pattern}, seq={e.seq_ratio*100:.0f}%, reaccess={e.reaccess_ratio*100:.0f}%)")
    
    print("-" * 70)
    
    # 정책별 사용 빈도
    policy_counts = {}
    for e in events:
        policy_counts[e.to_policy] = policy_counts.get(e.to_policy, 0) + 1
    
    print("\n정책 선택 빈도:")
    for policy, count in sorted(policy_counts.items(), key=lambda x: -x[1]):
        print(f"  {policy}: {count}회")


def plot_detection_timeline(detections: List[DetectionEvent], 
                            switches: List[SwitchEvent],
                            output_path: Path) -> None:
    """패턴 감지 타임라인 시각화"""
    if not HAS_MATPLOTLIB or not detections:
        return
    
    fig, axes = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
    
    x = range(len(detections))
    
    # 상단: 비율 추이
    ax1 = axes[0]
    ax1.plot(x, [e.seq_ratio * 100 for e in detections], 
             label='Sequential %', color='#2E86AB', linewidth=1.5)
    ax1.plot(x, [e.reaccess_ratio * 100 for e in detections],
             label='Re-access %', color='#A23B72', linewidth=1.5)
    ax1.plot(x, [e.recent_re_ratio * 100 for e in detections],
             label='Recent Re-access %', color='#F18F01', linewidth=1.5, alpha=0.7)
    ax1.plot(x, [e.ws_hit_ratio * 100 for e in detections],
             label='WS Hit %', color='#44AF69', linewidth=1.5, alpha=0.7)
    
    # 임계값 표시
    ax1.axhline(70, color='red', linestyle='--', alpha=0.5, label='Seq threshold (70%)')
    ax1.axhline(15, color='purple', linestyle='--', alpha=0.5, label='Reaccess low (15%)')
    
    ax1.set_ylabel('Ratio (%)')
    ax1.set_title('Pattern Detection Metrics Over Time')
    ax1.legend(loc='upper right', fontsize=8)
    ax1.set_ylim(0, 105)
    ax1.grid(True, alpha=0.3)
    
    # 하단: 예상 패턴
    ax2 = axes[1]
    pattern_map = {'FIFO': 0, 'S3FIFO': 1, 'MRU': 2, 'LRU': 3}
    colors_map = {'FIFO': '#A23B72', 'S3FIFO': '#C73E1D', 'MRU': '#F18F01', 'LRU': '#2E86AB'}
    
    patterns = [classify_expected_pattern(e.seq_ratio, e.reaccess_ratio,
                                           e.recent_re_ratio, e.ws_hit_ratio) 
                for e in detections]
    y_vals = [pattern_map[p] for p in patterns]
    colors = [colors_map[p] for p in patterns]
    
    ax2.scatter(x, y_vals, c=colors, s=10, alpha=0.6)
    
    # 실제 전환 표시 (있다면)
    if switches:
        # Rough mapping: assume switches correspond to detection indices
        switch_indices = [int(len(detections) * i / len(switches)) for i in range(len(switches))]
        for idx, sw in zip(switch_indices, switches):
            if sw.pattern in pattern_map:
                ax2.axvline(idx, color='black', linestyle='-', alpha=0.5, linewidth=2)
                ax2.annotate(f'→{sw.to_policy}', (idx, pattern_map.get(sw.pattern, 0)),
                            fontsize=8, rotation=45)
    
    ax2.set_yticks(list(pattern_map.values()))
    ax2.set_yticklabels(list(pattern_map.keys()))
    ax2.set_xlabel('Detection Event #')
    ax2.set_ylabel('Detected Pattern')
    ax2.set_title('Expected Pattern Classification')
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    print(f"\n타임라인 그래프 저장: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='동적 정책 컨트롤러의 패턴 감지 디버깅 및 분석'
    )
    parser.add_argument('--log', '-l', type=Path,
                        help='controller_output.log 경로')
    parser.add_argument('--csv', '-c', type=Path,
                        help='policy_switches.csv 경로')
    parser.add_argument('--dir', '-d', type=Path,
                        help='결과 디렉토리 (log와 csv 자동 탐색)')
    parser.add_argument('--plot', '-p', type=Path,
                        help='타임라인 그래프 출력 경로')
    
    args = parser.parse_args()
    
    # 파일 경로 결정
    log_path = args.log
    csv_path = args.csv
    
    if args.dir:
        if not log_path:
            candidate = args.dir / 'controller_output.log'
            if candidate.exists():
                log_path = candidate
        if not csv_path:
            candidate = args.dir / 'policy_switches.csv'
            if candidate.exists():
                csv_path = candidate
    
    print("=" * 70)
    print("동적 정책 컨트롤러 패턴 감지 분석")
    print("=" * 70)
    
    detections = []
    switches = []
    
    # 로그 파싱
    if log_path and log_path.exists():
        print(f"\n로그 파일: {log_path}")
        detections = parse_controller_log(log_path)
        analyze_detections(detections)
    else:
        print("\n[주의] 컨트롤러 로그 파일이 없습니다 (--log 또는 --dir 지정)")
    
    # CSV 파싱
    if csv_path and csv_path.exists():
        print(f"\nCSV 파일: {csv_path}")
        switches = parse_switches_csv(csv_path)
        analyze_switches(switches)
    else:
        print("\n[주의] 정책 전환 CSV가 없습니다 (--csv 또는 --dir 지정)")
    
    # 플롯 생성
    if args.plot and detections:
        plot_detection_timeline(detections, switches, args.plot)
    elif detections and HAS_MATPLOTLIB:
        default_plot = Path('/tmp/pattern_detection_timeline.png')
        plot_detection_timeline(detections, switches, default_plot)
    
    print("\n" + "=" * 70)
    print("분석 완료")
    print("=" * 70)


if __name__ == '__main__':
    main()

