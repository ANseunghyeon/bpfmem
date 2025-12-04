#!/usr/bin/env python3
"""
plot_results.py

Generate publication-quality figures for the 14weeks cache policy experiment.
Produces:
1. Makespan comparison bar chart
2. Per-phase latency distribution (box plots)
3. Throughput comparison
4. Policy switch timeline (for dynamic variant)
5. CDF of access latencies

Usage:
    python3 plot_results.py --input /path/to/run_stamp_dir --output /path/to/output
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not available, skipping plots", file=sys.stderr)

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


# =============================================================================
# Color Scheme (publication-friendly)
# =============================================================================

COLORS = {
    'mglru': '#2E86AB',      # Blue
    'fifo': '#A23B72',       # Magenta
    'mru': '#F18F01',        # Orange
    's3fifo': '#C73E1D',     # Red
    'lhd': '#3B1F2B',        # Dark
    'sampling': '#95C623',   # Green
    'dynamic': '#44AF69',    # Teal-green
}

PHASE_COLORS = {
    'MRU': '#F18F01',
    'LRU': '#2E86AB',
    'FIFO': '#A23B72',
    'S3FIFO': '#C73E1D',
    'RANDOM': '#666666',
}

FONT_SIZE = 12
TITLE_SIZE = 14


# =============================================================================
# Data Loading
# =============================================================================

def load_variant_data(variant_dir: Path) -> Optional[Dict]:
    """Load all data for a variant."""
    meta_path = variant_dir / "meta.json"
    if not meta_path.exists():
        return None
    
    with open(meta_path) as f:
        data = json.load(f)
    
    data['name'] = variant_dir.name
    data['dir'] = variant_dir
    
    # Load phase results if available
    phase_csv = variant_dir / "phase_results.csv"
    if phase_csv.exists() and HAS_PANDAS:
        data['phases'] = pd.read_csv(phase_csv)
    
    # Load summary if available
    summary_path = variant_dir / "summary.json"
    if summary_path.exists():
        with open(summary_path) as f:
            data['summary'] = json.load(f)
    
    # Load policy switches if available
    switches_path = variant_dir / "policy_switches.csv"
    if not switches_path.exists():
        switches_path = variant_dir / "controller" / "policy_switches.csv"
    if switches_path.exists() and HAS_PANDAS:
        data['switches'] = pd.read_csv(switches_path)
    
    return data


def load_all_variants(results_dir: Path) -> Dict[str, Dict]:
    """Load data for all variants in a run directory."""
    variants = {}
    for item in results_dir.iterdir():
        if item.is_dir():
            data = load_variant_data(item)
            if data:
                variants[item.name] = data
    return variants


# =============================================================================
# Plotting Functions
# =============================================================================

def plot_makespan_comparison(variants: Dict[str, Dict], output_dir: Path):
    """Bar chart comparing makespan across variants."""
    if not HAS_MATPLOTLIB:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    names = []
    makespans = []
    colors = []
    
    for name, data in sorted(variants.items()):
        names.append(name.upper())
        makespans.append(data.get('makespan_sec', 0))
        colors.append(COLORS.get(name, '#888888'))
    
    x = np.arange(len(names))
    bars = ax.bar(x, makespans, color=colors, edgecolor='black', linewidth=0.5)
    
    # Add value labels on bars
    for bar, val in zip(bars, makespans):
        height = bar.get_height()
        ax.annotate(f'{val:.2f}s',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=FONT_SIZE - 1)
    
    ax.set_xlabel('Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Makespan (seconds)', fontsize=FONT_SIZE)
    ax.set_title('Total Workload Execution Time by Policy', fontsize=TITLE_SIZE)
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=FONT_SIZE)
    ax.tick_params(axis='y', labelsize=FONT_SIZE)
    
    # Add grid
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'makespan_comparison.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'makespan_comparison.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: makespan_comparison.png/pdf")


def plot_per_phase_duration(variants: Dict[str, Dict], output_dir: Path):
    """Grouped bar chart showing per-phase duration for each variant."""
    if not HAS_MATPLOTLIB or not HAS_PANDAS:
        return
    
    # Collect phase data
    phase_names = ['MRU', 'LRU', 'FIFO', 'S3FIFO', 'RANDOM']
    variant_names = []
    phase_data = {p: [] for p in phase_names}
    
    for name, data in sorted(variants.items()):
        if 'phases' not in data:
            continue
        variant_names.append(name.upper())
        df = data['phases']
        for phase in phase_names:
            row = df[df['phase'] == phase]
            if len(row) > 0:
                phase_data[phase].append(row['duration_sec'].values[0])
            else:
                phase_data[phase].append(0)
    
    if not variant_names:
        return
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    x = np.arange(len(variant_names))
    width = 0.15
    
    for i, phase in enumerate(phase_names):
        offset = (i - len(phase_names) / 2 + 0.5) * width
        bars = ax.bar(x + offset, phase_data[phase], width,
                      label=phase, color=PHASE_COLORS.get(phase, '#888888'),
                      edgecolor='black', linewidth=0.3)
    
    ax.set_xlabel('Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Duration (seconds)', fontsize=FONT_SIZE)
    ax.set_title('Per-Phase Duration by Policy', fontsize=TITLE_SIZE)
    ax.set_xticks(x)
    ax.set_xticklabels(variant_names, fontsize=FONT_SIZE)
    ax.legend(title='Phase', fontsize=FONT_SIZE - 1)
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'per_phase_duration.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'per_phase_duration.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: per_phase_duration.png/pdf")


def plot_latency_distribution(variants: Dict[str, Dict], output_dir: Path):
    """Box plot of latency distributions per variant and phase."""
    if not HAS_MATPLOTLIB or not HAS_PANDAS:
        return
    
    # Check if we have latency histogram data
    variant_names = []
    avg_latencies = []
    
    for name, data in sorted(variants.items()):
        if 'phases' not in data:
            continue
        df = data['phases']
        if 'lat_avg_us' in df.columns:
            variant_names.append(name.upper())
            avg_latencies.append(df['lat_avg_us'].mean())
    
    if not variant_names:
        print("  Skipped: latency_distribution (no latency data)")
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = [COLORS.get(name.lower(), '#888888') for name in variant_names]
    bars = ax.bar(variant_names, avg_latencies, color=colors,
                  edgecolor='black', linewidth=0.5)
    
    ax.set_xlabel('Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Average Latency (μs)', fontsize=FONT_SIZE)
    ax.set_title('Average Access Latency by Policy', fontsize=TITLE_SIZE)
    ax.tick_params(axis='both', labelsize=FONT_SIZE)
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'latency_comparison.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'latency_comparison.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: latency_comparison.png/pdf")


def plot_throughput_comparison(variants: Dict[str, Dict], output_dir: Path):
    """Bar chart of throughput (accesses per second)."""
    if not HAS_MATPLOTLIB:
        return
    
    variant_names = []
    throughputs = []
    
    for name, data in sorted(variants.items()):
        if 'summary' in data and 'phases' in data['summary']:
            total_accesses = sum(p['accesses'] for p in data['summary']['phases'])
            total_time = data['summary']['total_duration_sec']
            if total_time > 0:
                variant_names.append(name.upper())
                throughputs.append(total_accesses / total_time)
        elif 'phases' in data:
            df = data['phases']
            total_accesses = df['accesses'].sum()
            total_time = df['duration_sec'].sum()
            if total_time > 0:
                variant_names.append(name.upper())
                throughputs.append(total_accesses / total_time)
    
    if not variant_names:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = [COLORS.get(name.lower(), '#888888') for name in variant_names]
    bars = ax.bar(variant_names, [t / 1000 for t in throughputs],  # Convert to K ops/s
                  color=colors, edgecolor='black', linewidth=0.5)
    
    ax.set_xlabel('Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Throughput (K accesses/sec)', fontsize=FONT_SIZE)
    ax.set_title('Access Throughput by Policy', fontsize=TITLE_SIZE)
    ax.tick_params(axis='both', labelsize=FONT_SIZE)
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'throughput_comparison.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'throughput_comparison.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: throughput_comparison.png/pdf")


def plot_policy_switches(variants: Dict[str, Dict], output_dir: Path):
    """Timeline of policy switches for dynamic variant."""
    if not HAS_MATPLOTLIB or not HAS_PANDAS:
        return
    
    # Find dynamic variant
    dynamic_data = variants.get('dynamic')
    if not dynamic_data or 'switches' not in dynamic_data:
        print("  Skipped: policy_switches (no dynamic variant data)")
        return
    
    df = dynamic_data['switches']
    if len(df) == 0:
        print("  Skipped: policy_switches (no switches recorded)")
        return
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Normalize timestamps
    if 'timestamp_ns' in df.columns:
        t0 = df['timestamp_ns'].min()
        times = (df['timestamp_ns'] - t0) / 1e9  # Convert to seconds
    else:
        times = np.arange(len(df))
    
    # Policy mapping for y-axis
    policies = ['fifo', 'mru', 'mglru', 's3fifo', 'lhd', 'sampling']
    policy_y = {p: i for i, p in enumerate(policies)}
    
    # Plot switches
    y_vals = [policy_y.get(p.lower(), 0) for p in df['to_policy']]
    colors = [COLORS.get(p.lower(), '#888888') for p in df['to_policy']]
    
    ax.scatter(times, y_vals, c=colors, s=100, zorder=3, edgecolor='black', linewidth=0.5)
    
    # Connect with lines
    for i in range(1, len(times)):
        ax.plot([times.iloc[i-1], times.iloc[i]], [y_vals[i-1], y_vals[i]],
                'k-', alpha=0.3, linewidth=1)
    
    ax.set_xlabel('Time (seconds)', fontsize=FONT_SIZE)
    ax.set_ylabel('Active Policy', fontsize=FONT_SIZE)
    ax.set_title('Dynamic Policy Switches Over Time', fontsize=TITLE_SIZE)
    ax.set_yticks(range(len(policies)))
    ax.set_yticklabels([p.upper() for p in policies], fontsize=FONT_SIZE)
    ax.tick_params(axis='x', labelsize=FONT_SIZE)
    ax.xaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    # Add legend
    handles = [mpatches.Patch(color=COLORS.get(p, '#888888'), label=p.upper())
               for p in policies if p in [s.lower() for s in df['to_policy']]]
    ax.legend(handles=handles, loc='upper right', fontsize=FONT_SIZE - 1)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'policy_switches.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'policy_switches.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: policy_switches.png/pdf")


def plot_latency_histogram(variants: Dict[str, Dict], output_dir: Path):
    """Stacked histogram of latency distribution buckets."""
    if not HAS_MATPLOTLIB or not HAS_PANDAS:
        return
    
    bucket_labels = ['<1μs', '1-10μs', '10-100μs', '100μs-1ms',
                     '1-10ms', '10-100ms', '>100ms']
    bucket_cols = ['pct_lt1us', 'pct_1_10us', 'pct_10_100us', 'pct_100us_1ms',
                   'pct_1_10ms', 'pct_10_100ms', 'pct_gt100ms']
    
    variant_names = []
    bucket_data = {b: [] for b in bucket_labels}
    
    for name, data in sorted(variants.items()):
        if 'phases' not in data:
            continue
        df = data['phases']
        
        # Check if we have histogram columns
        if not all(c in df.columns for c in bucket_cols):
            continue
        
        variant_names.append(name.upper())
        for label, col in zip(bucket_labels, bucket_cols):
            bucket_data[label].append(df[col].mean())
    
    if not variant_names:
        print("  Skipped: latency_histogram (no histogram data)")
        return
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    x = np.arange(len(variant_names))
    width = 0.6
    
    bottom = np.zeros(len(variant_names))
    colors = plt.cm.RdYlGn(np.linspace(0.9, 0.1, len(bucket_labels)))
    
    for i, (label, color) in enumerate(zip(bucket_labels, colors)):
        values = bucket_data[label]
        ax.bar(x, values, width, bottom=bottom, label=label, color=color,
               edgecolor='white', linewidth=0.5)
        bottom += np.array(values)
    
    ax.set_xlabel('Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Percentage (%)', fontsize=FONT_SIZE)
    ax.set_title('Latency Distribution by Policy', fontsize=TITLE_SIZE)
    ax.set_xticks(x)
    ax.set_xticklabels(variant_names, fontsize=FONT_SIZE)
    ax.legend(title='Latency Bucket', loc='upper right', fontsize=FONT_SIZE - 2)
    ax.set_ylim(0, 105)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'latency_histogram.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'latency_histogram.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: latency_histogram.png/pdf")


def plot_improvement_chart(variants: Dict[str, Dict], output_dir: Path):
    """Show improvement of dynamic over baseline policies."""
    if not HAS_MATPLOTLIB:
        return
    
    if 'dynamic' not in variants:
        print("  Skipped: improvement_chart (no dynamic variant)")
        return
    
    dynamic_makespan = variants['dynamic'].get('makespan_sec', 0)
    if dynamic_makespan == 0:
        return
    
    improvements = []
    names = []
    
    for name, data in sorted(variants.items()):
        if name == 'dynamic':
            continue
        makespan = data.get('makespan_sec', 0)
        if makespan > 0:
            # Negative improvement means dynamic is better (faster)
            improvement = (makespan - dynamic_makespan) / makespan * 100
            improvements.append(improvement)
            names.append(name.upper())
    
    if not names:
        return
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    x = np.arange(len(names))
    colors = ['#44AF69' if v > 0 else '#E94F37' for v in improvements]
    bars = ax.bar(x, improvements, color=colors, edgecolor='black', linewidth=0.5)
    
    # Add value labels
    for bar, val in zip(bars, improvements):
        height = bar.get_height()
        va = 'bottom' if height >= 0 else 'top'
        offset = 3 if height >= 0 else -3
        ax.annotate(f'{val:+.1f}%',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, offset),
                    textcoords="offset points",
                    ha='center', va=va,
                    fontsize=FONT_SIZE)
    
    ax.axhline(0, color='black', linewidth=0.8)
    ax.set_xlabel('Baseline Policy', fontsize=FONT_SIZE)
    ax.set_ylabel('Improvement (%)', fontsize=FONT_SIZE)
    ax.set_title('Dynamic Policy Improvement Over Static Policies', fontsize=TITLE_SIZE)
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=FONT_SIZE)
    ax.tick_params(axis='y', labelsize=FONT_SIZE)
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)
    
    plt.tight_layout()
    plt.savefig(output_dir / 'improvement_chart.png', dpi=300, bbox_inches='tight')
    plt.savefig(output_dir / 'improvement_chart.pdf', bbox_inches='tight')
    plt.close()
    
    print(f"  Generated: improvement_chart.png/pdf")


def generate_summary_table(variants: Dict[str, Dict], output_dir: Path):
    """Generate a summary table in CSV and LaTeX format."""
    rows = []
    
    for name, data in sorted(variants.items()):
        row = {
            'Policy': name.upper(),
            'Makespan (s)': f"{data.get('makespan_sec', 0):.2f}",
        }
        
        if 'phases' in data:
            df = data['phases']
            row['Accesses'] = f"{df['accesses'].sum():,}"
            if 'lat_avg_us' in df.columns:
                row['Avg Latency (μs)'] = f"{df['lat_avg_us'].mean():.1f}"
        
        if 'summary' in data:
            total_accesses = sum(p['accesses'] for p in data['summary']['phases'])
            total_time = data['summary']['total_duration_sec']
            if total_time > 0:
                row['Throughput (K/s)'] = f"{total_accesses / total_time / 1000:.1f}"
        
        if name == 'dynamic' and 'switches' in data:
            row['Policy Switches'] = len(data['switches'])
        
        rows.append(row)
    
    # Write CSV
    if rows:
        csv_path = output_dir / 'summary_table.csv'
        if HAS_PANDAS:
            pd.DataFrame(rows).to_csv(csv_path, index=False)
        else:
            with open(csv_path, 'w') as f:
                headers = rows[0].keys()
                f.write(','.join(headers) + '\n')
                for row in rows:
                    f.write(','.join(str(row.get(h, '')) for h in headers) + '\n')
        print(f"  Generated: summary_table.csv")
    
    # Write LaTeX
    latex_path = output_dir / 'summary_table.tex'
    with open(latex_path, 'w') as f:
        f.write("\\begin{table}[htbp]\n")
        f.write("\\centering\n")
        f.write("\\caption{Cache Policy Performance Comparison}\n")
        f.write("\\label{tab:policy_comparison}\n")
        
        if rows:
            cols = list(rows[0].keys())
            f.write("\\begin{tabular}{" + "l" * len(cols) + "}\n")
            f.write("\\toprule\n")
            f.write(" & ".join(cols) + " \\\\\n")
            f.write("\\midrule\n")
            for row in rows:
                f.write(" & ".join(str(row.get(c, '')) for c in cols) + " \\\\\n")
            f.write("\\bottomrule\n")
            f.write("\\end{tabular}\n")
        
        f.write("\\end{table}\n")
    print(f"  Generated: summary_table.tex")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Generate plots for 14weeks experiment')
    parser.add_argument('--input', '-i', required=True, help='Input directory (run stamp folder)')
    parser.add_argument('--output', '-o', help='Output directory (default: same as input)')
    args = parser.parse_args()
    
    input_dir = Path(args.input)
    output_dir = Path(args.output) if args.output else input_dir
    
    if not input_dir.exists():
        print(f"Error: Input directory not found: {input_dir}", file=sys.stderr)
        sys.exit(1)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading results from: {input_dir}")
    variants = load_all_variants(input_dir)
    
    if not variants:
        print("No variant data found!")
        sys.exit(1)
    
    print(f"Found {len(variants)} variants: {', '.join(variants.keys())}")
    print(f"\nGenerating plots...")
    
    plot_makespan_comparison(variants, output_dir)
    plot_per_phase_duration(variants, output_dir)
    plot_latency_distribution(variants, output_dir)
    plot_throughput_comparison(variants, output_dir)
    plot_policy_switches(variants, output_dir)
    plot_latency_histogram(variants, output_dir)
    plot_improvement_chart(variants, output_dir)
    generate_summary_table(variants, output_dir)
    
    print(f"\nDone! Results saved to: {output_dir}")


if __name__ == '__main__':
    main()

