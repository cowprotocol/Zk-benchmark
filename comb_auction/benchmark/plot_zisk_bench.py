#!/usr/bin/env python3

import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

INPUT  = Path('./zisk_bench_results.jsonl')
OUT_DIR = Path('./zisk-plots')

def load_jsonl(path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def enrich(records):
    out = []
    for r in records:
        stats  = r.get('stats')  or {}
        prove  = r.get('prove')  or {}
        steps  = prove.get('steps')
        time_s = prove.get('time_seconds')
        if steps is None and time_s is None:
            continue

        total_trades = stats.get('total_trades') or 1
        real = isinstance(r.get('auction_id'), int) and r.get('auction_start', 0) != 0

        out.append({
            'auction_id':     r.get('auction_id'),
            'auction_index':  r.get('auction_index'),
            'real':           real,
            'num_solutions':  stats.get('num_solutions', 0),
            'total_trades':   total_trades,
            'tmax':           stats.get('max_trades_per_solution', 0),
            'pmax':           stats.get('max_pairs_per_solution', 0),
            'steps':          steps,
            'time_s':         time_s,
            'steps_per_trade': (steps / total_trades) if steps else None,
        })
    return out


def label(r):
    if r['real']:
        return f"real {r['auction_id']}"
    return f"synth N={r['num_solutions']} T={r['tmax']} P={r['pmax']}"


def fmt_steps_ax(ax):
    ax.xaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{x/1e6:.1f}M' if x >= 1e6 else f'{x/1e3:.0f}k')
    )


def save(fig, path):
    fig.savefig(path, dpi=130, bbox_inches='tight')
    print(f"  saved {path}")
    plt.close(fig)


def plot_summary(records, out_dir):
    valid = sorted([r for r in records if r['steps'] and r['time_s']], key=lambda r: r['steps'])
    if not valid:
        return

    labels = [label(r) for r in valid]
    steps  = [r['steps']  for r in valid]
    times  = [r['time_s'] for r in valid]
    colors = ['tab:orange' if r['real'] else 'tab:blue' for r in valid]
    h      = max(4, len(valid) * 0.5 + 1)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, h))
    fig.suptitle('Benchmark summary  (orange = real, blue = synthetic)')

    b1 = ax1.barh(labels, steps, color=colors)
    ax1.bar_label(b1,
                  labels=[f'{s/1e6:.2f}M' if s >= 1e6 else f'{s/1e3:.0f}k' for s in steps],
                  padding=4, fontsize=8)
    ax1.set_xlabel('Steps')
    ax1.set_title('Steps')
    ax1.invert_yaxis()
    ax1.grid(True, axis='x')
    fmt_steps_ax(ax1)

    b2 = ax2.barh(labels, times, color=colors)
    ax2.bar_label(b2, labels=[f'{t:.2f}s' for t in times], padding=4, fontsize=8)
    ax2.set_xlabel('Prove time (s)')
    ax2.set_title('Prove time')
    ax2.invert_yaxis()
    ax2.grid(True, axis='x')

    fig.tight_layout()
    save(fig, out_dir / 'summary.png')


def plot_steps_vs_trades(records, out_dir):
    real  = [r for r in records if     r['real'] and r['steps']]
    synth = [r for r in records if not r['real'] and r['steps']]
    if not real and not synth:
        return

    fig, ax = plt.subplots(figsize=(9, 5))

    for grp, color, marker, name in [
        (synth, 'tab:blue',   's', 'Synthetic'),
        (real,  'tab:orange', 'o', 'Real'),
    ]:
        if not grp:
            continue
        xs = [r['total_trades'] for r in grp]
        ys = [r['steps']        for r in grp]
        ax.scatter(xs, ys, color=color, marker=marker, label=name, s=65, zorder=3)
        if len(grp) >= 2:
            c = np.polyfit(xs, ys, 1)
            xl = np.linspace(min(xs), max(xs), 200)
            ax.plot(xl, np.polyval(c, xl), '--', color=color, alpha=0.6,
                    label=f'{name} fit  {c[0]:,.0f} steps/trade')

    ax.set_xlabel('Total trades')
    ax.set_ylabel('Steps')
    ax.set_title('Steps vs total trades')
    ax.legend()
    ax.grid(True)
    ax.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{x/1e6:.1f}M' if x >= 1e6 else f'{x/1e3:.0f}k')
    )
    fig.tight_layout()
    save(fig, out_dir / 'steps_vs_trades.png')


def plot_nmax_sweep(records, out_dir):
    from collections import defaultdict
    synth = [r for r in records if not r['real'] and r['steps']]
    if len(synth) < 2:
        return

    groups = defaultdict(list)
    for r in synth:
        groups[(r['tmax'], r['pmax'])].append(r)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    fig.suptitle('Synthetic sweep: NMax')

    for (tmax, pmax), grp in sorted(groups.items()):
        grp = sorted(grp, key=lambda r: r['num_solutions'])
        if len(set(r['num_solutions'] for r in grp)) < 2:
            continue
        xs = [r['num_solutions'] for r in grp]
        ax1.plot(xs, [r['steps']  for r in grp], marker='o', label=f'T={tmax} P={pmax}')
        ax2.plot(xs, [r['time_s'] for r in grp], marker='o', label=f'T={tmax} P={pmax}')

    for ax, ylabel, title in [
        (ax1, 'Steps',          'Steps vs NMax'),
        (ax2, 'Prove time (s)', 'Prove time vs NMax'),
    ]:
        ax.set_xlabel('NMax')
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.legend()
        ax.grid(True)

    ax1.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{x/1e6:.1f}M' if x >= 1e6 else f'{x/1e3:.0f}k')
    )
    fig.tight_layout()
    save(fig, out_dir / 'nmax_sweep.png')


def plot_tmax_sweep(records, out_dir):
    synth = sorted(
        [r for r in records if not r['real'] and r['steps'] and r['num_solutions'] == 120],
        key=lambda r: r['tmax']
    )
    if len(synth) < 2:
        return

    xs       = [r['tmax']   for r in synth]
    ys_steps = [r['steps']  for r in synth]
    ys_time  = [r['time_s'] for r in synth]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    fig.suptitle('Synthetic sweep: TMax  (NMax=120, PairMax=10)')

    ax1.plot(xs, ys_steps, marker='o', color='tab:blue')
    ax1.set_xlabel('TMax')
    ax1.set_ylabel('Steps')
    ax1.set_title('Steps vs TMax')
    ax1.set_xticks(xs)
    ax1.grid(True)
    ax1.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{x/1e6:.1f}M' if x >= 1e6 else f'{x/1e3:.0f}k')
    )

    ax2.plot(xs, ys_time, marker='o', color='tab:orange')
    ax2.set_xlabel('TMax')
    ax2.set_ylabel('Prove time (s)')
    ax2.set_title('Prove time vs TMax')
    ax2.set_xticks(xs)
    ax2.grid(True)

    fig.tight_layout()
    save(fig, out_dir / 'tmax_sweep.png')


def main():
    out_dir = OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    records = enrich(load_jsonl(INPUT))
    n_real  = sum(r['real'] for r in records)
    print(f"  {len(records)} records  ({n_real} real, {len(records)-n_real} synthetic)")

    plot_summary(records, out_dir)         
    plot_steps_vs_trades(records, out_dir) 
    plot_nmax_sweep(records, out_dir)      
    plot_tmax_sweep(records, out_dir)     


if __name__ == '__main__':
    main()