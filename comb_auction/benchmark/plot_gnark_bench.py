#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np


def load(path: str) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def clean(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        if r.get('error'):
            print(f"  skip (error): {r['params']} — {r['error'][:80]}")
            continue
        r['constraints'] = r.get('setup', {}).get('constraints') or 0
        r['witness_s']   = r.get('prove', {}).get('witness_s')
        r['prove_s']     = r.get('prove', {}).get('prove_s')
        r['verify_s']    = r.get('prove', {}).get('verify_s')
        out.append(r)
    return out


def group_by(records, vary_key, fixed):
    out = [r for r in records if all(r['params'].get(k) == v for k, v in fixed.items())]
    return sorted(out, key=lambda r: r['params'][vary_key])


def label(p):
    return f"N={p['NMax']} T={p['TMax']} W={p['WMax']} P={p['PairMax']}"


def fmt_c(ax):
    ax.yaxis.set_major_formatter(
        ticker.FuncFormatter(lambda x, _: f'{x/1e6:.1f}M' if x >= 1e6 else f'{x/1e3:.0f}k')
    )


def save(fig, path):
    fig.savefig(path, dpi=130, bbox_inches='tight')
    print(f"  saved {path}")
    plt.close(fig)


def sweep_plot(records, vary_key, fixed, out_dir, filename, title):
    subset = group_by(records, vary_key, fixed)
    if len(subset) < 2:
        print(f"  {filename}: not enough points ({len(subset)} found for fixed={fixed}), skipping")
        return

    xs     = [r['params'][vary_key] for r in subset]
    constr = [r['constraints']      for r in subset]
    prove  = [r['prove_s']          for r in subset]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    fig.suptitle(title)

    ax1.plot(xs, constr, marker='o')
    ax1.set_xlabel(vary_key)
    ax1.set_ylabel('Constraints')
    ax1.set_title(f'Constraints vs {vary_key}')
    ax1.set_xticks(xs)
    ax1.grid(True)
    fmt_c(ax1)

    ax2.plot(xs, prove, marker='o', color='tab:orange')
    ax2.set_xlabel(vary_key)
    ax2.set_ylabel('Prove time (ms)')
    ax2.set_title(f'Prove time vs {vary_key}')
    ax2.set_xticks(xs)
    ax2.grid(True)

    fig.tight_layout()
    save(fig, out_dir / filename)


def timing_breakdown(records, out_dir):
    valid = [r for r in records if r.get('prove_s') is not None]
    if not valid:
        return

    valid   = sorted(valid, key=lambda r: (r['witness_s'] or 0) + (r['prove_s'] or 0))
    labels  = [label(r['params']) for r in valid]
    witness = [r['witness_s'] or 0 for r in valid]
    prove   = [r['prove_s']   or 0 for r in valid]
    ys      = np.arange(len(valid))

    fig, ax = plt.subplots(figsize=(10, max(4, len(valid) * 0.5 + 1)))
    ax.barh(ys, witness, label='Witness')
    ax.barh(ys, prove,   label='Prove', left=witness)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel('Time (ms)')
    ax.set_title('Timing breakdown per config')
    ax.legend()
    ax.grid(True, axis='x')
    fig.tight_layout()
    save(fig, out_dir / 'timing_breakdown.png')


def summary_bars(records, out_dir):
    valid = sorted([r for r in records if r.get('prove_s') is not None], key=lambda r: r['prove_s'])
    if not valid:
        return

    labels = [label(r['params']) for r in valid]
    prove  = [r['prove_s']     for r in valid]
    constr = [r['constraints'] for r in valid]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, max(4, len(valid) * 0.5 + 1)))

    b1 = ax1.barh(labels, prove)
    ax1.set_xlabel('Prove time (ms)')
    ax1.set_title('Prove time per config')
    ax1.bar_label(b1, fmt='%.0fms', padding=3, fontsize=8)
    ax1.invert_yaxis()
    ax1.grid(True, axis='x')

    b2 = ax2.barh(labels, constr, color='tab:orange')
    ax2.set_xlabel('Constraints')
    ax2.set_title('Constraints per config')
    fmt_c(ax2)
    ax2.bar_label(b2, labels=[f'{v/1e6:.2f}M' if v >= 1e6 else f'{v/1e3:.0f}k' for v in constr],
                  padding=3, fontsize=8)
    ax2.invert_yaxis()
    ax2.grid(True, axis='x')

    fig.tight_layout()
    save(fig, out_dir / 'summary_bars.png')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input',   default='benchmark_results.json')
    ap.add_argument('--out_dir', default='gnark-plots')
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records = clean(load(args.input))
    print(f"  {len(records)} records loaded")
    if not records:
        return

    sweep_plot(records, 'NMax',    {'TMax': 10,  'WMax': 30, 'PairMax': 10}, out_dir, 'nmax_sweep.png',    'Effect of NMax (TMax=10, WMax=30, PairMax=10)')
    sweep_plot(records, 'TMax',    {'NMax': 120, 'WMax': 30, 'PairMax': 10}, out_dir, 'tmax_sweep.png',    'Effect of TMax (NMax=120, WMax=30, PairMax=10)')
    sweep_plot(records, 'PairMax', {'NMax': 120, 'WMax': 30, 'TMax': 10},    out_dir, 'pairmax_sweep.png', 'Effect of PairMax (NMax=120, WMax=30, TMax=10)')
    timing_breakdown(records, out_dir)
    summary_bars(records, out_dir)

    def fm(v):
        return f"{v:.0f}ms" if v is not None else "   -"

    print(f"\n  {'Config':<38} {'Auction':>10} {'Constraints':>13} {'Witness':>10} {'Prove':>10}")
    print(f"  {'-'*85}")
    for r in sorted(records, key=lambda x: x.get('prove_s') or 0):
        p  = r['params']
        c  = r['constraints']
        cs = f"{c/1e6:.2f}M" if c >= 1e6 else f"{c/1e3:.0f}k"
        print(f"  {label(p):<38} {str(r.get('auction_id') or '-'):>10} {cs:>13} {fm(r['witness_s']):>10} {fm(r['prove_s']):>10}")


if __name__ == '__main__':
    main()