#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def directed_pair(trade: Dict[str, Any]) -> Tuple[str, str]:
    return (str(trade["sell_token"]).lower(), str(trade["buy_token"]).lower())


@dataclass
class AuctionStats:
    auction_id: int
    auction_index: int          # sequential position (0-based)
    solutions: int
    max_trades_in_solution: int
    max_pairs_in_solution: int
    max_trades_solution_uid: int
    max_pairs_solution_uid: int


def compute_stats(data: Dict[str, Any]) -> Tuple[List[AuctionStats], Dict[str, Any]]:
    auctions = data.get("auctions", [])
    per_auction: List[AuctionStats] = []

    all_solution_trade_counts: List[int] = []
    all_solution_pair_counts: List[int] = []
    all_auction_solution_counts: List[int] = []

    for idx, a in enumerate(auctions):
        auction_id = int(a["auction_id"])
        sols = a.get("solutions", [])
        solutions_count = len(sols)
        all_auction_solution_counts.append(solutions_count)

        max_trades, max_pairs = 0, 0
        max_trades_uid, max_pairs_uid = -1, -1

        for sol in sols:
            uid = int(sol.get("solution_uid", -1))
            trades = sol.get("trades", [])
            tcnt = len(trades)
            pcnt = len(set(directed_pair(t) for t in trades))

            all_solution_trade_counts.append(tcnt)
            all_solution_pair_counts.append(pcnt)

            if tcnt > max_trades:
                max_trades, max_trades_uid = tcnt, uid
            if pcnt > max_pairs:
                max_pairs, max_pairs_uid = pcnt, uid

        per_auction.append(AuctionStats(
            auction_id=auction_id,
            auction_index=idx,
            solutions=solutions_count,
            max_trades_in_solution=max_trades,
            max_pairs_in_solution=max_pairs,
            max_trades_solution_uid=max_trades_uid,
            max_pairs_solution_uid=max_pairs_uid,
        ))

    rng = data.get("range", {})
    summary = {
        "input_range": rng,
        "counts": {
            "auctions": len(auctions),
            "solutions_total": sum(all_auction_solution_counts),
            "trades_total": sum(all_solution_trade_counts),
        },
        "solutions_per_auction": {
            "max": int(max(all_auction_solution_counts)) if all_auction_solution_counts else 0,
            "mean": float(np.mean(all_auction_solution_counts)) if all_auction_solution_counts else 0,
        },
        "trades_per_solution": {
            "max": int(max(all_solution_trade_counts)) if all_solution_trade_counts else 0,
            "mean": float(np.mean(all_solution_trade_counts)) if all_solution_trade_counts else 0,
        },
        "pairs_per_solution": {
            "max": int(max(all_solution_pair_counts)) if all_solution_pair_counts else 0,
            "mean": float(np.mean(all_solution_pair_counts)) if all_solution_pair_counts else 0,
        },
    }

    return per_auction, summary


def build_title(summary: Dict[str, Any]) -> str:
    rng = summary.get("input_range", {})
    start = rng.get("auction_start", rng.get("start", "?"))
    end = rng.get("auction_end", rng.get("end", "?"))
    n = summary["counts"]["auctions"]
    return f"Auction Analysis  |  Auctions {start} – {end}  |  n = {n:,}"


def plot_solutions_heatmap(per_auction: List[AuctionStats], title: str, out_path: str) -> None:
    indices = np.array([s.auction_index for s in per_auction])
    solutions = np.array([s.solutions for s in per_auction])

    n_auctions = len(per_auction)
    max_sols = int(solutions.max()) if len(solutions) else 1

    x_bins = min(80, n_auctions)
    y_bins = max_sols + 1  # one bin per solution count value

    h, xedges, yedges = np.histogram2d(
        indices, solutions,
        bins=[x_bins, y_bins],
        range=[[0, n_auctions], [0, max_sols + 1]],
    )

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.suptitle(title, fontsize=11, fontweight="bold", y=1.01)

    im = ax.imshow(
        h.T,
        origin="lower",
        aspect="auto",
        extent=[xedges[0], xedges[-1], yedges[0], yedges[-1]],
        cmap="YlOrRd",
        interpolation="nearest",
    )

    cbar = fig.colorbar(im, ax=ax, label="# auctions in bin")
    ax.set_xlabel("Auction index (chronological)")
    ax.set_ylabel("Number of solutions")
    ax.set_title("Distribution of solutions per auction over time")


    mean_line = float(np.mean(solutions))
    ax.axhline(mean_line, color="#2c7bb6", linewidth=1.4, linestyle="--", label=f"mean = {mean_line:.1f}")
    ax.legend(loc="upper right", fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")



def plot_complexity(per_auction: List[AuctionStats], title: str, out_path: str) -> None:
    solutions = np.array([s.solutions for s in per_auction])
    max_trades = np.array([s.max_trades_in_solution for s in per_auction])
    max_pairs = np.array([s.max_pairs_in_solution for s in per_auction])
    # Color by auction index to reveal time trends
    c = np.array([s.auction_index for s in per_auction])

    fig = plt.figure(figsize=(14, 5))
    fig.suptitle(title, fontsize=11, fontweight="bold")
    gs = gridspec.GridSpec(1, 2, figure=fig, wspace=0.30)

    common_scatter_kw = dict(s=12, alpha=0.55, cmap="viridis", c=c)

    ax1 = fig.add_subplot(gs[0])
    sc1 = ax1.scatter(solutions, max_trades, **common_scatter_kw)
    ax1.set_xlabel("Solutions in auction")
    ax1.set_ylabel("Max trades in any solution")
    ax1.set_title("Per-auction: solutions  ×  max trades")
    fig.colorbar(sc1, ax=ax1, label="auction index")

    if len(max_trades):
        idx_max = int(np.argmax(max_trades))
        ax1.annotate(
            f"  max={max_trades[idx_max]}\n  auction {per_auction[idx_max].auction_id}",
            xy=(solutions[idx_max], max_trades[idx_max]),
            fontsize=7, color="#c0392b",
        )

    ax2 = fig.add_subplot(gs[1])
    sc2 = ax2.scatter(solutions, max_pairs, **common_scatter_kw)
    ax2.set_xlabel("Solutions in auction")
    ax2.set_ylabel("Max distinct directed pairs in any solution")
    ax2.set_title("Per-auction: solutions  ×  max directed pairs")
    fig.colorbar(sc2, ax=ax2, label="auction index")

    if len(max_pairs):
        idx_max = int(np.argmax(max_pairs))
        ax2.annotate(
            f"  max={max_pairs[idx_max]}\n  auction {per_auction[idx_max].auction_id}",
            xy=(solutions[idx_max], max_pairs[idx_max]),
            fontsize=7, color="#c0392b",
        )

    plt.tight_layout()
    plt.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


def save_csv(per_auction: List[AuctionStats], out_path: str) -> None:
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "auction_id", "auction_index", "solutions",
            "max_trades_in_solution", "max_trades_solution_uid",
            "max_pairs_in_solution", "max_pairs_solution_uid",
        ])
        for s in per_auction:
            w.writerow([
                s.auction_id, s.auction_index, s.solutions,
                s.max_trades_in_solution, s.max_trades_solution_uid,
                s.max_pairs_in_solution, s.max_pairs_solution_uid,
            ])

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to auctions_<start>_<end>.json")
    ap.add_argument("--out_dir", default="analysis_out", help="Output directory")
    ap.add_argument("--topk", type=int, default=25, help="Top-k worst-case auctions in summary.json")
    args = ap.parse_args()

    data = load_json(args.input)
    per_auction, summary = compute_stats(data)
    ensure_dir(args.out_dir)

    csv_path = os.path.join(args.out_dir, "per_auction.csv")
    save_csv(per_auction, csv_path)
    print(f"Saved: {csv_path}")

    summary["worst_auctions"] = {
        "by_solutions": [
            {"auction_id": s.auction_id, "solutions": s.solutions}
            for s in sorted(per_auction, key=lambda s: s.solutions, reverse=True)[: args.topk]
        ],
        "by_max_trades": [
            {"auction_id": s.auction_id, "max_trades": s.max_trades_in_solution,
             "solution_uid": s.max_trades_solution_uid}
            for s in sorted(per_auction, key=lambda s: s.max_trades_in_solution, reverse=True)[: args.topk]
        ],
        "by_max_pairs": [
            {"auction_id": s.auction_id, "max_pairs": s.max_pairs_in_solution,
             "solution_uid": s.max_pairs_solution_uid}
            for s in sorted(per_auction, key=lambda s: s.max_pairs_in_solution, reverse=True)[: args.topk]
        ],
    }

    summary_path = os.path.join(args.out_dir, "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved: {summary_path}")

    chart_title = build_title(summary)

    plot_solutions_heatmap(
        per_auction, chart_title,
        os.path.join(args.out_dir, "plot1_solutions_heatmap.png"),
    )

    plot_complexity(
        per_auction, chart_title,
        os.path.join(args.out_dir, "plot2_complexity.png"),
    )


if __name__ == "__main__":
    main()