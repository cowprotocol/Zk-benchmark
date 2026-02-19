#!/usr/bin/env python3
import argparse
import json
import os
import re
import statistics
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

@dataclass
class AuctionStats:
    auction_index: int
    auction_id: int
    num_solutions: int
    total_trades: int
    max_trades_per_solution: int
    max_pairs_per_solution: int 


def directed_pair(trade: Dict[str, Any]) -> Tuple[str, str]:
    return (trade["sell_token"].lower(), trade["buy_token"].lower())


def compute_auction_stats(auction_index: int, auction: Dict[str, Any]) -> AuctionStats:
    solutions = auction.get("solutions", [])
    num_solutions = len(solutions)

    total_trades = 0
    max_trades = 0
    max_pairs = 0

    for sol in solutions:
        trades = sol.get("trades", [])
        tlen = len(trades)
        total_trades += tlen
        max_trades = max(max_trades, tlen)

        pairs = set(directed_pair(t) for t in trades)
        max_pairs = max(max_pairs, len(pairs))

    return AuctionStats(
        auction_index=auction_index,
        auction_id=int(auction["auction_id"]),
        num_solutions=num_solutions,
        total_trades=total_trades,
        max_trades_per_solution=max_trades,
        max_pairs_per_solution=max_pairs,
    )


def median_target(stats: List[AuctionStats]) -> Tuple[float, float, float]:
    sols = [s.num_solutions for s in stats]
    mxtr = [s.max_trades_per_solution for s in stats]
    mxpa = [s.max_pairs_per_solution for s in stats]
    return (statistics.median(sols), statistics.median(mxtr), statistics.median(mxpa))


def pick_candidates(stats: List[AuctionStats], k: int = 5) -> List[AuctionStats]:
    if not stats:
        return []

    # most solutions
    a = max(stats, key=lambda s: (s.num_solutions, s.total_trades, s.max_trades_per_solution))

    # high solutions + high max trades
    b = max(stats, key=lambda s: (s.num_solutions, s.max_trades_per_solution, s.total_trades))

    # highest max pairs
    c = max(stats, key=lambda s: (s.max_pairs_per_solution, s.num_solutions, s.total_trades))

    # big overall weighted
    def score_big(s: AuctionStats) -> float:
        return (
            3.0 * s.num_solutions
            + 2.0 * s.max_trades_per_solution
            + 2.0 * s.max_pairs_per_solution
            + 0.01 * s.total_trades
        )

    d = max(stats, key=score_big)

    # typical (closest to medians)
    ms, mt, mp = median_target(stats)

    def dist_med(s: AuctionStats) -> float:
        return (s.num_solutions - ms) ** 2 + (s.max_trades_per_solution - mt) ** 2 + (s.max_pairs_per_solution - mp) ** 2

    e = min(stats, key=dist_med)

    picked = [a, b, c, d, e]

    # Dedup
    seen = set()
    uniq: List[AuctionStats] = []
    for s in picked:
        key = (s.auction_index, s.auction_id)
        if key not in seen:
            seen.add(key)
            uniq.append(s)

    if len(uniq) < k:
        remaining = [x for x in stats if (x.auction_index, x.auction_id) not in seen]
        remaining.sort(key=score_big, reverse=True)
        uniq.extend(remaining[: (k - len(uniq))])

    return uniq[:k]


def run_cmd(cmd: List[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    t0 = time.perf_counter()
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    t1 = time.perf_counter()
    return {
        "returncode": p.returncode,
        "wall_seconds": t1 - t0,
        "stdout": p.stdout,
    }


def default_witness_lib() -> Path:
    ext = "dylib" if (os.uname().sysname.lower() == "darwin") else "so"
    return Path.home() / ".zisk" / "bin" / f"libzisk_witness.{ext}"


_RE_INT_COMMAS = re.compile(r"(\d[\d,]*)")

def _parse_int_commas(s: str) -> int:
    return int(s.replace(",", "").strip())


def parse_ziskemu_report(out: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {}

    m = re.search(r"^\s*STEPS\s+(\d[\d,]*)\s*$", out, flags=re.MULTILINE)
    if m:
        res["steps"] = _parse_int_commas(m.group(1))

    m = re.search(r"^\s*TOTAL\s+(\d[\d,]*)\s+100\.00%\s*$", out, flags=re.MULTILINE)
    if m:
        res["total_cost"] = _parse_int_commas(m.group(1))

    m = re.search(r"^\s*RAM USAGE\s+(\d[\d,]*)\s+", out, flags=re.MULTILINE)
    if m:
        res["ram_usage_bytes"] = _parse_int_commas(m.group(1))

    return res


def parse_prove_summary(out: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {}

    m = re.search(
        r"time:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds,\s*steps:\s*([0-9]+)",
        out,
        flags=re.IGNORECASE,
    )
    if m:
        res["time_seconds"] = float(m.group(1))
        res["steps"] = int(m.group(2))

    return res

def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument("--auction-start", type=int, required=True)
    ap.add_argument("--auction-end", type=int, required=True)

    ap.add_argument("--data-dir", type=str, default="data")
    ap.add_argument("--host-dir", type=str, default="host")
    ap.add_argument("--guest-dir", type=str, default="guest")

    ap.add_argument("--elf", type=str, default="target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction")
    ap.add_argument("--input", type=str, default="build/input.bin")

    ap.add_argument("--proving-key", type=str, default=str(Path.home() / ".zisk" / "provingKey"))
    ap.add_argument("--witness-lib", type=str, default="", help="Optional override. Default: ~/.zisk/bin/libzisk_witness.(so|dylib)")

    ap.add_argument("--out-jsonl", type=str, default="zisk_bench_results.jsonl")
    ap.add_argument("--num-cases", type=int, default=5)

    args = ap.parse_args()

    auction_start = args.auction_start
    auction_end = args.auction_end

    data_dir = Path(args.data_dir)
    host_dir = Path(args.host_dir)
    guest_dir = Path(args.guest_dir)

    json_path = data_dir / f"auctions_{auction_start}_{auction_end}.json"
    if not json_path.exists():
        raise SystemExit(f"missing JSON: {json_path}")

    with json_path.open("r", encoding="utf-8") as f:
        root = json.load(f)

    auctions = root.get("auctions", [])
    if not auctions:
        raise SystemExit("JSON has no auctions[]")

    all_stats: List[AuctionStats] = [compute_auction_stats(i, a) for i, a in enumerate(auctions)]
    candidates = pick_candidates(all_stats, k=args.num_cases)

    elf_path = Path(args.elf)         
    input_path = Path(args.input)   
    proving_key = Path(args.proving_key)
    witness_lib = Path(args.witness_lib) if args.witness_lib.strip() else default_witness_lib()

    out_jsonl = Path(args.out_jsonl)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    print(f"[bench] loaded {len(auctions)} auctions from {json_path}")
    print("[bench] selected candidates:")
    for s in candidates:
        print(
            f"  - idx={s.auction_index} auction_id={s.auction_id} "
            f"solutions={s.num_solutions} max_trades={s.max_trades_per_solution} "
            f"max_pairs={s.max_pairs_per_solution} total_trades={s.total_trades}"
        )

    for s in candidates:
        host_cmd = [
            "cargo", "run", "--release", "--",
            "--auction-start", str(auction_start),
            "--auction-end", str(auction_end),
            "--auction-index", str(s.auction_index),
        ]
        host_res = run_cmd(host_cmd, cwd=host_dir)
        if host_res["returncode"] != 0:
            raise SystemExit(
                f"[bench] host failed for idx={s.auction_index}, auction_id={s.auction_id}\n"
                f"{host_res['stdout']}"
            )

        ziskemu_cmd = [
            "ziskemu",
            "-e", str(elf_path),
            "-i", str(input_path),
            "-X", "-S", "-D",
        ]
        ziskemu_res = run_cmd(ziskemu_cmd, cwd=guest_dir)
        if ziskemu_res["returncode"] != 0:
            raise SystemExit(
                f"[bench] ziskemu failed for auction_id={s.auction_id}\n"
                f"{ziskemu_res['stdout']}"
            )
        ziskemu_metrics = parse_ziskemu_report(ziskemu_res["stdout"])
        if "steps" not in ziskemu_metrics:
            raise SystemExit(
                f"[bench] ziskemu output did not contain STEPS for auction_id={s.auction_id}\n"
                f"(update parser if format changed)\n"
                f"{ziskemu_res['stdout']}"
            )

        prove_cmd = [
            "cargo-zisk", "prove",
            "-e", str(elf_path),
            "-i", str(input_path),
            "-w", str(witness_lib),
            "-k", str(proving_key),
            "-o", "proof",  
        ]
        prove_res = run_cmd(prove_cmd, cwd=guest_dir)
        if prove_res["returncode"] != 0:
            raise SystemExit(
                f"[bench] prove failed for auction_id={s.auction_id}\n"
                f"{prove_res['stdout']}"
            )

        prove_metrics = parse_prove_summary(prove_res["stdout"])
        if "time_seconds" not in prove_metrics or "steps" not in prove_metrics:
            raise SystemExit(
                f"[bench] prove output did not contain final summary time/steps for auction_id={s.auction_id}\n"
                f"(update parser if format changed)\n"
                f"{prove_res['stdout']}"
            )

        record = {
            "auction_start": auction_start,
            "auction_end": auction_end,
            "auction_index": s.auction_index,
            "auction_id": s.auction_id,
            "stats": {
                "num_solutions": s.num_solutions,
                "total_trades": s.total_trades,
                "max_trades_per_solution": s.max_trades_per_solution,
                "max_pairs_per_solution": s.max_pairs_per_solution,
            },
            "ziskemu": {
                "steps": ziskemu_metrics["steps"],
                "total_cost": ziskemu_metrics.get("total_cost"),
                "ram_usage_bytes": ziskemu_metrics.get("ram_usage_bytes"),
            },
            "prove": {
                "time_seconds": prove_metrics["time_seconds"],
                "steps": prove_metrics["steps"],
            },
        }

        with out_jsonl.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        print(
            f"[bench] auction_id={s.auction_id} "
            f"emu_steps={record['ziskemu']['steps']} "
            f"prove_time={record['prove']['time_seconds']:.2f}s "
            f"prove_steps={record['prove']['steps']}"
        )

    print(f"[bench] results appended to {out_jsonl}")


if __name__ == "__main__":
    main()
