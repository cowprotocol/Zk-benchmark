#!/usr/bin/env python3
"""
Usage:
  uv run bench_gnark.py \
    --circuit_path  "../circuit/comb_gnark/circuit.go" \
    --setup_dir     "../circuit/comb_gnark/setup/main.go" \
    --prover_dir    "../circuit/comb_gnark/prover/main.go" \
    --output        benchmark_results.json \
    --auction_start $((12311225 - 1000)) \
    --auction_end   12311225 \
    --auction_index 13
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

BASELINE = dict(NMax=120, TMax=10, WMax=30, PairMax=10, TreeDepth=7)

PARAM_GRID = [
    dict(NMax=120, TMax=10, WMax=30, PairMax=10, TreeDepth=7),
    dict(NMax=200, TMax=10, WMax=30, PairMax=10, TreeDepth=8),
    dict(NMax=300, TMax=10, WMax=30, PairMax=10, TreeDepth=9),
    dict(NMax=400, TMax=10, WMax=30, PairMax=10, TreeDepth=9),
    dict(NMax=120, TMax=15, WMax=30, PairMax=10, TreeDepth=7),
    dict(NMax=120, TMax=20, WMax=30, PairMax=10, TreeDepth=7),
    dict(NMax=120, TMax=10, WMax=30, PairMax=10, TreeDepth=7),
    dict(NMax=120, TMax=10, WMax=30, PairMax=15, TreeDepth=7),
    dict(NMax=120, TMax=10, WMax=30, PairMax=20, TreeDepth=7),
]

CONST_PATTERN = re.compile(
    r'^(\s*)(NMax|TMax|WMax|PairMax|TreeDepth)(\s*=\s*)(\d+)(\s*//.*)?$',
    re.MULTILINE,
)

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
CONSTRAINTS_PATTERN = re.compile(r'Constraints:\s*(\d+)')
AUCTION_ID_PATTERN = re.compile(r'->\s+auction_id=(\d+)\b')
GNARK_TOOK = re.compile(r"\bDBG\s+([\w][\w\s]+?)\s+done\b.*?\btook=([\d.]+)")

def strip_ansi(s: str) -> str:
    return ANSI_ESCAPE.sub("", s)

def patch_constants(circuit_path: Path, params: dict) -> str:
    src = circuit_path.read_text()

    def replacer(m: re.Match) -> str:
        name = m.group(2)
        if name in params:
            comment = m.group(5) or ""
            return f"{m.group(1)}{name}{m.group(3)}{params[name]}{comment}"
        return m.group(0)

    patched = CONST_PATTERN.sub(replacer, src)

    for name, val in params.items():
        if not re.search(rf'\b{name}\s*=\s*{val}\b', patched):
            raise ValueError(f"Failed to patch '{name}' → {val} in {circuit_path}")
    return patched

def extract_constraints(stdout: str) -> Optional[int]:
    m = CONSTRAINTS_PATTERN.search(stdout)
    return int(m.group(1)) if m else None

def parse_auction_id(out: str) -> Optional[int]:
    m = AUCTION_ID_PATTERN.search(out)
    return int(m.group(1)) if m else None

def extract_gnark_timings(out: str) -> dict:
    clean = strip_ansi(out)
    timings = {}
    for m in GNARK_TOOK.finditer(clean):
        label = m.group(1).strip().lower()
        sec = float(m.group(2))
        if "constraint system solver" in label or "solver" in label:
            timings["witness_s"] = sec
        elif "prover" in label:
            timings["prove_s"] = sec
    return timings

def run_cmd(cmd: list[str], cwd: str, label: str) -> tuple[int, str]:
    print(f"  [{label}] {' '.join(cmd)}")

    p = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    out_lines = []
    try:
        for line in p.stdout:
            out_lines.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
    finally:
        rc = p.wait()

    out = "".join(out_lines)
    return rc, out

def save(results: list, path: Path):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  → saved {len(results)} records to {path}")

def load_existing(path: Path) -> tuple[list, set]:
    if not path.exists():
        return [], set()
    with open(path) as f:
        results = json.load(f)
    keys = {
        (
            r["params"]["NMax"],
            r["params"]["TMax"],
            r["params"]["WMax"],
            r["params"]["PairMax"],
            r["params"]["TreeDepth"],
            r.get("auction_start"),
            r.get("auction_end"),
            r.get("auction_index"),
        )
        for r in results
        if "params" in r
    }
    print(f"Resuming: {len(results)} existing records loaded from {path}")
    return results, keys

def print_summary(results: list):
    valid = [r for r in results if "error" not in r]
    if not valid:
        return

    header = f"{'Config':<40} {'Auction':>8} {'Constraints':>12} {'Witness':>9} {'Prove':>9}"
    print(f"\n{header}")
    print("-" * len(header))

    def fsec(x):
        if x is None:
            return "     —"
        try:
            return f"{float(x):.3f}s"
        except Exception:
            return "     —"

    for r in sorted(valid, key=lambda x: (x.get("prove", {}).get("prove_s") or 0)):
        p = r["params"]
        lbl = f"N={p['NMax']} T={p['TMax']} W={p['WMax']} P={p['PairMax']}"
        c = (r.get("setup", {}) or {}).get("constraints") or 0
        cs = f"{c/1e6:.2f}M" if c >= 1e6 else f"{c/1e3:.0f}k"
        auction_id = r.get("auction_id")
        auction_s = str(auction_id) if auction_id is not None else "—"
        witness_s = (r.get("prove", {}) or {}).get("witness_s")
        prove_s = (r.get("prove", {}) or {}).get("prove_s")

        print(
            f"  {lbl:<38} {auction_s:>8} {cs:>12}"
            f" {fsec(witness_s):>9}"
            f" {fsec(prove_s):>9}"
        )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--circuit_path", required=True)
    ap.add_argument("--setup_dir", required=True)
    ap.add_argument("--prover_dir", required=True)
    ap.add_argument("--output", default="benchmark_results.json")
    ap.add_argument("--auction_start", type=int, required=True)
    ap.add_argument("--auction_end", type=int, required=True)
    ap.add_argument("--auction_index", type=int, default=0)
    ap.add_argument("--skip_prove", action="store_true")
    ap.add_argument("--go_cmd", default="go")
    args = ap.parse_args()

    circuit_path = Path(args.circuit_path).resolve()
    if not circuit_path.exists():
        sys.exit(f"ERROR: circuit.go not found at {circuit_path}")

    setup_path = Path(args.setup_dir).resolve()
    prover_path = Path(args.prover_dir).resolve()
    comb_root = setup_path.parent.parent if setup_path.is_file() else setup_path
    prover_cwd = prover_path.parent if prover_path.is_file() else prover_path
    if not comb_root.is_dir():
        sys.exit(f"ERROR: setup_dir does not resolve to comb_gnark dir: {comb_root}")
    if not prover_cwd.is_dir():
        sys.exit(f"ERROR: prover_dir is not a directory: {prover_cwd}")

    # Paths for r1cs, pk, vk — all kept in comb_gnark root
    cs_path  = str(comb_root / "circuit.r1cs")
    pk_path  = str(comb_root / "comb_auction.g16.pk")
    vk_path  = str(comb_root / "comb_auction.g16.vk")
    proof_path = str(comb_root / "proof.json")

    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    original_src = circuit_path.read_text()
    results, existing_keys = load_existing(output_path)

    try:
        for idx, params in enumerate(PARAM_GRID):
            key = (
                params["NMax"],
                params["TMax"],
                params["WMax"],
                params["PairMax"],
                params["TreeDepth"],
                args.auction_start,
                args.auction_end,
                args.auction_index,
            )
            if key in existing_keys:
                print(f"\n[{idx+1}/{len(PARAM_GRID)}] Skip (already done): {params}")
                continue

            print(f"\n{'='*60}")
            print(f"[{idx+1}/{len(PARAM_GRID)}] Config: {params}")
            print("=" * 60)

            record = {
                "params": params,
                "auction_start": args.auction_start,
                "auction_end": args.auction_end,
                "auction_index": args.auction_index,
                "auction_id": None,
                "setup": {},
                "prove": {},
            }

            patched = patch_constants(circuit_path, params)
            circuit_path.write_text(patched)
            print("Patched circuit.go")

            rc, out = run_cmd([args.go_cmd, "run", "."], str(setup_path.parent), "setup")
            if rc != 0:
                record["error"] = out[-2000:]
                results.append(record)
                save(results, output_path)
                continue

            record["setup"]["constraints"] = extract_constraints(out)

            if args.skip_prove:
                results.append(record)
                save(results, output_path)
                continue

            prove_cmd = [
                args.go_cmd,
                "run",
                ".",
                "--auction_start", str(args.auction_start),
                "--auction_end",   str(args.auction_end),
                "--auction_index", str(args.auction_index),
                "--verify",        "true",
                "--cs",            cs_path,
                "--pk",            pk_path,
                "--vk",            vk_path,
                "--out",           proof_path,
            ]

            rc, out = run_cmd(prove_cmd, str(prover_cwd), "prove(warmup)")
            if rc != 0:
                record["error"] = out[-2000:]
                results.append(record)
                save(results, output_path)
                continue

            rc, out = run_cmd(prove_cmd, str(prover_cwd), "prove(measured)")
            if rc != 0:
                record["error"] = out[-2000:]
                results.append(record)
                save(results, output_path)
                continue

            record["auction_id"] = parse_auction_id(out)
            took = extract_gnark_timings(out)
            record["prove"]["witness_s"] = took.get("witness_s")
            record["prove"]["prove_s"] = took.get("prove_s")

            print(
                f"  Timings: witness_s={record['prove'].get('witness_s')} "
                f"prove_s={record['prove'].get('prove_s')}"
            )

            results.append(record)
            save(results, output_path)

    finally:
        circuit_path.write_text(original_src)
        print("\nRestored original circuit.go")

    print(f"\nAll done. Results in {output_path}")
    print_summary(results)

if __name__ == "__main__":
    main()