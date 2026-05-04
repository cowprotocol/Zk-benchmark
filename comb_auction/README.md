Implements zk circuits winner selection for the combinatorial auction in two proving systems: Gnark and Zisk.

Both implementations take the same auction data as input, run identical scoring/selection logic, and produce equivalent public outputs, differing only in how the computation is expressed (static R1CS constraints vs. dynamic program execution).
For context on the motivation and broader architecture, see this [document](https://www.notion.so/cownation/Zk-circuit-for-combinatorial-auctions-winner-selection-2e68da5f04ca8048aa4ef1b830aebe70?source=copy_link)

## What's in this PR

### Mental model

The scoring and selection logic implemented here is a one-to-one match of the autopilot's winner selection, with one intentional omission: fees policies logic is not yet included in the surplus computation.
Fee policies logic is a bounded arithmetic adjustment per trade and can be layered in without materially changing circuit size.
In the autopilot, you run this pipeline and trust the output. In a zk circuit, the prover claims the output and the circuit verifies the claim is consistent with the input. The key shift is:
The prover supplies pre-computed intermediate values as private witness, and the circuit checks that they're correct, rather than computing everything from scratch.
For example, the prover pre-computes `pair_score[k]` (the aggregated score per directed pair bucket) outside the circuit and provides it as witness. The circuit then verifies that these per-pair scores are consistent with the individual trade scores it computed, using a polynomial identity check. This is cheaper than having the circuit do dynamic bucketing itself.
Similarly, the prover provides the solutions already sorted by score descending. The circuit doesn't sort, it just checks that the ordering invariant holds on the provided sequence.

But there's one thing the circuit does that the autopilot doesn't need to: it verifies the dataset itself.
The autopilot trusts its own input, it reads from the orderbook and operates on whatever it sees. The circuit can't do that. The entire auction dataset (solutions, trades, prices) enters as private witness, meaning the on-chain verifier never sees it. Without an anchor, the prover could supply any dataset and produce a valid proof for it, excluding competitor solutions, altering trade amounts, or fabricating data entirely.
This is what `bidset_root` solves. It's a Merkle root over per-solution leaf commitments, where each leaf binds (solver, solution_id, trades, prices). Inside the circuit, every solution in the private witness is hashed into a leaf, the leaves are assembled into a Merkle tree, and the computed root is constrained equal to the public bidset_root.
Any change to the witness, a missing solution, a modified trade, a different price, produces a different root and the proof fails.

### 1. Gnark Circuit (`comb_auction/circuit/comb_gnark/`)

**`circuit.go`**: The circuit implementation. The circuit enforces the full auction pipeline in a single proof:

- **Bidset root binding**: Each active solution is committed to a MiMC leaf: `H(DOMAIN_LEAF || solver || solution_id || trades_len || trades_commit)`. The `trades_commit` is a polynomial accumulator `Σ field_k · r^k` over all trade fields (using a Fiat-Shamir challenge `r` derived from `auction_id`), which avoids hashing every field individually while still binding all trade data. Leaves are padded to `2^TreeDepth` and the recomputed Merkle root is constrained equal to the public `bidset_root`.

- **Score computation**: Per-trade surplus is computed in-circuit using hint-based `divFloor`/`divCeil` (circuit enforces `a = b·q + r`, `r < b` via range checks). Sell-side and buy-side formulas match the autopilot logic exactly. Trade scores are summed per solution.

- **Pair aggregation binding**: Per-solution, a random challenge `alpha = H(auction_id || DOMAIN_ALPHA || solver || solution_id)` is used to enforce a Schwartz-Zippel identity: `Σ(score_t · α^{pair_idx_t}) == Σ(pair_score[k] · α^k)`. This binds the prover-supplied per-pair score witness values `(pair_score[k])` to the trade-level scores actually computed in-circuit for that solution, ensuring the per-pair scores used downstream in baseline filtering and winner selection are consistent with the actual trade surplus

- **Baseline filter**: Single-pair solutions define baseline scores per directed pair. Multi-pair solutions must beat every relevant baseline on each of their pair buckets. This is enforced via a linear scan with conditional `hintIsLessStrict` comparisons (hint + range-check pattern, avoiding expensive bit decompositions).

- **Survivor packing and ordering**: Surviving solutions are prefix-sum packed into a dense `packed[0..alive_len-1]` array. Canonical ordering is enforced: descending by score, with ties broken by descending leaf commit hash.

- **Greedy winner selection**: Winners are greedily picked in order, skipping any solution whose directed pair keys conflict with already-selected winners. Conflict detection uses an accumulated `IsZero` sum across all `WMax × PairMax × PairMax` potential collisions, collapsed to a single boolean via one final `IsZero`, exploiting the fact that addition is free.

- **Comparison strategy**: All comparisons use `cmp.BoundedComparator` with appropriate bit-width bounds, and a custom `hintIsLessStrict` that avoids the standard gnark comparator's internal bit decomposition. The hint provides the comparison result, the circuit verifies it by range-checking the difference (`b - a - 1` if lt=1, `a - b` if lt=0). This significantly reduces constraint count compared to native comparisons.

**`prover/`**: Off-chain witness builder and Groth16 prover.

- Fetches real auction data via `data/fetch.py` (queries the orderbook DB)
- Computes native MiMC hashes, derives all Fiat-Shamir challenges, runs scoring/filtering/selection in Go, and maps the results into the circuit assignment
- Exports Solidity-compatible proof JSON
- **GPU acceleration**: build tag `icicle` enables ICICLE-based GPU proving via `backend.WithIcicleAcceleration()`

**`setup/`**: Compiles the circuit, runs Groth16 trusted setup, and exports:

- `circuit.r1cs`, proving key, verification key
- Auto-generated `Verifier.sol` from gnark's Solidity exporter

**`contract/`**: On-chain verification (Foundry):

- `CombAuctionVerifier.sol`: Two-phase flow: `postRoot()` stores autopilot-attested `bidset_root`, then `submitWinnersProof()` verifies a Groth16 proof against it and stores winners. The `isWinner[auctionId][solver]` mapping gates settlement.
- `Verifier.sol`: Auto-generated Groth16 verifier (exported by setup)

### 2. Zisk Circuit (`comb_auction/circuit/zisk/`)

**`guest/src/main.rs`** : The zkVM guest program. Implements identical auction logic as a standard Rust program running inside Zisk. Unlike gnark where correctness is enforced by static R1CS constraints, here the prover attests that this exact program was executed faithfully over the provided input, so the logic is written as straightforward Rust and the proof system handles soundness.

- **Input deserialization** : A custom zero-copy `Bytes` reader parses the host-provided input as a packed big-endian binary stream. No serde: the reader exposes `u8`, `u32_be`, `u64_be`, `u128_be`, `addr20` (20-byte), and `uid56` (56-byte) methods directly on a byte slice cursor. This avoids trait dispatch and format-handling code that inflates the execution trace. Bounds are validated during parsing: `num_solutions ≤ MAX_SOLUTIONS`, `max_winners ≤ MAX_WINNERS`, `tree_depth ≤ MAX_TREE_DEPTH`, `num_trades ≤ MAX_TRADES_PER_SOLUTION`.

- **Bidset root binding**: Each solution is committed via a single streaming Keccak256 over its canonical encoding: `H("SOL" || solver || solution_id || n_prices || [price_items...] || n_trades || [trade_items...])`. Prices are encoded as 36-byte items `(token_address[20] || price_u128_be[16])`, trades as 177-byte items `(uid[56] || sell_token[20] || buy_token[20] || limit_sell[16] || limit_buy[16] || exec_sell[16] || exec_buy[16] || side[1] || native_price_buy[16])`. Canonical ordering is enforced: prices must be sorted by address, trades by order UID. The guest panics if either invariant is violated. All solution commits are collected, sorted and padded to `2^tree_depth` leaves (zero-padded), and hashed into a Keccak256 Merkle tree. The resulting `bidset_root` is published as output.

- **Score computation**: Per-trade surplus is computed. The scoring formulas match the autopilot exactly:
  - Sell-side: `partial_limit_buy = ceil(limit_buy * executed_sell / limit_sell)`, then `surplus_buy = executed_buy - partial_limit_buy`, then `score = floor(surplus_buy * native_price_buy / 1e18)` (zero if no surplus).
  - Buy-side: `partial_limit_sell = floor(limit_sell * executed_buy / limit_buy)`, then `surplus_sell = partial_limit_sell - executed_sell`, converted to buy-token units via `floor(surplus_sell * limit_buy / limit_sell)`, then `score = floor(surplus_buy_equiv * native_price_buy / 1e18)`.

  Note: the `u128` divisions here compile to `__udivti3` calls in the Zisk execution trace, which are one of the more expensive operations.

- **Pair aggregation**: Trade scores are bucketed by `DirectedPair { sell, buy }` using a linear scan over a `Vec<(DirectedPair, u128)>` per solution (capped at `MAX_PAIRS_PER_SOLUTION`). Scores for trades sharing the same directed pair are accumulated via `saturating_add`.

- **Baseline filter**: First pass: single-pair solutions (`pairs_scores.len() == 1`) populate a baseline map `Vec<BaselineEntry>` tracking the best score per directed pair (linear scan with max-update). Second pass: `solutions.retain()` keeps all single-pair solutions unconditionally, and keeps multi-pair solutions only if every one of their pair scores `≥ baseline_get(pair)`. Solutions failing any pair are dropped entirely.

- **Ordering**: Surviving solutions are sorted in-place: descending by `total_score`, with ties broken by descending `sol_commit` bytes (comparison on the 32-byte Keccak commit). This produces a canonical ordering independent of input order.

- **Greedy winner selection**: Iterates the sorted survivors in order. For each candidate: checks if any of its directed pairs `(sell, buy)` conflict with already-selected winners by linear scan over a `used_pairs: Vec<(Address20, Address20)>`. If no conflict and winner capacity remains, the solution is selected and its pairs are appended to `used_pairs`. Early-exits once `max_winners` is reached.

- **Output encoding** — Three values are published via `set_output`:
  - Slot 0: `winner_count` (u32)
  - Slots 1–8: `winners_root`: a Keccak256 Merkle root over winner leaves, where each winner leaf is `H("WIN" || sol_commit || score_u128_be)`. The winner tree is padded to the next power-of-two.
  - Slots 9–16: `bidset_root`: the Merkle root over all solution commits.

**`host/`**: Fetches real auction data from the orderbook API (via `fetch.py`), encodes it into the guest's packed binary format, and invokes the Zisk prover.

**`host-synthetic/`**: Generates synthetic auctions with configurable parameters (`num_solutions`, `trades_per_solution`, `pairs_per_solution`, `num_tokens`, `num_solvers`, seed) for controlled benchmarking. 35% of generated solutions are single-pair (matching observed production distribution). Trade parameters (amounts, execution fractions, native prices) are randomised within realistic bounds (`MIN_AMOUNT=1e6` to `MAX_AMOUNT=1e15`, execution between 50–100% of limits).

### 3. Data Tooling (`comb_auction/data/`)

- **`fetch.py`**: Queries the orderbook DB for auction data within a given `auction_start` and `auction_end` range. Outputs JSON matching the prover input format.
- **`analyse_auctions.py`**: Analyses fetched auction data to determine production parameter distributions: solutions per auction, trades per solution, directed pairs per solution. Generates heatmaps and complexity plots used to justify the choice of `NMax`, `TMax`, `PairMax`.

### 4. Benchmarking (`comb_auction/benchmark/`)

- **`bench_gnark.py`**: Sweeps across a parameter grid (`NMax ∈ {120, 200, 300, 400}`, `TMax ∈ {10, 15, 20}`, `PairMax ∈ {10, 15, 20}`). For each config: patches circuit constants → recompiles → runs setup → proves a real auction → captures constraint count + timing breakdown.
- **`bench_zisk.py`**: Benchmarks the Zisk implementation across both real auction data and synthetic worst-case inputs. Captures step count, proving time, and emulator stats.
- **`plot_gnark_bench.py` / `plot_zisk_bench.py`**: Generates visualisation plots (NMax sweep, TMax sweep, PairMax sweep, timing breakdowns, summary bars).

### Benchmarks

Benchmark results can be found in `comb_auction/benchmark/gnark-plots`, `comb_auction/benchmark/gnark-gpu-plots`, `comb_auction/benchmark/zisk-plots`.

## How to Run

### Pre-requisites

- **Zisk**: To run the zisk guest and host code, you need to have zisk installed in your machine, the installation guide can be found [here](https://ziskdocs.vercel.app/getting-started/installation)
- **Gnark**: To run the Gnark circuit, you need to have Golang installed in your machine.
- **GPU acceleration**: To use ICICLE-based GPU proving for gnark, you need an NVIDIA GPU with CUDA installed and the ICICLE library set up. The dependency (`icicle-gnark/v3 v3.2.2`) is already in `go.mod`, build with `-tags icicle` to activate it. Without the build tag, the prover falls back to CPU-only Groth16.
- **Benchmarking**: Requires Python ≥3.13 with [uv](https://docs.astral.sh/uv/) for dependency management.

### Gnark

```bash
# Compile circuit + trusted setup + export Verifier.sol
cd comb_auction/circuit/comb_gnark/setup && go run .

# Prove a real auction (fetches data if needed)
cd comb_auction/circuit/comb_gnark/prover
go run . --auction_start 12310225 --auction_end 12311225 --auction_index 13

# GPU-accelerated proving (requires ICICLE)
go run -tags icicle . --auction_start 12310225 --auction_end 12311225 --auction_index 13
```

### Zisk

```bash
# build ELF from guest
cd comb_auction/circuit/zisk/guest && cargo-zisk build --release
# build input bin
cd comb_auction/circuit/zisk/host && cargo run -- --auction-start 12310225 --auction-end 12311225 --auction-index 13
# execution metrics
cd comb_auction/circuit/zisk/guest && ziskemu -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -i build/input.bin -m -x
# program setup
cd comb_auction/circuit/zisk/guest && cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -k $HOME/.zisk/provingKey
# generate proof
cd comb_auction/circuit/zisk/guest && cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -i build/input.bin -w $HOME/.zisk/bin/libzisk_witness.$LIB_EXT -k $HOME/.zisk/provingKey -o proof

# Synthetic benchmarks
# instead of second step in previous commands, run this, all other steps remains the same
cd comb_auction/circuit/zisk/host-synthetic
cargo run --release -- \
  --nmax 120 \
  --tmax 10 \
  --wmax 30 \
  --pairmax 10 \
  --treedepth 7
```

### Benchmarks

```bash
cd comb_auction/benchmark
  uv run bench_gnark.py \
    --circuit_path  "../circuit/comb_gnark/circuit.go" \
    --setup_dir     "../circuit/comb_gnark/setup/main.go" \
    --prover_dir    "../circuit/comb_gnark/prover/main.go" \
    --output        benchmark_results.json \
    --auction_start $((12311225 - 1000)) \
    --auction_end   12311225 \
    --auction_index 13
uv run bench_zisk.py \
  --auction-start 12310225 \
  --auction-end 12311225 \
  --data-dir ../data/ \
  --host-dir ../circuit/zisk/host \
  --guest-dir ../circuit/zisk/guest
uv run plot_gnark_bench.py
uv run plot_zisk_bench.py
```
