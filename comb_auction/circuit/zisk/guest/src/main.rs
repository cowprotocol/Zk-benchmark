/*
This guest logic matches the autopilot winner selection.
The potential optimisations: Replace keccak with zkVM friendly hash and reduce __udivti3 costs by division tricks.
*/

#![no_main]
ziskos::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};
use ziskos::{read_input, set_output};
use auction_caps::{MAX_SOLUTIONS, MAX_TRADES_PER_SOLUTION, MAX_WINNERS, MAX_PAIRS_PER_SOLUTION, MAX_TREE_DEPTH, MAX_BASELINE_PAIRS};

const ONE_E18: u128 = 1_000_000_000_000_000_000u128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address20(pub [u8; 20]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DirectedPair {
    pub sell: Address20,
    pub buy: Address20,
}

#[derive(Clone, Copy, Debug)]
pub enum Side {
    Sell = 0,
    Buy = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OrderUid(pub [u8; 56]);

#[derive(Clone, Debug)]
pub struct TradeIn {
    pub order_uid: OrderUid, // canonical sort key if needed
    pub sell_token: Address20,
    pub buy_token: Address20,

    // NOTE: u128 covers all realistic ERC-20 amounts but some on-chain orders
    // use u256 limit values. The gnark circuit also range-checks amounts to
    // 128 bits. We'd need a U256 type in both guest and circuit which would increase proving cost. Revisit this assumption.       
    pub limit_sell: u128,
    pub limit_buy: u128,

    pub executed_sell: u128,
    pub executed_buy: u128,

    pub side: Side,

    // native price of buy token, scaled by 1e18 (price_in_native = native_price_buy / 1e18)
    pub native_price_buy: u128,
}

#[derive(Clone, Debug)]
pub struct SolutionIn {
    pub solver: Address20,
    pub solution_id: u64,

    // Uniform Clearing Prices map (optional for winner selection, used for binding)
    pub prices: Vec<(Address20, u128)>,

    pub trades: Vec<TradeIn>,
}

#[derive(Clone, Debug)]
pub struct AuctionInput {
    pub auction_id: u64,
    pub max_winners: u32,
    pub tree_depth: u8, // Merkle depth for bidset_root tree (power-of-two leaves)
    pub solutions: Vec<SolutionIn>,
}

/// Lightweight zero-alloc cursor over a flat `&[u8]` input buffer.
/// The host serialises the entire `AuctionInput` into a single contiguous
/// byte slice (big-endian, packed); `Bytes` walks through it field-by-field,
/// parsing fixed-width integers, addresses, and UIDs without copying.
#[derive(Clone, Copy)]
struct Bytes<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Bytes<'a> {
    #[inline] fn new(b: &'a [u8]) -> Self { Self { b, i: 0 } }

    #[inline] fn take(&mut self, n: usize) -> &'a [u8] {
        let j = self.i + n;
        if j > self.b.len() { self.fail(9001); }
        let out = &self.b[self.i..j];
        self.i = j;
        out
    }

    #[inline] fn u8(&mut self) -> u8 { self.take(1)[0] }

    #[inline] fn u32_be(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().expect("4 bytes"))
    }

    #[inline] fn u64_be(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().expect("8 bytes"))
    }

    #[inline] fn u128_be(&mut self) -> u128 {
        u128::from_be_bytes(self.take(16).try_into().expect("16 bytes"))
    }

    #[inline] fn addr20(&mut self) -> Address20 {
        let s = self.take(20);
        let mut a = [0u8; 20];
        a.copy_from_slice(s);
        Address20(a)
    }

    #[inline] fn uid56(&mut self) -> [u8; 56] {
        let s = self.take(56);
        let mut a = [0u8; 56];
        a.copy_from_slice(s);
        a
    }

    #[inline(never)]
    fn fail(&self, code: u32) -> ! {
        set_output(0, code);
        loop {}
    }
}

fn decode_input(bytes: &[u8]) -> AuctionInput {
    let mut r = Bytes::new(bytes);

    let auction_id = r.u64_be();
    let max_winners = r.u32_be();
    let tree_depth = r.u8();
    let num_solutions = r.u32_be() as usize;

    if num_solutions > MAX_SOLUTIONS {
        r.fail(100);
    }
    if (max_winners as usize) > MAX_WINNERS {
        r.fail(101);
    }
    if tree_depth > MAX_TREE_DEPTH {
        r.fail(102);
    }

    let mut solutions: Vec<SolutionIn> = Vec::with_capacity(num_solutions);

    for _ in 0..num_solutions {
        let solver = r.addr20();
        let solution_id = r.u64_be();

        let num_prices = r.u32_be() as usize;
        let mut prices: Vec<(Address20, u128)> = Vec::with_capacity(num_prices);
        for _ in 0..num_prices {
            let tok = r.addr20();
            let price = r.u128_be();
            prices.push((tok, price));
        }

        let num_trades = r.u32_be() as usize;
        if num_trades > MAX_TRADES_PER_SOLUTION {
            r.fail(103);
        }

        let mut trades: Vec<TradeIn> = Vec::with_capacity(num_trades);
        for _ in 0..num_trades {
            let uid = OrderUid(r.uid56());
            let sell = r.addr20();
            let buy = r.addr20();

            let limit_sell = r.u128_be();
            let limit_buy = r.u128_be();

            let executed_sell = r.u128_be();
            let executed_buy = r.u128_be();

            let side_u = r.u8();
            let side = match side_u {
                0 => Side::Sell,
                1 => Side::Buy,
                _ => r.fail(104),
            };

            let native_price_buy = r.u128_be();

            trades.push(TradeIn {
                order_uid: uid,
                sell_token: sell,
                buy_token: buy,
                limit_sell,
                limit_buy,
                executed_sell,
                executed_buy,
                side,
                native_price_buy,
            });
        }

        if !is_sorted_by_addr(&prices) {
            r.fail(105);
        }
        if !is_sorted_by_uid(&trades) {
            r.fail(106);
        }

        solutions.push(SolutionIn {
            solver,
            solution_id,
            prices,
            trades,
        });
    }

    AuctionInput {
        auction_id,
        max_winners,
        tree_depth,
        solutions,
    }
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn keccak256_stream<F: FnOnce(&mut Keccak)>(f: F) -> [u8; 32] {
    let mut k = Keccak::v256();
    f(&mut k);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[inline]
fn is_sorted_by_addr(prices: &[(Address20, u128)]) -> bool {
    prices.windows(2).all(|w| w[0].0 .0 <= w[1].0 .0)
}

#[inline]
fn is_sorted_by_uid(trades: &[TradeIn]) -> bool {
    trades.windows(2).all(|w| w[0].order_uid.0 <= w[1].order_uid.0)
}

fn u128_be(x: u128) -> [u8; 16] {
    x.to_be_bytes()
}

// Leaf commit binding solution payload (for bidset_root):
// leaf = H("SOL"|solver|solution_id|prices_hash|trades_hash)
fn solution_leaf_commit(sol: &SolutionIn) -> [u8; 32] {
    // single Keccak over the full canonical encoding.

    // TODO: refactor to hash the raw input bytes directly instead of
    // re-serializing deserialized fields. Track (start, end) byte offsets
    // per solution during decode_input and feed the original slice into
    // keccak. Avoids ~177 bytes/trade of redundant copying.
    const PRICE_ITEM_LEN: usize = 36;
    const TRADE_ITEM_LEN: usize = 177;

    keccak256_stream(|k| {
        k.update(b"SOL");
        k.update(&sol.solver.0);
        k.update(&sol.solution_id.to_be_bytes());

        let n_prices: u32 = sol.prices.len() as u32;
        k.update(&n_prices.to_be_bytes());

        for (tok, price) in &sol.prices {
            let mut buf = [0u8; PRICE_ITEM_LEN];
            // token address (20)
            buf[0..20].copy_from_slice(&tok.0);
            // price u128 BE (16)
            buf[20..36].copy_from_slice(&price.to_be_bytes());
            k.update(&buf);
        }

        let n_trades: u32 = sol.trades.len() as u32;
        k.update(&n_trades.to_be_bytes());

        for t in &sol.trades {
            let mut buf = [0u8; TRADE_ITEM_LEN];
            let mut o = 0usize;

            // uid (56)
            buf[o..o + 56].copy_from_slice(&t.order_uid.0);
            o += 56;

            // sell token (20)
            buf[o..o + 20].copy_from_slice(&t.sell_token.0);
            o += 20;

            // buy token (20)
            buf[o..o + 20].copy_from_slice(&t.buy_token.0);
            o += 20;

            // limit_sell (16)
            buf[o..o + 16].copy_from_slice(&t.limit_sell.to_be_bytes());
            o += 16;

            // limit_buy (16)
            buf[o..o + 16].copy_from_slice(&t.limit_buy.to_be_bytes());
            o += 16;

            // executed_sell (16)
            buf[o..o + 16].copy_from_slice(&t.executed_sell.to_be_bytes());
            o += 16;

            // executed_buy (16)
            buf[o..o + 16].copy_from_slice(&t.executed_buy.to_be_bytes());
            o += 16;

            // side (1)
            buf[o] = t.side as u8;
            o += 1;

            // native_price_buy (16)
            buf[o..o + 16].copy_from_slice(&t.native_price_buy.to_be_bytes());
            o += 16;

            debug_assert!(o == TRADE_ITEM_LEN);
            k.update(&buf);
        }
    })
}

fn merkle_root(leaves: Vec<[u8; 32]>, depth: usize) -> [u8; 32] {
    // leaves.len() must be exactly 2^depth
    assert_eq!(leaves.len(), 1 << depth, "leaves.len() must be exactly 2^depth");
    let mut cur = leaves;
    let mut next: Vec<[u8; 32]> = Vec::with_capacity(cur.len() / 2);

    for _ in 0..depth {
        next.clear();
        for i in (0..cur.len()).step_by(2) {
            let h = keccak256(&[cur[i].as_slice(), cur[i + 1].as_slice()]);
            next.push(h);
        }
        core::mem::swap(&mut cur, &mut next);
    }

    cur[0]
}

// Winner leaf = H("WIN"|solution_leaf_commit|score_u128_be)
fn winner_leaf(sol_commit: [u8; 32], score: u128) -> [u8; 32] {
    keccak256(&[b"WIN", sol_commit.as_slice(), u128_be(score).as_slice()])
}

fn ceil_div(a: u128, b: u128) -> u128 {
    // assumes b>0
    // TODO: saturating_mul silently caps at u128::MAX on overflow, producing
    // incorrect scores. Need 256-bit intermediate arithmetic (widening multiply
    // + long division) to handle cases where a * mul > u128::MAX — e.g. large
    // token amounts multiplied by native_price_buy. The gnark circuit handles
    // this correctly via field arithmetic.
    if a == 0 {
        return 0;
    }
    (a - 1) / b + 1
}

fn floor_mul_div(a: u128, mul: u128, div: u128) -> u128 {
    // floor(a*mul/div), assumes div>0 and fits u128 under chosen bounds
    a.saturating_mul(mul) / div
}

fn ceil_mul_div(a: u128, mul: u128, div: u128) -> u128 {
    // ceil(a*mul/div), assumes div>0
    ceil_div(a.saturating_mul(mul), div)
}


fn trade_score(t: &TradeIn) -> u128 {
    match t.side {
        Side::Sell => {
            // partial_limit_buy = ceil(limit_buy * executed_sell / limit_sell)
            // surplus_buy = executed_buy - partial_limit_buy
            // score_native = floor(surplus_buy * native_price_buy / 1e18)
            if t.limit_sell == 0 {
                return 0;
            }
            let partial_limit_buy = ceil_mul_div(t.limit_buy, t.executed_sell, t.limit_sell);
            if t.executed_buy <= partial_limit_buy {
                return 0;
            }
            let surplus_buy = t.executed_buy - partial_limit_buy;
            floor_mul_div(surplus_buy, t.native_price_buy, ONE_E18)
        }
        Side::Buy => {
            // partial_limit_sell = floor(limit_sell * executed_buy / limit_buy)
            // surplus_sell = partial_limit_sell - executed_sell
            // convert surplus_sell to buy token units via order limit ratio: floor(surplus_sell * limit_buy / limit_sell)
            // score_native = floor(surplus_buy_equiv * native_price_buy / 1e18)
            if t.limit_buy == 0 || t.limit_sell == 0 {
                return 0;
            }
            let partial_limit_sell = floor_mul_div(t.limit_sell, t.executed_buy, t.limit_buy);
            if partial_limit_sell <= t.executed_sell {
                return 0;
            }
            let surplus_sell = partial_limit_sell - t.executed_sell;
            let surplus_buy_equiv = floor_mul_div(surplus_sell, t.limit_buy, t.limit_sell);
            floor_mul_div(surplus_buy_equiv, t.native_price_buy, ONE_E18)
        }
    }
}

#[derive(Clone, Debug)]
struct ScoredSolution {
    total_score: u128,
    // per directed pair aggregated score
    pairs_scores: Vec<(DirectedPair, u128)>,
    // cached commit
    sol_commit: [u8; 32],
}
#[inline]
fn find_pair_idx(pairs: &[(DirectedPair, u128)], key: DirectedPair) -> Option<usize> {
    pairs.iter().position(|(p, _)| *p == key)
}

fn score_solution(sol: &SolutionIn, sol_commit: [u8; 32]) -> ScoredSolution {
    let mut pairs_scores: Vec<(DirectedPair, u128)> = Vec::with_capacity(sol.trades.len().min(MAX_PAIRS_PER_SOLUTION));
    let mut total = 0u128;

    for t in &sol.trades {
        let sc = trade_score(t);
        total = total.saturating_add(sc);

        let pair = DirectedPair { sell: t.sell_token, buy: t.buy_token };

        if let Some(i) = find_pair_idx(&pairs_scores, pair) {
            pairs_scores[i].1 = pairs_scores[i].1.saturating_add(sc);
        } else {
            if pairs_scores.len() >= MAX_PAIRS_PER_SOLUTION {
                panic!("too many directed pairs in one solution");
            }
            pairs_scores.push((pair, sc));
        }
    }

    ScoredSolution {
        total_score: total,
        pairs_scores,
        sol_commit,
    }
}

#[derive(Clone, Copy)]
struct BaselineEntry {
    pair: DirectedPair,
    best_score: u128,
}

#[inline]
fn baseline_get(b: &[BaselineEntry], pair: DirectedPair) -> u128 {
    b.iter()
        .find(|e| e.pair == pair)
        .map(|e| e.best_score)
        .unwrap_or(0)
}

#[inline]
fn baseline_update(b: &mut Vec<BaselineEntry>, pair: DirectedPair, score: u128) {
    for e in b.iter_mut() {
        if e.pair == pair {
            if score > e.best_score {
                e.best_score = score;
            }
            return;
        }
    }
    b.push(BaselineEntry { pair, best_score: score });
}


fn baseline_filter(mut solutions: Vec<ScoredSolution>) -> Vec<ScoredSolution> {
    let mut baseline: Vec<BaselineEntry> = Vec::with_capacity(MAX_BASELINE_PAIRS);

    for s in &solutions {
        if s.pairs_scores.len() == 1 {
            let (pair, score) = s.pairs_scores[0];
            baseline_update(&mut baseline, pair, score);
        }
    }
    solutions.retain(|s| {
        if s.pairs_scores.len() == 1 {
            return true;
        }
        for (pair, sc) in &s.pairs_scores {
            if *sc < baseline_get(&baseline, *pair) {
                return false;
            }
        }
        true
    });

    solutions
}

#[inline]
fn used_contains(used: &[(Address20, Address20)], p: (Address20, Address20)) -> bool {
    used.iter().any(|u| *u == p)
}

fn pick_winners_greedy(sorted: &[ScoredSolution], max_winners: usize) -> Vec<usize> {
    let mut winners: Vec<usize> = Vec::with_capacity(max_winners.min(MAX_WINNERS));
    let mut used_pairs: Vec<(Address20, Address20)> =
        Vec::with_capacity(MAX_WINNERS * MAX_PAIRS_PER_SOLUTION);

    for (idx, s) in sorted.iter().enumerate() {
        if winners.len() >= max_winners { break; }
        if s.pairs_scores.is_empty() { continue; }

        let mut ok = true;
        for (pair, _) in &s.pairs_scores {
            let k = (pair.sell, pair.buy);
            if used_contains(&used_pairs, k) { ok = false; break; }
        }
        if !ok { continue; }

        for (pair, _) in &s.pairs_scores {
            used_pairs.push((pair.sell, pair.buy));
        }
        winners.push(idx);
    }
    winners
}

fn set_output_u32_be_chunks(start_slot: usize, bytes32: [u8; 32]) {
    for i in 0..8 {
        let j = i * 4;
        let w = u32::from_be_bytes([bytes32[j], bytes32[j + 1], bytes32[j + 2], bytes32[j + 3]]);
        set_output(start_slot + i, w);
    }
}


fn main() {
    let input_bytes = read_input();
    let inp: AuctionInput = decode_input(&input_bytes);

    if inp.solutions.len() > MAX_SOLUTIONS { panic!("too many solutions"); }
    if (inp.max_winners as usize) > MAX_WINNERS { panic!("max_winners too large"); }
    if inp.tree_depth > MAX_TREE_DEPTH { panic!("tree_depth too large"); }
    for sol in &inp.solutions {
        if sol.trades.len() > MAX_TRADES_PER_SOLUTION { panic!("too many trades"); }
    }

     // canonical leaf order: sort by solution_commit bytes ascending (so roots don't depend on input order)
    let mut all_commits: Vec<[u8; 32]> = Vec::with_capacity(inp.solutions.len());

    // score all solutions
    let mut scored: Vec<ScoredSolution> = Vec::with_capacity(inp.solutions.len());
     for sol in &inp.solutions {
        let commit = solution_leaf_commit(sol);
        all_commits.push(commit);
        scored.push(score_solution(sol, commit));
    }

    // baseline filter 
    scored = baseline_filter(scored);

    // sort by total score desc (stable tie-breaker by commit bytes)
    scored.sort_by(|a, b| {
        b.total_score
            .cmp(&a.total_score)
            .then_with(|| b.sol_commit.cmp(&a.sol_commit))
    });

    // greedy pick winners with disjoint directed pairs across solutions
    let winner_idxs = pick_winners_greedy(&scored, inp.max_winners as usize);

    // compute bidset_root from all solution commits in this snapshot, using fixed depth
    let depth = inp.tree_depth as usize;
    let leaf_count = 1usize << depth;

    all_commits.sort();

    // pad/truncate to exactly 2^depth leaves
    all_commits.sort();
    all_commits.resize(leaf_count, [0u8; 32]);
    let bidset_root = merkle_root(all_commits, depth);

    // winners_root over winner leave
    let mut w_leaves: Vec<[u8; 32]> = Vec::with_capacity(winner_idxs.len());
    for &i in &winner_idxs {
        let w = &scored[i];
        w_leaves.push(winner_leaf(w.sol_commit, w.total_score));
    }

    let winners_root = if w_leaves.is_empty() {
        [0u8; 32] // no winners => null root
    } else {
        let pow2n = w_leaves.len().next_power_of_two();
        w_leaves.resize(pow2n, [0u8; 32]);
        let winners_depth = pow2n.trailing_zeros() as usize;
        merkle_root(w_leaves, winners_depth)
    };

    // publish outputs
    set_output(0, winner_idxs.len() as u32);
    set_output_u32_be_chunks(1, winners_root);
    set_output_u32_be_chunks(9, bidset_root);
}