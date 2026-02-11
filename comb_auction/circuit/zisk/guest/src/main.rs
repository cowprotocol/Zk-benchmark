#![no_main]
ziskos::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};
use serde::{Deserialize, Serialize};
use ziskos::{read_input, set_output};
use serde_big_array::BigArray;

const ONE_E18: u128 = 1_000_000_000_000_000_000u128;
const MAX_SOLUTIONS: usize = 200;
const MAX_TRADES_PER_SOLUTION: usize = 100;
const MAX_WINNERS: usize = 100;
const MAX_PAIRS_PER_SOLUTION: usize = 10;
const MAX_TREE_DEPTH: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address20(pub [u8; 20]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DirectedPair {
    pub sell: Address20,
    pub buy: Address20,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Side {
    Sell = 0,
    Buy = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrderUid(#[serde(with = "BigArray")] pub [u8; 56]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeIn {
    pub order_uid: OrderUid, // canonical sort key if needed
    pub sell_token: Address20,
    pub buy_token: Address20,

    pub limit_sell: u128,
    pub limit_buy: u128,

    pub executed_sell: u128,
    pub executed_buy: u128,

    pub side: Side,

    // native price of buy token, scaled by 1e18 (price_in_native = native_price_buy / 1e18)
    pub native_price_buy: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolutionIn {
    pub solver: Address20,
    pub solution_id: u64,

    // Uniform Clearing Prices map (optional for winner selection, used for binding)
    pub prices: Vec<(Address20, u128)>,

    pub trades: Vec<TradeIn>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionInput {
    pub auction_id: u64,
    pub max_winners: usize,
    pub tree_depth: u8, // Merkle depth for bidset_root tree (power-of-two leaves)
    pub solutions: Vec<SolutionIn>,
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

fn u64_be(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

fn u128_be(x: u128) -> [u8; 16] {
    x.to_be_bytes()
}

fn prices_hash(prices: &[(Address20, u128)]) -> [u8; 32] {
    let mut v = prices.to_vec();
    v.sort_by(|(a1, _), (a2, _)| a1.0.cmp(&a2.0));

    let mut buf = Vec::with_capacity(v.len() * (20 + 16));
    for (tok, price) in v {
        buf.extend_from_slice(&tok.0);
        buf.extend_from_slice(&u128_be(price));
    }
    keccak256(&[buf.as_slice()])
}

fn trades_hash(trades: &[TradeIn]) -> [u8; 32] {
    let mut v = trades.to_vec();
   v.sort_by(|t1, t2| t1.order_uid.0.cmp(&t2.order_uid.0));

    let mut buf = Vec::new();
    for t in v {
        buf.extend_from_slice(&t.order_uid.0);
        buf.extend_from_slice(&t.sell_token.0);
        buf.extend_from_slice(&t.buy_token.0);
        buf.extend_from_slice(&u128_be(t.limit_sell));
        buf.extend_from_slice(&u128_be(t.limit_buy));
        buf.extend_from_slice(&u128_be(t.executed_sell));
        buf.extend_from_slice(&u128_be(t.executed_buy));
        buf.push(t.side as u8);
        buf.extend_from_slice(&u128_be(t.native_price_buy));
    }
    keccak256(&[buf.as_slice()])
}

// Leaf commit binding solution payload (for bidset_root):
// leaf = H("SOL"|solver|solution_id|prices_hash|trades_hash)
fn solution_leaf_commit(sol: &SolutionIn) -> [u8; 32] {
    let tag = b"SOL";
    let solver = sol.solver.0;
    let sid = u64_be(sol.solution_id);
    let ph = prices_hash(&sol.prices);
    let th = trades_hash(&sol.trades);

    keccak256(&[
        tag,
        solver.as_slice(),
        sid.as_slice(),
        ph.as_slice(),
        th.as_slice(),
    ])
}

fn merkle_root(leaves: Vec<[u8; 32]>, depth: usize) -> [u8; 32] {
    // leaves.len() must be exactly 2^depth
    let mut cur = leaves;
    let mut next: Vec<[u8; 32]> = Vec::with_capacity(cur.len() / 2);

    for _ in 0..depth {
        next.clear();
        for i in (0..cur.len()).step_by(2) {
            let h = keccak256(&[cur[i].as_slice(), cur[i + 1].as_slice()]);
            next.push(h);
        }
        std::mem::swap(&mut cur, &mut next);
    }

    cur[0]
}

// Winner leaf = H("WIN"|solution_leaf_commit|score_u128_be)
fn winner_leaf(sol_commit: [u8; 32], score: u128) -> [u8; 32] {
    keccak256(&[b"WIN", sol_commit.as_slice(), u128_be(score).as_slice()])
}

fn ceil_div(a: u128, b: u128) -> u128 {
    // assumes b>0
    if a == 0 {
        return 0;
    }
    (a - 1) / b + 1
}

fn floor_mul_div(a: u128, mul: u128, div: u128) -> u128 {
    // floor(a*mul/div), assumes div>0 and fits u128 under your chosen bounds
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
    for (i, (p, _)) in pairs.iter().enumerate() {
        if *p == key {
            return Some(i);
        }
    }
    None
}

fn score_solution(sol: &SolutionIn) -> ScoredSolution {
   let mut pairs_scores: Vec<(DirectedPair, u128)> = Vec::with_capacity(8.min(MAX_PAIRS_PER_SOLUTION));
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
        sol_commit: solution_leaf_commit(sol),
    }
}

#[derive(Clone, Copy)]
struct BaselineEntry {
    pair: DirectedPair,
    best_score: u128,
}

#[inline]
fn baseline_get(b: &[BaselineEntry], pair: DirectedPair) -> u128 {
    for e in b {
        if e.pair == pair {
            return e.best_score;
        }
    }
    0
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
    let mut baseline: Vec<BaselineEntry> = Vec::with_capacity(64);

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
    for u in used {
        if *u == p {
            return true;
        }
    }
    false
}

fn pick_winners_greedy(sorted: &[ScoredSolution], max_winners: usize) -> Vec<ScoredSolution> {
    let mut winners: Vec<ScoredSolution> = Vec::with_capacity(max_winners.min(MAX_WINNERS));
    let mut used_pairs: Vec<(Address20, Address20)> =
        Vec::with_capacity(MAX_WINNERS * MAX_PAIRS_PER_SOLUTION); 

    for s in sorted {
        if winners.len() >= max_winners {
            break;
        }
        if s.pairs_scores.is_empty() {
            continue;
        }

        // check disjointness
        let mut ok = true;
        for (pair, _) in &s.pairs_scores {
            let k = (pair.sell, pair.buy);
            if used_contains(&used_pairs, k) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        // accept: mark pairs used
        for (pair, _) in &s.pairs_scores {
            used_pairs.push((pair.sell, pair.buy));
        }
        winners.push(s.clone());
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
    let inp: AuctionInput = bincode::deserialize(&input_bytes).expect("bad input encoding");

    if inp.solutions.len() > MAX_SOLUTIONS { panic!("too many solutions"); }
    if inp.max_winners > MAX_WINNERS { panic!("max_winners too large"); }
    if inp.tree_depth > MAX_TREE_DEPTH { panic!("tree_depth too large"); }
     for sol in &inp.solutions {
        if sol.trades.len() > MAX_TRADES_PER_SOLUTION { panic!("too many trades"); }
    }

    // score all solutions
    let mut scored: Vec<ScoredSolution> = Vec::with_capacity(inp.solutions.len());
    for sol in &inp.solutions {
        scored.push(score_solution(sol));
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
    let winners = pick_winners_greedy(&scored, inp.max_winners);

    // compute bidset_root from all solution commits in this snapshot, using fixed depth
    let depth = inp.tree_depth as usize;
    let leaf_count = 1usize << depth;

    // canonical leaf order: sort by solution_commit bytes ascending (so roots don't depend on input order)
    let mut all_commits: Vec<[u8; 32]> = Vec::with_capacity(inp.solutions.len());
    for sol in &inp.solutions {
        all_commits.push(solution_leaf_commit(sol));
    }

    all_commits.sort();

    // pad/truncate to exactly 2^depth leaves
    let mut leaves = Vec::with_capacity(leaf_count);
    for i in 0..leaf_count {
        if i < all_commits.len() {
            leaves.push(all_commits[i]);
        } else {
            leaves.push([0u8; 32]);
        }
    }
    let bidset_root = merkle_root(leaves, depth);

    // winners_root over winner leave
    let mut w_leaves: Vec<[u8; 32]> = Vec::with_capacity(winners.len().max(1));
    for w in &winners {
        w_leaves.push(winner_leaf(w.sol_commit, w.total_score));
    }

    let mut pow2n = 1usize;
    while pow2n < w_leaves.len().max(1) {
        pow2n <<= 1;
    }
    while w_leaves.len() < pow2n {
        w_leaves.push([0u8; 32]);
    }
    let winners_depth = pow2n.trailing_zeros() as usize;
    let winners_root = merkle_root(w_leaves, winners_depth);

    // publish outputs
    set_output(0, winners.len() as u32);
    set_output_u32_be_chunks(1, winners_root);
    set_output_u32_be_chunks(9, bidset_root);
}