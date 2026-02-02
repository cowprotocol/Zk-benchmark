#![no_main]
ziskos::entrypoint!(main);

use ziskos::{read_input, set_output};
use tiny_keccak::{Hasher, Keccak};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
struct Trade {
    id: [u8; 32],
    sell: [u8; 20],
    buy: [u8; 20],
    score: u128,
}

#[derive(Clone, Serialize, Deserialize)]
struct Solution {
    id: [u8; 32],
    solver: [u8; 20],
    score: u128,
    trades: Vec<Trade>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Winner {
    id: [u8; 32],
    solver: [u8; 20],
    score: u128,
}

#[derive(Clone, Serialize, Deserialize)]
struct Input {
    auction_id: u64,
    solutions: Vec<Solution>,          // already split, already scored
    provided_winners: Vec<Winner>,     // expected winners (host computes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pair([u8; 20], [u8; 20]);

fn aggregate_scores(sol: &Solution) -> Vec<(Pair, u128)> {
    let mut out: Vec<(Pair, u128)> = Vec::new();
    for t in &sol.trades {
        let key = Pair(t.sell, t.buy);
        let mut found = false;
        for (k, v) in out.iter_mut() {
            if *k == key {
                *v += t.score;
                found = true;
                break;
            }
        }
        if !found {
            out.push((key, t.score));
        }
    }
    out
}

fn compute_baselines(solutions: &[Solution]) -> Vec<(Pair, u128)> {
    let mut baselines: Vec<(Pair, u128)> = Vec::new();
    for sol in solutions {
        let agg = aggregate_scores(sol);
        if agg.len() != 1 { continue; }
        let (pair, score) = agg[0];

        let mut found = false;
        for (p, best) in baselines.iter_mut() {
            if *p == pair {
                if score > *best { *best = score; } // strict >
                found = true;
                break;
            }
        }
        if !found {
            baselines.push((pair, score));
        }
    }
    baselines
}

fn lookup_baseline(baselines: &[(Pair, u128)], pair: Pair) -> u128 {
    for (p, s) in baselines {
        if *p == pair { return *s; }
    }
    0
}

fn baseline_filter(solutions: &[Solution]) -> Vec<bool> {
    let baselines = compute_baselines(solutions);
    let mut kept = vec![false; solutions.len()];

    for (i, sol) in solutions.iter().enumerate() {
        let agg = aggregate_scores(sol);
        if agg.len() == 1 {
            kept[i] = true;
            continue;
        }
        let mut ok = true;
        for (pair, score) in agg {
            if score < lookup_baseline(&baselines, pair) {
                ok = false;
                break;
            }
        }
        kept[i] = ok;
    }
    kept
}

fn directed_pairs_unique(sol: &Solution) -> Vec<Pair> {
    let mut pairs: Vec<Pair> = Vec::new();
    for t in &sol.trades {
        let p = Pair(t.sell, t.buy);
        if !pairs.contains(&p) {
            pairs.push(p);
        }
    }
    pairs
}

// stable descending sort 
fn select_winners(solutions: &[Solution], kept: &[bool]) -> Vec<Winner> {
    let mut idx: Vec<usize> = (0..solutions.len()).collect();
    idx.sort_by(|&a, &b| {
        let sa = solutions[a].score;
        let sb = solutions[b].score;
        if sa != sb { sb.cmp(&sa) } else { a.cmp(&b) }
    });

    let mut used: Vec<Pair> = Vec::new();
    let mut winners: Vec<Winner> = Vec::new();

    for i in idx {
        if !kept[i] { continue; }
        let pairs = directed_pairs_unique(&solutions[i]);

        let mut conflict = false;
        'outer: for p in &pairs {
            for u in &used {
                if p == u { conflict = true; break 'outer; }
            }
        }

        if !conflict {
            winners.push(Winner {
                id: solutions[i].id,
                solver: solutions[i].solver,
                score: solutions[i].score,
            });
            for p in pairs { used.push(p); }
        }
    }

    winners
}

// commitment to winners (order-sensitive)
fn winners_root(winners: &[Winner]) -> [u8; 32] {
    let mut h = Keccak::v256();;
    for w in winners {
        h.update(w.id);
        h.update(w.solver);
        // score as big-endian 16 bytes (u128)
        h.update(w.score.to_be_bytes());
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn main() {
    let input_bytes = read_input();
    let inp: Input = bincode::deserialize(&input_bytes).expect("decode Input");

    let kept = baseline_filter(&inp.solutions);
    let computed = select_winners(&inp.solutions, &kept);

    // equality check vs provided winners 
    if computed.len() != inp.provided_winners.len() {
        panic!("winner length mismatch");
    }
    for (a, b) in computed.iter().zip(inp.provided_winners.iter()) {
        if a.id != b.id || a.solver != b.solver || a.score != b.score {
            panic!("winner mismatch");
        }
    }

    // publish auction_id (u64 -> 2 u32)
    set_output(0, (inp.auction_id >> 32) as u32);
    set_output(1, (inp.auction_id & 0xffffffff) as u32);

    // publish winners_root (8 u32)
    let root = winners_root(&computed);
    for i in 0..8 {
        let c = u32::from_be_bytes([root[i*4], root[i*4+1], root[i*4+2], root[i*4+3]]);
        set_output(2 + i, c);
    }

    // publish winner_count
    set_output(10, computed.len() as u32);
}
