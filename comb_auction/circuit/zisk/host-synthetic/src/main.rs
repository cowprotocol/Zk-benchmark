use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::{collections::{HashMap, HashSet}, fs::File, io::Write, path::PathBuf};

const ONE_E18: u128 = 1_000_000_000_000_000_000u128;

const DEFAULT_NUM_TOKENS: usize = 40;
const DEFAULT_NUM_SOLVERS: usize = 30;
const DEFAULT_SEED: u64 = 12345;

const SINGLE_PAIR_FRACTION: f64 = 0.35;

const MIN_AMOUNT: u128 = 1_000_000;
const MAX_AMOUNT: u128 = 1_000_000_000_000_000;
const MIN_PRICE: u128 = ONE_E18 / 10000;
const MAX_PRICE: u128 = ONE_E18 * 10000;

const MIN_FRAC_BPS: u128 = 5000;  // 50%
const MAX_FRAC_BPS: u128 = 10000; // 100%

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address20(pub [u8; 20]);

#[derive(Clone, Copy, Debug)]
pub enum Side {
    Sell = 0,
    Buy = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OrderUid(pub [u8; 56]);

#[derive(Clone, Debug)]
pub struct TradeIn {
    pub order_uid: OrderUid,
    pub sell_token: Address20,
    pub buy_token: Address20,

    pub limit_sell: u128,
    pub limit_buy: u128,

    pub executed_sell: u128,
    pub executed_buy: u128,

    pub side: Side,
    pub native_price_buy: u128,
}

#[derive(Clone, Debug)]
pub struct SolutionIn {
    pub solver: Address20,
    pub solution_id: u64,

    pub prices: Vec<(Address20, u128)>,
    pub trades: Vec<TradeIn>,
}

#[derive(Clone, Debug)]
pub struct AuctionInput {
    pub auction_id: u64,
    pub max_winners: u32,
    pub tree_depth: u8,
    pub solutions: Vec<SolutionIn>,
}

fn random_address(rng: &mut StdRng) -> Address20 {
    let mut addr = [0u8; 20];
    rng.fill(&mut addr);
    Address20(addr)
}


fn encode_packed(inp: &AuctionInput) -> Vec<u8> {
    let mut out = Vec::with_capacity(1_000_000);

    push_u64_be(&mut out, inp.auction_id);
    push_u32_be(&mut out, inp.max_winners);
    push_u8(&mut out, inp.tree_depth);
    push_u32_be(&mut out, inp.solutions.len() as u32);

    for sol in &inp.solutions {
        push_addr20(&mut out, sol.solver);
        push_u64_be(&mut out, sol.solution_id);

        push_u32_be(&mut out, sol.prices.len() as u32);
        for (tok, price) in &sol.prices {
            push_addr20(&mut out, *tok);
            push_u128_be(&mut out, *price);
        }

        push_u32_be(&mut out, sol.trades.len() as u32);
        for t in &sol.trades {
            push_uid56(&mut out, t.order_uid);
            push_addr20(&mut out, t.sell_token);
            push_addr20(&mut out, t.buy_token);

            push_u128_be(&mut out, t.limit_sell);
            push_u128_be(&mut out, t.limit_buy);

            push_u128_be(&mut out, t.executed_sell);
            push_u128_be(&mut out, t.executed_buy);

            push_u8(&mut out, t.side as u8);
            push_u128_be(&mut out, t.native_price_buy);
        }
    }

    out
}

#[derive(Clone, Debug)]
struct Args {
    nmax: usize,
    tmax: usize,
    wmax: u32,
    pairmax: usize,
    treedepth: u8,
    seed: u64,
    tokens: usize,
    solvers: usize,
    single_pair_frac: Option<f64>,
    out: PathBuf,
}

fn parse_args() -> Args {
    let mut nmax: Option<usize> = None;
    let mut tmax: Option<usize> = None;
    let mut wmax: Option<u32> = None;
    let mut pairmax: Option<usize> = None;
    let mut treedepth: Option<u8> = None;
    let mut seed: u64 = DEFAULT_SEED;
    let mut tokens: usize = DEFAULT_NUM_TOKENS;
    let mut solvers: usize = DEFAULT_NUM_SOLVERS;
    let mut single_pair_frac: Option<f64> = None;
    let mut out: PathBuf = PathBuf::from("../guest/build/input.bin");

    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let v = it.next().unwrap_or_else(|| {
            eprintln!("missing value for arg: {k}");
            std::process::exit(2);
        });
        match k.as_str() {
            "--nmax"            => nmax = Some(v.parse().expect("bad --nmax")),
            "--tmax"            => tmax = Some(v.parse().expect("bad --tmax")),
            "--wmax"            => wmax = Some(v.parse().expect("bad --wmax")),
            "--pairmax"         => pairmax = Some(v.parse().expect("bad --pairmax")),
            "--treedepth"       => treedepth = Some(v.parse().expect("bad --treedepth")),
            "--seed"            => seed = v.parse().expect("bad --seed"),
            "--tokens"          => tokens = v.parse().expect("bad --tokens"),
            "--solvers"         => solvers = v.parse().expect("bad --solvers"),
            "--single-pair-frac"=> single_pair_frac = Some(v.parse().expect("bad --single-pair-frac")),
            "--out"             => out = PathBuf::from(v),
            _ => {
                eprintln!("unknown arg: {k}");
                eprintln!("usage: cargo run --release -- \
                    --nmax N --tmax T --wmax W --pairmax P --treedepth D \
                    [--seed S] [--tokens K] [--solvers M] \
                    [--single-pair-frac F] [--out PATH]");
                std::process::exit(2);
            }
        }
    }

    Args {
        nmax: nmax.expect("missing --nmax"),
        tmax: tmax.expect("missing --tmax"),
        wmax: wmax.expect("missing --wmax"),
        pairmax: pairmax.expect("missing --pairmax"),
        treedepth: treedepth.expect("missing --treedepth"),
        seed,
        tokens,
        solvers,
        single_pair_frac,
        out,
    }
}

fn generate_unique_pairs(
    rng: &mut StdRng,
    tokens: &[Address20],
    count: usize,
) -> Vec<(Address20, Address20)> {
    let mut seen = HashSet::<(Address20, Address20)>::new();
    let mut pairs = Vec::with_capacity(count);

    let max_possible = tokens.len().saturating_mul(tokens.len().saturating_sub(1));
    let target = count.min(max_possible);

    while pairs.len() < target {
        let sell = tokens[rng.gen_range(0..tokens.len())];
        let mut buy = tokens[rng.gen_range(0..tokens.len())];
        while buy == sell {
            buy = tokens[rng.gen_range(0..tokens.len())];
        }
        if seen.insert((sell, buy)) {
            pairs.push((sell, buy));
        }
    }
    pairs
}

fn generate_trade(
    rng: &mut StdRng,
    order_counter: u64,
    sell_token: Address20,
    buy_token: Address20,
) -> TradeIn {
    let mut uid = [0u8; 56];
    uid[0..8].copy_from_slice(&order_counter.to_be_bytes());
    rng.fill(&mut uid[8..]);

    let side = if rng.gen_bool(0.5) { Side::Sell } else { Side::Buy };
    let limit_sell = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);
    let limit_buy  = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);

    let surplus_bps: u128 = rng.gen_range(10u128..=500u128);
    let frac_bps: u128    = rng.gen_range(MIN_FRAC_BPS..=MAX_FRAC_BPS);

    let (executed_sell, executed_buy) = match side {
        Side::Sell => {
            let executed_sell = limit_sell.saturating_mul(frac_bps) / 10_000;
            let proportional = limit_buy
                .saturating_mul(executed_sell)
                / limit_sell.max(1);
            let executed_buy = proportional
                .saturating_mul(10_000 + surplus_bps)
                / 10_000;
            (executed_sell.max(1), executed_buy.max(1))
        }
        Side::Buy => {
            let executed_buy = limit_buy.saturating_mul(frac_bps) / 10_000;
            let proportional = limit_sell
                .saturating_mul(executed_buy)
                / limit_buy.max(1);
            let executed_sell = proportional
                .saturating_mul(10_000 - surplus_bps)
                / 10_000;
            (executed_sell.max(1), executed_buy.max(1))
        }
    };

    TradeIn {
        order_uid: OrderUid(uid),
        sell_token,
        buy_token,
        limit_sell,
        limit_buy,
        executed_sell,
        executed_buy,
        side,
        native_price_buy: rng.gen_range(MIN_PRICE..=MAX_PRICE),
    }
}

fn build_prices(
    rng: &mut StdRng,
    pairs: &[(Address20, Address20)],
) -> Vec<(Address20, u128)> {
    let mut token_set: HashSet<Address20> = HashSet::new();
    for (s, b) in pairs {
        token_set.insert(*s);
        token_set.insert(*b);
    }
    let mut prices: Vec<(Address20, u128)> = token_set
        .into_iter()
        .map(|tok| (tok, rng.gen_range(MIN_PRICE..=MAX_PRICE)))
        .collect();
    prices.sort_by(|(t1, _), (t2, _)| t1.0.cmp(&t2.0));
    prices
}

fn generate_auction(args: &Args) -> AuctionInput {
    let mut rng = StdRng::seed_from_u64(args.seed);

    let tokens: Vec<Address20> = (0..args.tokens).map(|_| random_address(&mut rng)).collect();
    let solvers: Vec<Address20> = (0..args.solvers).map(|_| random_address(&mut rng)).collect();

    let spf = args.single_pair_frac.unwrap_or(SINGLE_PAIR_FRACTION);
    let single_pair_count = ((args.nmax as f64) * spf).round() as usize;
    let multi_pair_count  = args.nmax - single_pair_count;

    let mut order_counter: u64 = 0;
    let mut solutions = Vec::with_capacity(args.nmax);

    for solution_id in 0..single_pair_count as u64 {
        let solver = solvers[rng.gen_range(0..solvers.len())];

        // Exactly one pair per solution.
        let pairs = generate_unique_pairs(&mut rng, &tokens, 1);
        let (sell_token, buy_token) = pairs[0];

        let mut trades = Vec::with_capacity(args.tmax);
        for _ in 0..args.tmax {
            order_counter += 1;
            trades.push(generate_trade(&mut rng, order_counter, sell_token, buy_token));
        }
        trades.sort_by(|a, b| a.order_uid.0.cmp(&b.order_uid.0));

        let prices = build_prices(&mut rng, &pairs);

        solutions.push(SolutionIn {
            solver,
            solution_id,
            prices,
            trades,
        });
    }

    for i in 0..multi_pair_count as u64 {
        let solution_id = single_pair_count as u64 + i;
        let solver = solvers[rng.gen_range(0..solvers.len())];

        let pairs = generate_unique_pairs(&mut rng, &tokens, args.pairmax);
        let pairs_len = pairs.len().max(1);

        let mut trades = Vec::with_capacity(args.tmax);
        for ti in 0..args.tmax {
            order_counter += 1;
            let (sell_token, buy_token) = pairs[ti % pairs_len];
            trades.push(generate_trade(&mut rng, order_counter, sell_token, buy_token));
        }
        trades.sort_by(|a, b| a.order_uid.0.cmp(&b.order_uid.0));

        let prices = build_prices(&mut rng, &pairs);

        solutions.push(SolutionIn {
            solver,
            solution_id,
            prices,
            trades,
        });
    }

    AuctionInput {
        auction_id: rng.gen(),
        max_winners: args.wmax,
        tree_depth: args.treedepth,
        solutions,
    }
}

fn main() {
    let args = parse_args();

    let auction = generate_auction(&args);
    let encoded = encode_packed(&auction);

    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent).expect("failed to create output dir");
    }

    let mut file = File::create(&args.out).expect("failed to create input.bin");
    file.write_all(&encoded).expect("failed to write input.bin");

    let spf = args.single_pair_frac.unwrap_or(SINGLE_PAIR_FRACTION);
    let single_count = ((args.nmax as f64) * spf).round() as usize;
    let multi_count  = args.nmax - single_count;

    let mut max_pairs: usize = 0;
    let mut filtered_estimate: usize = 0;
    for sol in &auction.solutions {
        let mut set = HashSet::<(Address20, Address20)>::new();
        for t in &sol.trades {
            set.insert((t.sell_token, t.buy_token));
        }
        let np = set.len();
        max_pairs = max_pairs.max(np);
        if np > 1 {
            filtered_estimate += 1;
        }
    }

    println!(
        "Generated: {} bytes ({:.2} MB) -> {}",
        encoded.len(),
        encoded.len() as f64 / 1_000_000.0,
        args.out.display()
    );
    println!(
        "Params: NMax={}, TMax={}, WMax={}, PairMax={}, TreeDepth={}, seed={}",
        args.nmax, args.tmax, args.wmax, args.pairmax, args.treedepth, args.seed
    );
    println!(
        "Solutions: {} total  ({} single-pair specialists [{:.0}%], {} multi-pair [{:.0}%])",
        auction.solutions.len(),
        single_count,
        spf * 100.0,
        multi_count,
        (1.0 - spf) * 100.0,
    );
    println!(
        "Trades/solution: {}, Total trades: {}, max_pairs_per_solution: {}",
        args.tmax,
        auction.solutions.len() * args.tmax,
        max_pairs,
    );
    println!(
        "baseline_filter: {} multi-pair solutions will be evaluated against per-pair baselines",
        filtered_estimate,
    );
}
