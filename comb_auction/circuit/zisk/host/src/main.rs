use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::fs::File;
use std::io::Write;

const ONE_E18: u128 = 1_000_000_000_000_000_000;
const NUM_SOLUTIONS: usize = 100;
const TRADES_PER_SOLUTION: usize = 100;
const NUM_TOKENS: usize = 40;
const NUM_SOLVERS: usize = 30;

const MAX_WINNERS: u32 = 60;
const TREE_DEPTH: u8 = 7;
const SEED: u64 = 12345;

const MIN_AMOUNT: u128 = 1_000_000;
const MAX_AMOUNT: u128 = 1_000_000_000_000_000;
const MIN_PRICE: u128 = ONE_E18 / 10000;
const MAX_PRICE: u128 = ONE_E18 * 10000;

const MIN_FRAC_BPS: u128 = 5000;  // 50%
const MAX_FRAC_BPS: u128 = 10000; 

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

#[inline]
fn push_u8(out: &mut Vec<u8>, x: u8) {
    out.push(x);
}

#[inline]
fn push_u32_be(out: &mut Vec<u8>, x: u32) {
    out.extend_from_slice(&x.to_be_bytes());
}

#[inline]
fn push_u64_be(out: &mut Vec<u8>, x: u64) {
    out.extend_from_slice(&x.to_be_bytes());
}

#[inline]
fn push_u128_be(out: &mut Vec<u8>, x: u128) {
    out.extend_from_slice(&x.to_be_bytes());
}

#[inline]
fn push_addr20(out: &mut Vec<u8>, a: Address20) {
    out.extend_from_slice(&a.0);
}

#[inline]
fn push_uid56(out: &mut Vec<u8>, uid: OrderUid) {
    out.extend_from_slice(&uid.0);
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

fn generate_auction() -> AuctionInput {
    let mut rng = StdRng::seed_from_u64(SEED);

    let tokens: Vec<Address20> = (0..NUM_TOKENS).map(|_| random_address(&mut rng)).collect();
    let solvers: Vec<Address20> = (0..NUM_SOLVERS).map(|_| random_address(&mut rng)).collect();

    let mut order_counter: u64 = 0;
    let mut solutions = Vec::with_capacity(NUM_SOLUTIONS);

    for solution_id in 0..NUM_SOLUTIONS as u64 {
        let solver = solvers[rng.gen_range(0..NUM_SOLVERS)];

        // Pick a token pair for this solution
        let sell_idx = rng.gen_range(0..NUM_TOKENS);
        let mut buy_idx = rng.gen_range(0..NUM_TOKENS);
        while buy_idx == sell_idx {
            buy_idx = rng.gen_range(0..NUM_TOKENS);
        }
        let sell_token = tokens[sell_idx];
        let buy_token = tokens[buy_idx];
        // Generate trades
        let mut trades = Vec::with_capacity(TRADES_PER_SOLUTION);
        for _ in 0..TRADES_PER_SOLUTION {
            order_counter += 1;

            // uid[0..8] = counter, rest random
            let mut uid = [0u8; 56];
            uid[0..8].copy_from_slice(&order_counter.to_be_bytes());
            rng.fill(&mut uid[8..]);

            let side = if rng.gen_bool(0.5) { Side::Sell } else { Side::Buy };
            let limit_sell = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);
            let limit_buy = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);

            // Generate execution with positive surplus
            let surplus_bps: u128 = rng.gen_range(10u128..=500u128);
            let frac_bps: u128 = rng.gen_range(MIN_FRAC_BPS..=MAX_FRAC_BPS);

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

            trades.push(TradeIn {
                order_uid: OrderUid(uid),
                sell_token,
                buy_token,
                limit_sell,
                limit_buy,
                executed_sell,
                executed_buy,
                side,
                native_price_buy: rng.gen_range(MIN_PRICE..=MAX_PRICE),
            });
        }

        trades.sort_by(|a, b| a.order_uid.0.cmp(&b.order_uid.0));

        // Prices (guest expects sorted by token)
        let mut prices = vec![
            (sell_token, rng.gen_range(MIN_PRICE..=MAX_PRICE)),
            (buy_token, rng.gen_range(MIN_PRICE..=MAX_PRICE)),
        ];
        prices.sort_by(|(t1, _), (t2, _)| t1.0.cmp(&t2.0));

        solutions.push(SolutionIn {
            solver,
            solution_id,
            prices,
            trades,
        });
    }

    AuctionInput {
        auction_id: rng.gen(),
        max_winners: MAX_WINNERS,
        tree_depth: TREE_DEPTH,
        solutions,
    }
}

fn main() {
    let auction = generate_auction();
    let encoded = encode_packed(&auction);

    std::fs::create_dir_all("../guest/build").expect("failed to create ../guest/build");

    let mut file = File::create("../guest/build/input.bin").expect("failed to create input.bin");
    file.write_all(&encoded).expect("failed to write input.bin");

    println!(
        "Generated input.bin: {} bytes ({:.2} MB)",
        encoded.len(),
        encoded.len() as f64 / 1_000_000.0
    );
    println!(
        "Solutions: {}, Trades/solution: {}, Total trades: {}",
        auction.solutions.len(),
        auction.solutions[0].trades.len(),
        auction.solutions.len() * auction.solutions[0].trades.len()
    );
}
