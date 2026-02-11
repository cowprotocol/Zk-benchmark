use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fs::File;
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address20(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Side {
    Sell = 0,
    Buy = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrderUid(#[serde(with = "BigArray")] pub [u8; 56]);

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolutionIn {
    pub solver: Address20,
    pub solution_id: u64,
    pub prices: Vec<(Address20, u128)>,
    pub trades: Vec<TradeIn>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuctionInput {
    pub auction_id: u64,
    pub max_winners: usize,
    pub tree_depth: u8,
    pub solutions: Vec<SolutionIn>,
}

const NUM_SOLUTIONS: usize = 200;
const TRADES_PER_SOLUTION: usize = 100;
const NUM_TOKENS: usize = 20;
const NUM_SOLVERS: usize = 15;
const MAX_WINNERS: usize = 100;
const TREE_DEPTH: u8 = 8;
const SEED: u64 = 12345;

const ONE_E18: u128 = 1_000_000_000_000_000_000;
const MIN_AMOUNT: u128 = 1_000_000;
const MAX_AMOUNT: u128 = 1_000_000_000_000_000;
const MIN_PRICE: u128 = ONE_E18 / 10000;
const MAX_PRICE: u128 = ONE_E18 * 10000;


fn random_address(rng: &mut StdRng) -> Address20 {
    let mut addr = [0u8; 20];
    rng.fill(&mut addr);
    Address20(addr)
}

fn generate_auction() -> AuctionInput {
    let mut rng = StdRng::seed_from_u64(SEED);
    
    let tokens: Vec<Address20> = (0..NUM_TOKENS).map(|_| random_address(&mut rng)).collect();
    let solvers: Vec<Address20> = (0..NUM_SOLVERS).map(|_| random_address(&mut rng)).collect();
    
    let mut order_counter: u64 = 0;
    let mut solutions = Vec::with_capacity(NUM_SOLUTIONS);
    
    for solution_id in 0..NUM_SOLUTIONS as u64 {
        let solver = solvers[rng.gen_range(0..NUM_SOLVERS)];
        
        // Pick a token pair
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
            let mut uid = [0u8; 56];
            uid[0..8].copy_from_slice(&order_counter.to_be_bytes());
            rng.fill(&mut uid[8..]);
            
            let side = if rng.gen_bool(0.5) { Side::Sell } else { Side::Buy };
            let limit_sell = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);
            let limit_buy = rng.gen_range(MIN_AMOUNT..=MAX_AMOUNT);
            
            // Generate execution with positive surplus
            let surplus_bps = rng.gen_range(10u32..=500);
            let (executed_sell, executed_buy) = match side {
                Side::Sell => {
                    let executed_sell = (limit_sell as f64 * rng.gen_range(0.5..=1.0)) as u128;
                    let proportional = limit_buy.saturating_mul(executed_sell) / limit_sell.max(1);
                    let executed_buy = (proportional as f64 * (1.0 + surplus_bps as f64 / 10000.0)) as u128;
                    (executed_sell.max(1), executed_buy.max(1))
                }
                Side::Buy => {
                    let executed_buy = (limit_buy as f64 * rng.gen_range(0.5..=1.0)) as u128;
                    let proportional = limit_sell.saturating_mul(executed_buy) / limit_buy.max(1);
                    let executed_sell = (proportional as f64 * (1.0 - surplus_bps as f64 / 10000.0)) as u128;
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
        
        // Prices for tokens
        let prices = vec![
            (sell_token, rng.gen_range(MIN_PRICE..=MAX_PRICE)),
            (buy_token, rng.gen_range(MIN_PRICE..=MAX_PRICE)),
        ];
        
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
    let encoded = bincode::serialize(&auction).expect("serialization failed");
    
    std::fs::create_dir_all("../guest/build").expect("failed to create build dir");
    
    let mut file = File::create("../guest/build/input.bin").expect("failed to create file");
    file.write_all(&encoded).expect("failed to write");
    
    println!("Generated input.bin: {} bytes ({:.2} MB)", 
        encoded.len(), 
        encoded.len() as f64 / 1_000_000.0
    );
    println!("Solutions: {}, Trades/solution: {}, Total trades: {}", 
        NUM_SOLUTIONS, 
        TRADES_PER_SOLUTION, 
        NUM_SOLUTIONS * TRADES_PER_SOLUTION
    );
}