use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{PathBuf},
    process::{Command, Stdio},
};
use clap::Parser;
use serde::Deserialize;
use auction_caps::*;
/*
Usage:
1. Just for building the input.bin for ziskemu execution: cd host && cargo run -- \
  --auction-start 12310225 \
  --auction-end 12311225 \
  --auction-index 13 \
2. Execute using ziskemu: cd guest && ziskemu -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -i build/input.bin 
3. Performance metrics: cd guest && ziskemu -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -i build/input.bin -X -S -D
4. Verify constraints: cd guest && LIB_EXT=$([[ "$(uname)" == "Darwin" ]] && echo "dylib" || echo "so")
cargo-zisk verify-constraints -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -i build/input.bin -w $HOME/.zisk/bin/libzisk_witness.$LIB_EXT -k $HOME/.zisk/provingKey
5. Program setup: cd guest && cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zisk_comb_auction -k $HOME/.zisk/provingKey
6. Generate proof: cd guest && LIB_EXT=$([[ "$(uname)" == "Darwin" ]] && echo "dylib" || echo "so")
cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/yourzisk_comb_auction_program -i build/input.bin -w $HOME/.zisk/bin/libzisk_witness.$LIB_EXT -k $HOME/.zisk/provingKey -o proof

This is needed only for the first time and only iff the guest code is changed. You can just call the 1 & 6 step directly if the guest code remains same and you have executed all these commands before.
Commands 2,3 & 4 are just for metrics and statistics and can be skipped, although command 4 is recommened to be called to check if guest and host code are compatible.
*/

#[derive(Parser, Debug)]
#[command(name = "auction-host")]
struct Cli {
    #[arg(long)]
    auction_start: u64,
    #[arg(long)]
    auction_end: u64,
    #[arg(long)]
    auction_index: usize,
    #[arg(long, default_value = "../../../data/fetch.py")]
    fetch_script: PathBuf,

    #[arg(long, default_value = "../../../data/")]
    data_dir: PathBuf,

    #[arg(long, default_value = "../guest/build")]
    build_dir: PathBuf,
}

#[derive(Deserialize, Debug)]
struct FetchOutput {
    auctions: Vec<AuctionJson>,
}

#[derive(Deserialize, Debug, Clone)]
struct AuctionJson {
    auction_id: u64,
    solutions: Vec<SolutionJson>,
}

#[derive(Deserialize, Debug, Clone)]
struct SolutionJson {
    solution_uid: u64,
    solver: String, 
    trades: Vec<TradeJson>,
}

#[derive(Deserialize, Debug, Clone)]
struct TradeJson {
    order_uid: String,          
    sell_token: String,          
    buy_token: String,          
    limit_sell: String,   
    limit_buy: String,    
    exec_sell: String,    
    exec_buy: String,     
    side: u8,                
    buy_token_price_e18: String
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Address20([u8; 20]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct OrderUid([u8; 56]);

#[derive(Clone, Debug)]
struct TradeIn {
    order_uid: OrderUid,
    sell_token: Address20,
    buy_token: Address20,
    limit_sell: u128,
    limit_buy: u128,
    executed_sell: u128,
    executed_buy: u128,
    side: u8, // 0/1
    native_price_buy: u128,
}

#[derive(Clone, Debug)]
struct SolutionIn {
    solver: Address20,
    solution_id: u64,
    prices: Vec<(Address20, u128)>, // sorted by token
    trades: Vec<TradeIn>,           // sorted by order_uid
}

#[derive(Clone, Debug)]
struct AuctionInput {
    auction_id: u64,
    max_winners: u32,
    tree_depth: u8,
    solutions: Vec<SolutionIn>,
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(format!("hex has odd length: {s}"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("invalid hex byte at {i}: {e} ({s})"))?;
        out.push(b);
    }
    Ok(out)
}

fn parse_addr(s: &str) -> Result<Address20, String> {
    let b = parse_hex_bytes(s)?;
    if b.len() != 20 {
        return Err(format!("expected 20-byte address, got {} bytes: {s}", b.len()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Ok(Address20(a))
}

fn parse_uid(s: &str) -> Result<OrderUid, String> {
    let b = parse_hex_bytes(s)?;
    if b.len() != 56 {
        return Err(format!("expected 56-byte uid, got {} bytes: {s}", b.len()));
    }
    let mut a = [0u8; 56];
    a.copy_from_slice(&b);
    Ok(OrderUid(a))
}

fn parse_u128_dec(s: &str) -> Result<u128, String> {
    s.parse::<u128>().map_err(|e| format!("invalid u128 decimal '{s}': {e}"))
}


fn build_auction_input(aj: &AuctionJson) -> Result<AuctionInput, String> {
    let mut solutions: Vec<SolutionIn> = Vec::with_capacity(aj.solutions.len());

    for sj in &aj.solutions {
        let solver = parse_addr(&sj.solver)?;

        let mut trades: Vec<TradeIn> = Vec::with_capacity(sj.trades.len());
        for tj in &sj.trades {
            if tj.side != 0 && tj.side != 1 {
                return Err(format!("invalid side {} for order_uid {}", tj.side, tj.order_uid));
            }
            trades.push(TradeIn {
                order_uid: parse_uid(&tj.order_uid)?,
                sell_token: parse_addr(&tj.sell_token)?,
                buy_token: parse_addr(&tj.buy_token)?,
                limit_sell: parse_u128_dec(&tj.limit_sell)?,
                limit_buy: parse_u128_dec(&tj.limit_buy)?,
                executed_sell: parse_u128_dec(&tj.exec_sell)?,
                executed_buy: parse_u128_dec(&tj.exec_buy)?,
                side: tj.side,
                native_price_buy: parse_u128_dec(&tj.buy_token_price_e18)?,
            });
        }

        // guest requires trades sorted by uid ascending
        trades.sort_by(|a, b| a.order_uid.0.cmp(&b.order_uid.0));

        // prices: dedupe buy-token prices we know, sorted by token address, since sell_token is not used for winner selection and only for canonical root
        let mut price_map: HashMap<[u8; 20], u128> = HashMap::new();
        for t in &trades {
            price_map.entry(t.buy_token.0).or_insert(t.native_price_buy);
        }
        let mut prices: Vec<(Address20, u128)> = price_map
            .into_iter()
            .map(|(addr, p)| (Address20(addr), p))
            .collect();
        prices.sort_by(|(a, _), (b, _)| a.0.cmp(&b.0));

        solutions.push(SolutionIn {
            solver,
            solution_id: sj.solution_uid,
            prices,
            trades,
        });
    }

    Ok(AuctionInput {
        auction_id: aj.auction_id,
        max_winners: MAX_WINNERS as u32,
        tree_depth: MAX_TREE_DEPTH,
        solutions,
    })
}


fn encode_packed(inp: &AuctionInput) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(4_000_000);

    macro_rules! push_u8   { ($v:expr) => { out.push($v as u8) } }
    macro_rules! push_u32  { ($v:expr) => { out.extend_from_slice(&($v as u32).to_be_bytes()) } }
    macro_rules! push_u64  { ($v:expr) => { out.extend_from_slice(&($v as u64).to_be_bytes()) } }
    macro_rules! push_u128 { ($v:expr) => { out.extend_from_slice(&($v as u128).to_be_bytes()) } }
    macro_rules! push_addr { ($a:expr) => { out.extend_from_slice(&($a).0) } }
    macro_rules! push_uid  { ($u:expr) => { out.extend_from_slice(&($u).0) } }

    push_u64!(inp.auction_id);
    push_u32!(inp.max_winners);
    push_u8!(inp.tree_depth);
    push_u32!(inp.solutions.len() as u32);

    for sol in &inp.solutions {
        push_addr!(sol.solver);
        push_u64!(sol.solution_id);

        push_u32!(sol.prices.len() as u32);
        for (tok, price) in &sol.prices {
            push_addr!(*tok);
            push_u128!(*price);
        }

        push_u32!(sol.trades.len() as u32);
        for t in &sol.trades {
            push_uid!(t.order_uid);
            push_addr!(t.sell_token);
            push_addr!(t.buy_token);

            push_u128!(t.limit_sell);
            push_u128!(t.limit_buy);

            push_u128!(t.executed_sell);
            push_u128!(t.executed_buy);

            push_u8!(t.side);

            push_u128!(t.native_price_buy);
        }
    }

    out
}

fn ensure_fetch_json(cli: &Cli) -> PathBuf {
    let json_path = cli.data_dir.join(format!(
        "auctions_{}_{}.json",
        cli.auction_start, cli.auction_end
    ));

    if json_path.exists() {
        println!("[host] Using cached {}", json_path.display());
        return json_path;
    }

    println!("[host] JSON not found — running fetch script …");

    let status = Command::new("python3")
        .arg(&cli.fetch_script)
        .arg("--auction_start")
        .arg(cli.auction_start.to_string())
        .arg("--auction_end")
        .arg(cli.auction_end.to_string())
        .arg("--auction_index")
        .arg(cli.auction_index.to_string())
        .current_dir(&cli.data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|e| panic!("failed to launch fetch script: {e}"));

    if !status.success() {
        panic!(
            "fetch script exited with status {status}. \
             Make sure PROD_DB_URL is set and the script path is correct."
        );
    }

    if !json_path.exists() {
        panic!("fetch script succeeded but {} was not created", json_path.display());
    }

    json_path
}

fn main() {
    let cli = Cli::parse();

    let json_path = ensure_fetch_json(&cli);

    let json_text = fs::read_to_string(&json_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", json_path.display()));

    let fetch_output: FetchOutput =
        serde_json::from_str(&json_text).unwrap_or_else(|e| panic!("JSON parse error: {e}"));

    let auctions = &fetch_output.auctions;
    if auctions.is_empty() {
        panic!("No auctions exported");
    }
    if cli.auction_index >= auctions.len() {
        panic!(
            "auction_index {} out of bounds (0..{})",
            cli.auction_index,
            auctions.len() - 1
        );
    }

    let auction_json = &auctions[cli.auction_index];
    println!(
        "[host] Selected auction_id={} (index {} of {}), solutions={}",
        auction_json.auction_id,
        cli.auction_index,
        auctions.len(),
        auction_json.solutions.len()
    );

    if auction_json.solutions.len() > MAX_SOLUTIONS {
        panic!(
            "solutions={} exceeds MAX_SOLUTIONS={}",
            auction_json.solutions.len(),
            MAX_SOLUTIONS
        );
    }
    for (i, sol) in auction_json.solutions.iter().enumerate() {
        if sol.trades.len() > MAX_TRADES_PER_SOLUTION {
            panic!(
                "solution[{i}] trades={} exceeds MAX_TRADES_PER_SOLUTION={}",
                sol.trades.len(),
                MAX_TRADES_PER_SOLUTION
            );
        }
    }

    let auction_input = build_auction_input(auction_json)
        .unwrap_or_else(|e| panic!("failed to build AuctionInput: {e}"));
    let encoded = encode_packed(&auction_input);

    fs::create_dir_all(&cli.build_dir)
        .unwrap_or_else(|e| panic!("cannot create build dir {}: {e}", cli.build_dir.display()));

    let input_bin = cli.build_dir.join("input.bin");
    let mut f = fs::File::create(&input_bin)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", input_bin.display()));
    f.write_all(&encoded)
        .unwrap_or_else(|e| panic!("cannot write input.bin: {e}"));

    let total_trades: usize = auction_input.solutions.iter().map(|s| s.trades.len()).sum();
    println!(
        "[host] Wrote {} ({:.3} MB) — auction_id={}, solutions={}, total_trades={}",
        input_bin.display(),
        encoded.len() as f64 / 1_000_000.0,
        auction_input.auction_id,
        auction_input.solutions.len(),
        total_trades,
    );
}
