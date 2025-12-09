#![allow(clippy::needless_return)]

use anyhow::{Context, Result};
use clap::Parser;
use common::{codec, Byte32, Candidate, GuestInput, PubKey, SchnorrSig};
use ere_zkvm_interface::{zkVM, Compiler, Input, InputItem, ProofKind, ProverResourceType};
use k256::ecdsa::{SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use k256::{
    schnorr::{signature::Signer as _, Signature, SigningKey},
    SecretKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tiny_keccak::{Hasher, Keccak};

// use ere_pico::{compiler::RustRv32ima as PicoCompiler, ErePico};
use ere_risc0::{compiler::RustRv32ima as Risc0Compiler, EreRisc0};
use ere_sp1::{compiler::RustRv32ima as Sp1Compiler, EreSP1};
use ere_zisk::{compiler::RustRv64imaCustomized as ZiskCompiler, EreZisk};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    msg: String,

    #[arg(long)]
    signers: String,

    #[arg(long, value_parser = ["sp1", "risc0", "zisk", "pico"])]
    zkvm: String,
}

const GUEST_SP1_DIR: &str = "guest-sp1";
const GUEST_RISC0_DIR: &str = "guest-risc0";
const GUEST_ZISK_DIR: &str = "guest-zisk";
// const GUEST_PICO_DIR: &str = "guest-pico";

#[derive(Clone, Copy, Debug)]
enum Backend {
    SP1,
    Risc0,
    Zisk,
    // Pico,
}

fn parse_backend(s: &str) -> Backend {
    match s {
        "sp1" => Backend::SP1,
        "risc0" => Backend::Risc0,
        "zisk" => Backend::Zisk,
        // "pico" => Backend::Pico,
        other => unreachable!("unknown zkvm: {other}"),
    }
}

fn guest_dir_for_backend(cwd: &Path, backend: Backend) -> PathBuf {
    match backend {
        Backend::SP1 => cwd.join(GUEST_SP1_DIR),
        Backend::Risc0 => cwd.join(GUEST_RISC0_DIR),
        Backend::Zisk => cwd.join(GUEST_ZISK_DIR),
        // Backend::Pico => cwd.join(GUEST_PICO_DIR),
    }
}

fn keccak2(a: &Byte32, b: &Byte32) -> Byte32 {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(a);
    h.update(b);
    h.finalize(&mut out);
    out
}

fn keccak256_bytes(data: &[u8]) -> Byte32 {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(data);
    h.finalize(&mut out);
    out
}

#[derive(Clone, Serialize, Deserialize)]
struct DiskKey {
    sk_hex: String,
    ax_hex: String,
    ay_hex: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct KeySet {
    // len = 64
    keys: Vec<DiskKey>,
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let ss = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(ss)?;
    anyhow::ensure!(
        bytes.len() == 32,
        "expected 32-byte hex, got {}",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_or_generate_64_keys<P: AsRef<Path>>(keys_path: P) -> Result<KeySet> {
    let path = keys_path.as_ref();

    if path.exists() {
        let data = fs::read(path).with_context(|| "reading keys.json")?;
        let ks: KeySet = serde_json::from_slice(&data).with_context(|| "parsing keys.json")?;
        return Ok(ks);
    }

    let mut keys = Vec::with_capacity(64);
    for _ in 0..64 {
        let sk = SecretKey::random(&mut OsRng);

        // Full uncompressed point for (ax, ay)
        let ecdsa_signing: EcdsaSigningKey = EcdsaSigningKey::from(&sk);
        let ecdsa_vk: EcdsaVerifyingKey = ecdsa_signing.verifying_key().clone();
        let enc = ecdsa_vk.to_encoded_point(false);
        let ax_bytes = enc.x().expect("uncompressed x");
        let ay_bytes = enc.y().expect("uncompressed y");

        let mut ax = [0u8; 32];
        let mut ay = [0u8; 32];
        ax.copy_from_slice(ax_bytes);
        ay.copy_from_slice(ay_bytes);

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&sk.to_bytes());

        keys.push(DiskKey {
            sk_hex: hex32(&sk_bytes),
            ax_hex: hex32(&ax),
            ay_hex: hex32(&ay),
        });
    }

    let ks = KeySet { keys };
    fs::write(path, serde_json::to_vec_pretty(&ks)?)?;
    println!("Generated 64 keypairs → {}", path.display());
    Ok(ks)
}

fn pubkeys_from_keyset(ks: &KeySet) -> Result<Vec<PubKey>> {
    let mut v = Vec::with_capacity(ks.keys.len());
    for dk in &ks.keys {
        let ax = parse_hex32(&dk.ax_hex)?;
        let ay = parse_hex32(&dk.ay_hex)?;
        v.push(PubKey { ax, ay });
    }
    Ok(v)
}

fn merkle_root_from_pubkeys(pks: &[PubKey]) -> Byte32 {
    assert!(
        !pks.is_empty() && pks.len().is_power_of_two(),
        "need 2^n pubkeys"
    );
    let mut level: Vec<Byte32> = pks.iter().map(|pk| keccak2(&pk.ax, &pk.ay)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(keccak2(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

fn parse_signer_indices(s: &str) -> Result<Vec<usize>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let idx: usize = part
            .trim()
            .parse()
            .with_context(|| format!("bad index: {part}"))?;
        anyhow::ensure!(idx < 64, "signer index out of range: {idx}");
        out.push(idx);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn schnorr_sign(sk_hex: &str, msg32: &Byte32) -> Result<SchnorrSig> {
    let sk_bytes = parse_hex32(sk_hex)?;
    let signing = SigningKey::from_bytes(&sk_bytes).context("SigningKey::from_bytes")?;
    let sig: Signature = signing.sign(msg32);
    let sig_bytes = sig.to_bytes(); // 64 bytes: r(32) || s(32)
    let mut rx = [0u8; 32];
    let mut s = [0u8; 32];
    rx.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);
    Ok(SchnorrSig { rx, s })
}

fn message_to_32(msg_arg: &str) -> Result<Byte32> {
    if let Some(h) = msg_arg.strip_prefix("0x") {
        let raw = hex::decode(h)?;
        return Ok(if raw.len() == 32 {
            let mut m = [0u8; 32];
            m.copy_from_slice(&raw);
            m
        } else {
            keccak256_bytes(&raw)
        });
    }
    let bytes = msg_arg.as_bytes();
    Ok(if bytes.len() == 32 {
        let mut m = [0u8; 32];
        m.copy_from_slice(bytes);
        m
    } else {
        keccak256_bytes(bytes)
    })
}

fn run_on_vm<V: zkVM>(label: &str, zkvm: V, input: &Input) -> anyhow::Result<()> {
    let (public_values_ex, exec_report) = zkvm.execute(input)?;
    println!(
        "[{label}] Execute OK. Cycles: {} (duration: {:?})",
        exec_report.total_num_cycles, exec_report.execution_duration
    );
    println!("[{label}] Public values (exec): {:?}", public_values_ex);
    println!("[{label}] exec report: {:?}", exec_report);

    let proof_kind = match label {
        "pico" | "zisk" => ProofKind::Compressed,
        _ => ProofKind::Groth16,
    };

    let (public_values_pr, proof, proving_report) = zkvm.prove(input, proof_kind)?;
    println!("[{label}] Proved in {:?}", proving_report.proving_time);
    println!("[{label}] Public values (prove): {:?}", public_values_pr);
    println!("[{label}] proving report: {:?}", proving_report);
    println!("[{label}] proof: {:?}", proof);

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let backend = parse_backend(&args.zkvm);
    let workspace_root = std::env::current_dir()?.canonicalize()?;
    let guest_dir = guest_dir_for_backend(&workspace_root, backend);
    let keys_path = "keys.json".to_string();

    let keyset = load_or_generate_64_keys(&keys_path)?;
    anyhow::ensure!(keyset.keys.len() == 64);

    let validators = pubkeys_from_keyset(&keyset)?;
    let root = merkle_root_from_pubkeys(&validators);

    let message = message_to_32(&args.msg)?;
    println!("Message (32B) = 0x{}", hex::encode(message));

    let signer_idxs = parse_signer_indices(&args.signers)?;
    println!("Signers = {:?}", signer_idxs);

    let mut candidates: Vec<Candidate> = Vec::with_capacity(32);
    for (i, dk) in keyset.keys.iter().enumerate() {
        let is_signer = signer_idxs.binary_search(&i).is_ok();
        let sig = if is_signer {
            schnorr_sign(&dk.sk_hex, &message)?
        } else {
            SchnorrSig {
                rx: [0u8; 32],
                s: [0u8; 32],
            }
        };
        let ax = parse_hex32(&dk.ax_hex)?;
        let ay = parse_hex32(&dk.ay_hex)?;
        candidates.push(Candidate {
            key: PubKey { ax, ay },
            sig,
            is_ignore: if is_signer { 0 } else { 1 },
        });
    }

    let input = GuestInput {
        root,
        message,
        candidates,
    };
    let input_bytes = codec::encode(&input);
    let zkvm_input: Input = vec![InputItem::Bytes(input_bytes.clone())].into();

    println!("workspace_root = {}", workspace_root.display());
    println!("guest_dir      = {}", guest_dir.display());

    match backend {
        Backend::SP1 => {
            let compiler = Sp1Compiler;
            let program = compiler.compile(&guest_dir)?;
            let zkvm = EreSP1::new(program, ProverResourceType::Cpu);
            run_on_vm("sp1", zkvm, &zkvm_input)?;
        }
        Backend::Risc0 => {
            let compiler = Risc0Compiler;
            let program = compiler.compile(&guest_dir)?;
            let zkvm = EreRisc0::new(program, ProverResourceType::Gpu)?;
            run_on_vm("risc0", zkvm, &zkvm_input)?;
        }
        Backend::Zisk => {
            let compiler = ZiskCompiler;
            let program = compiler.compile(&guest_dir)?;
            let zkvm = EreZisk::new(program, ProverResourceType::Gpu)?;
            run_on_vm("zisk", zkvm, &zkvm_input)?;
        } // Backend::Pico => {
          //     let compiler = PicoCompiler;
          //     let program = compiler.compile(&guest_dir)?;
          //     let zkvm = ErePico::new(program, ProverResourceType::Cpu);
          //     run_on_vm("pico", zkvm, &zkvm_input)?;
          // }
    }

    Ok(())
}
