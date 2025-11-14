#![cfg_attr(feature = "guest", no_std)]
#![no_main]
#[allow(unused_imports)]
extern crate alloc;

use alloc::vec::Vec;
use common::codec;
use common::{Byte32, GuestInput, PubKey, PublicRecord, SchnorrSig};
use guest::crypto;
use jolt::provable;
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

// not using inline from jolt-inlines-keccak256 due to builder registeration issue with ere.

// use this in futture if building from scratch
// jolt-inlines-keccak256 = { package = "jolt-inlines-keccak256", git = "https://github.com/a16z/jolt.git"}

// Error message observed:
// thread 'main' panicked at /usr/local/cargo/git/checkouts/jolt-bc4943ecdf5f6930/5101ad2/tracer/src/instruction/inline.rs:219:25:
// No inline sequence builder registered for inline with opcode=0x0b, funct3=0b0, funct7=0b0000001. Register a builder using register_inline()

// #[inline]
// fn keccak2(a: &Byte32, b: &Byte32) -> Byte32 {
//     let mut buf = [0u8; 64];
//     buf[..32].copy_from_slice(a);
//     buf[32..].copy_from_slice(b);

//     let hash = jolt_inlines_keccak256::Keccak256::digest(&buf);
//     hash.into()
// }

#[inline]
fn keccak2(a: &Byte32, b: &Byte32) -> Byte32 {
    let mut hasher = Keccak256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[inline]
fn schnorr_jolt(msg: &Byte32, ax: &Byte32, _ay: &Byte32, sig: &SchnorrSig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ax) else {
        return false;
    };

    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(&sig.rx);
    sig64[32..].copy_from_slice(&sig.s);

    let Ok(sig) = Signature::try_from(&sig64[..]) else {
        return false;
    };

    vk.verify(msg, &sig).is_ok()
}

#[jolt::provable()]
fn multischnorr(input_bytes: Vec<u8>) -> Vec<u8> {
    // Wire in the crypto callbacks (same as SP1/Risc0 guests)
    crypto::set_crypto(keccak2, schnorr_jolt);

    // 1) Decode GuestInput from the raw bytes (bincode)
    let (input, _len): (GuestInput, usize) =
        codec::decode(&input_bytes).expect("bincode decode failed");

    // 2) Rebuild pubkey list
    let pubkeys: Vec<PubKey> = input
        .candidates
        .iter()
        .map(|c| PubKey {
            ax: c.key.ax,
            ay: c.key.ay,
        })
        .collect();

    // 3) Merkle root check
    let computed_root = crypto::merkle_root_from_pubkeys(&pubkeys);
    assert_eq!(computed_root, input.root, "merkle root mismatch");

    // 4) Count valid signatures
    let mut sum_valid: u32 = 0;
    for c in &input.candidates {
        if c.is_ignore != 0 {
            continue;
        }
        if crypto::schnorr_verify(&input.message, &c.key.ax, &c.key.ay, &c.sig) {
            sum_valid += 1;
        }
    }

    // 5) Build PublicRecord and return it as bytes
    let record = PublicRecord {
        root: input.root,
        message: input.message,
        sum_valid,
    };

    codec::encode(&record)
}
