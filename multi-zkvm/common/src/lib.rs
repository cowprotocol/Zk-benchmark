#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub type Byte32 = [u8; 32];

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PubKey {
    pub ax: Byte32,
    pub ay: Byte32,
}

// Schnorr (R, s).
// classic Schnorr on short Weierstrass or BIP340-ish (x-only) flows.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SchnorrSig {
    pub rx: Byte32,
    pub s: Byte32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub key: PubKey,
    pub sig: SchnorrSig,
    pub is_ignore: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestInput {
    pub root: Byte32,
    pub message: Byte32,
    pub candidates: Vec<Candidate>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PublicRecord {
    pub root: Byte32,
    pub message: Byte32,
    pub sum_valid: u32,
}

pub mod codec {
    use super::*;

    #[inline]
    pub fn encode<T: Serialize>(value: &T) -> alloc::vec::Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::legacy()).expect("bincode encode")
    }

    #[inline]
    pub fn decode<T: DeserializeOwned>(
        bytes: &[u8],
    ) -> Result<(T, usize), bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
    }
}
