extern crate alloc;

use alloc::vec::Vec;
use common::{Byte32, PubKey, SchnorrSig};

pub type HashFn = fn(a: &Byte32, b: &Byte32) -> Byte32;

pub type SchnorrFn = fn(msg: &Byte32, ax: &Byte32, ay: &Byte32, sig: &SchnorrSig) -> bool;

static mut HASH: Option<HashFn> = None;
static mut SCHNORR: Option<SchnorrFn> = None;

pub fn set_crypto(hash: HashFn, schnorr: SchnorrFn) {
    unsafe {
        HASH = Some(hash);
        SCHNORR = Some(schnorr);
    }
}

#[inline]
pub fn hash(a: &Byte32, b: &Byte32) -> Byte32 {
    unsafe { (HASH.expect("hash not set"))(a, b) }
}

#[inline]
pub fn schnorr_verify(msg: &Byte32, ax: &Byte32, ay: &Byte32, sig: &SchnorrSig) -> bool {
    unsafe { (SCHNORR.expect("schnorr not set"))(msg, ax, ay, sig) }
}

#[inline]
pub fn merkle_root_from_pubkeys(pubkeys: &[PubKey]) -> Byte32 {
    assert!(
        !pubkeys.is_empty() && pubkeys.len().is_power_of_two(),
        "pubkeys must be 2^n"
    );

    let mut level: Vec<Byte32> = pubkeys.iter().map(|pk| hash(&pk.ax, &pk.ay)).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}
