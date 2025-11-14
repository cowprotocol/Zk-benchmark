#![no_main]

extern crate alloc;

use common::{Byte32, SchnorrSig};
use guest::{crypto, run_guest, set_platform_hooks};

use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use pico_sdk::entrypoint;
use pico_sdk::io::{commit_bytes, read_vec};
use tiny_keccak::{Hasher, Keccak};

pico_sdk::entrypoint!(main);

#[inline]
fn keccak2(a: &Byte32, b: &Byte32) -> Byte32 {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(a);
    k.update(b);
    k.finalize(&mut out);
    out
}

#[inline]
fn schnorr_pico(msg: &Byte32, ax: &Byte32, _ay: &Byte32, sig: &SchnorrSig) -> bool {
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

fn commit_public_bytes(bytes: &[u8]) {
    commit_bytes(bytes);
}

pub fn main() {
    set_platform_hooks(|| read_vec(), |bytes| commit_public_bytes(bytes));

    crypto::set_crypto(keccak2, schnorr_pico);

    run_guest();
}
