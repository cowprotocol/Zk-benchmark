#![no_main]
#![no_std]
ziskos::entrypoint!(main);

extern crate alloc;

use common::{Byte32, SchnorrSig};
use guest::{crypto, run_guest, set_platform_hooks};
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use tiny_keccak::{Hasher, Keccak};
use ziskos::{read_input, set_output};

#[inline]
fn keccak2(a: &Byte32, b: &Byte32) -> Byte32 {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(a);
    k.update(b);
    k.finalize(&mut out);
    out
}

// this doesn't use the k256 patched version (0.14.0-pre.8) for zisk as
// the version uses elliptic-curve = { version = "0.14.0-rc.7"} which results in errors while building.
// error: the trait bound `R: crypto_bigint::rand_core::RngCore` is not satisfied
//    --> /Users/user/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/elliptic-curve-0.14.0-rc.16/src/scalar/value.rs:69:40
//     |
// 69  |             inner: C::Uint::random_mod(rng, Self::MODULUS.as_nz_ref()),
//     |                    ------------------- ^^^ the trait `DerefMut` is not implemented for `R`
//     |                    |
//     |                    required by a bound introduced by this call
//     |
//     = note: required for `R` to implement `crypto_bigint::rand_core::RngCore`
// note: required by a bound in `random_mod`

#[inline]
fn schnorr_zisk(msg: &Byte32, ax: &Byte32, _ay: &Byte32, sig: &SchnorrSig) -> bool {
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

fn write_public_bytes(bytes: &[u8]) {
    let mut buf = [0u8; 4];

    for (i, chunk) in bytes.chunks(4).enumerate() {
        buf.fill(0);
        buf[..chunk.len()].copy_from_slice(chunk);

        let val: u32 = ((buf[0] as u32) << 24)
            | ((buf[1] as u32) << 16)
            | ((buf[2] as u32) << 8)
            | (buf[3] as u32);

        set_output(i, val);
    }
}

pub fn main() {
    set_platform_hooks(|| read_input(), |bytes| write_public_bytes(bytes));

    crypto::set_crypto(keccak2, schnorr_zisk);

    run_guest();
}
