#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use common::{codec, Candidate, GuestInput, PubKey};

pub mod crypto;

type ReadAllFn = fn() -> Vec<u8>;
type CommitFn = fn(&[u8]);

static mut READ_ALL: Option<ReadAllFn> = None;
static mut COMMIT: Option<CommitFn> = None;

pub fn set_platform_hooks(read_all: ReadAllFn, commit: CommitFn) {
    unsafe {
        READ_ALL = Some(read_all);
        COMMIT = Some(commit);
    }
}

#[inline]
fn read_all() -> Vec<u8> {
    unsafe { (READ_ALL.expect("READ hook not set"))() }
}

#[inline]
fn commit(bytes: &[u8]) {
    unsafe { (COMMIT.expect("COMMIT hook not set"))(bytes) }
}

pub fn run_guest() {
    let input_bytes = read_all();

    // deserialize input
    let (input, _len): (GuestInput, usize) =
        codec::decode(&input_bytes).expect("bincode decode failed");

    let pubkeys: Vec<PubKey> = input
        .candidates
        .iter()
        .map(|c: &Candidate| PubKey {
            ax: c.key.ax,
            ay: c.key.ay,
        })
        .collect();

    let computed_root = crypto::merkle_root_from_pubkeys(&pubkeys);
    assert_eq!(computed_root, input.root, "merkle root mismatch");

    let mut sum_valid: u32 = 0;
    for c in &input.candidates {
        if c.is_ignore != 0 {
            continue;
        }
        if crypto::schnorr_verify(&input.message, &c.key.ax, &c.key.ay, &c.sig) {
            sum_valid += 1;
        }
    }

    commit(&input.root);
    commit(&input.message);
    commit(&sum_valid.to_le_bytes());
}
