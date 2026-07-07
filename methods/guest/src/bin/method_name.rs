#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let password_bytes: Vec<u8> = env::read();
    let stored_commitment: [u8; 32] = env::read();

    let mut hasher = Sha256::new();
    hasher.update(&password_bytes);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash != stored_commitment {
        panic!("ZK Auth Failed: Invalid credential proof");
    }

    env::commit(&stored_commitment);
}
