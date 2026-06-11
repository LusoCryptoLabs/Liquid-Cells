//! Keccak-256 hashing primitives.
//!
//! Keccak is used everywhere a hash is needed (SMT nodes, leaf hashing, signed
//! message digests, on-chain commitments) for one reason: SP1 ships a keccak
//! precompile, so hashing is cheap inside the zkVM guest while remaining native
//! in the sequencer. The on-chain force-exit verifier MUST use this same keccak
//! SMT so a proof generated off-chain verifies on-chain unchanged.

use sha3::{Digest, Keccak256};

/// A 32-byte digest / SMT node / key.
pub type Hash = [u8; 32];

/// Keccak-256 of an arbitrary byte slice.
pub fn keccak(bytes: &[u8]) -> Hash {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Hash of an internal SMT node from its two children: keccak(left || right).
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    keccak(&buf)
}
