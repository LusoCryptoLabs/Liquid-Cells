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

/// Test-only keccak call counter, used to measure the SMT scheme's proving-cost win
/// (keccak invocations dominate guest cycles). Gated behind `hash_count` and therefore
/// **absent from the deployed guest ELF**, so the counter never perturbs the vkey.
#[cfg(feature = "hash_count")]
pub mod count {
    use std::sync::atomic::{AtomicU64, Ordering};
    pub(super) static N: AtomicU64 = AtomicU64::new(0);
    /// Number of `keccak` calls since the last [`reset`].
    pub fn get() -> u64 {
        N.load(Ordering::Relaxed)
    }
    /// Zero the counter.
    pub fn reset() {
        N.store(0, Ordering::Relaxed);
    }
}

/// Keccak-256 of an arbitrary byte slice.
pub fn keccak(bytes: &[u8]) -> Hash {
    #[cfg(feature = "hash_count")]
    count::N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
