//! Data availability: the canonical, on-chain-published state diff that makes
//! Liquid Cells trustless against **data withholding**.
//!
//! Each checkpoint commits `da_commitment = keccak(da_blob)` in its public values,
//! computed *in-circuit* from the post-state of the leaves the batch touched (see
//! [`crate::transition`]). The anchor type script binds that commitment to the blob
//! bytes the checkpoint transaction carries in its witness. Because the commitment is
//! proven from the real post-states and keccak is collision-resistant, a valid
//! checkpoint is **forced to publish the true diff** — the operator cannot advance the
//! root while hiding what changed.
//!
//! That is exactly what unilateral exit needs: replaying every checkpoint's blob from
//! genesis (oldest first) rebuilds the *exact* tree, so any user can recover their leaf
//! and a force-exit inclusion proof from L1 data alone, with no cooperation from the
//! sequencer. [`reconstruct`] is that independent verifier.

use crate::hash::{keccak, Hash};
use crate::smt::Smt;
use crate::types::Leaf;

/// Bytes per leaf record: `key(32) ‖ balance(16 BE) ‖ nonce(8 BE)`.
pub const DA_RECORD_LEN: usize = 32 + 16 + 8;

/// Canonical DA blob for one checkpoint: the post-state of the batch's touched leaves,
/// **sorted ascending by key**. `keccak` of this equals `PublicValues::da_commitment`.
pub fn encode_da_blob(post_state_sorted: &[(Hash, Leaf)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(post_state_sorted.len() * DA_RECORD_LEN);
    for (k, leaf) in post_state_sorted {
        b.extend_from_slice(k);
        b.extend_from_slice(&leaf.balance.to_be_bytes());
        b.extend_from_slice(&leaf.nonce.to_be_bytes());
    }
    b
}

/// The DA commitment a checkpoint commits in its public values = `keccak(blob)`.
pub fn da_commitment(blob: &[u8]) -> Hash {
    keccak(blob)
}

/// One parsed `(key, post-state leaf)` record from a DA blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaRecord {
    pub key: Hash,
    pub leaf: Leaf,
}

/// Parse a DA blob into its leaf records. `None` if the length is not a whole number
/// of records.
pub fn parse_da_blob(blob: &[u8]) -> Option<Vec<DaRecord>> {
    if blob.len() % DA_RECORD_LEN != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(blob.len() / DA_RECORD_LEN);
    for rec in blob.chunks(DA_RECORD_LEN) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&rec[..32]);
        let mut bal = [0u8; 16];
        bal.copy_from_slice(&rec[32..48]);
        let mut non = [0u8; 8];
        non.copy_from_slice(&rec[48..56]);
        out.push(DaRecord {
            key,
            leaf: Leaf { balance: u128::from_be_bytes(bal), nonce: u64::from_be_bytes(non) },
        });
    }
    Some(out)
}

/// Independently reconstruct the pool tree from an ordered sequence of checkpoint DA
/// blobs (**oldest first**), with no access to the sequencer. Replaying each blob's
/// post-state records yields the exact tree: `smt.root()` then equals the latest
/// on-chain anchor root, and `smt.proof(key)` is a force-exit-ready inclusion proof.
/// `None` if any blob is malformed.
pub fn reconstruct(blobs: &[Vec<u8>]) -> Option<Smt> {
    let mut smt = Smt::new();
    for blob in blobs {
        for rec in parse_da_blob(blob)? {
            smt.set_leaf_hash(rec.key, rec.leaf.hash());
        }
    }
    Some(smt)
}
