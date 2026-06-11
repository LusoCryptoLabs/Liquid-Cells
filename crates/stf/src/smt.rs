//! Sparse Merkle tree over 256-bit keccak keys.
//!
//! Convention: an absent leaf hashes to all-zero (`EMPTY_LEAF`). A leaf's stored
//! value is the keccak of its canonical content; the SMT key is `keccak(pubkey)`,
//! which randomizes placement (an attacker cannot grind a `participant_id` into a
//! chosen path).
//!
//! This is the *full-tree* reference implementation used by the sequencer and the
//! tests. The SP1 guest will operate on a *partial* tree (only the touched leaves
//! plus their sibling hashes) — the node-hashing rules here are the contract both
//! sides must match. Root/proof building is intentionally simple and obviously
//! correct; the production sequencer will keep an incremental tree.

use crate::hash::{node_hash, Hash};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Tree depth = key length in bits.
pub const DEPTH: usize = 256;

/// The hash of an absent leaf.
pub const EMPTY_LEAF: Hash = [0u8; 32];

/// `default_nodes()[d]` = hash of an all-empty subtree rooted at depth `d`.
/// `[DEPTH]` is the empty leaf; `[0]` is the empty-tree root.
fn default_nodes() -> &'static [Hash; DEPTH + 1] {
    static DEFAULTS: OnceLock<[Hash; DEPTH + 1]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; DEPTH + 1];
        d[DEPTH] = EMPTY_LEAF;
        let mut i = DEPTH;
        while i > 0 {
            i -= 1;
            d[i] = node_hash(&d[i + 1], &d[i + 1]);
        }
        d
    })
}

/// Bit `i` of a key, MSB-first (i = 0 is the most-significant bit of byte 0).
#[inline]
fn bit(key: &Hash, i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

#[derive(Clone, Default)]
pub struct Smt {
    /// key -> leaf-content hash. Absence == empty (never stores `EMPTY_LEAF`).
    leaves: BTreeMap<Hash, Hash>,
}

impl Smt {
    pub fn new() -> Self {
        Self { leaves: BTreeMap::new() }
    }

    pub fn get_leaf_hash(&self, key: &Hash) -> Hash {
        *self.leaves.get(key).unwrap_or(&EMPTY_LEAF)
    }

    pub fn set_leaf_hash(&mut self, key: Hash, leaf: Hash) {
        if leaf == EMPTY_LEAF {
            self.leaves.remove(&key);
        } else {
            self.leaves.insert(key, leaf);
        }
    }

    /// Current root.
    pub fn root(&self) -> Hash {
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        subtree(&entries, 0)
    }

    /// Sibling hashes from the root down to the leaf (`siblings[d]` is the sibling
    /// at depth `d`). Works for both membership and non-membership (`leaf` = empty).
    pub fn proof(&self, key: &Hash) -> Vec<Hash> {
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let mut sib = Vec::with_capacity(DEPTH);
        collect_siblings(&entries, key, 0, &mut sib);
        sib
    }
}

/// Hash of the subtree spanned by `entries` (all sharing the first `depth` bits),
/// sorted ascending by key.
fn subtree(entries: &[(Hash, Hash)], depth: usize) -> Hash {
    if entries.is_empty() {
        return default_nodes()[depth];
    }
    if depth == DEPTH {
        // 256-bit keys are unique => exactly one entry here.
        return entries[0].1;
    }
    let mid = entries.partition_point(|(k, _)| bit(k, depth) == 0);
    let (l, r) = entries.split_at(mid);
    node_hash(&subtree(l, depth + 1), &subtree(r, depth + 1))
}

fn collect_siblings(entries: &[(Hash, Hash)], key: &Hash, depth: usize, out: &mut Vec<Hash>) {
    if depth == DEPTH {
        return;
    }
    let mid = entries.partition_point(|(k, _)| bit(k, depth) == 0);
    let (l, r) = entries.split_at(mid);
    if bit(key, depth) == 0 {
        out.push(subtree(r, depth + 1));
        collect_siblings(l, key, depth + 1, out);
    } else {
        out.push(subtree(l, depth + 1));
        collect_siblings(r, key, depth + 1, out);
    }
}

/// Verify a proof produced by [`Smt::proof`]. `siblings[d]` is the sibling at depth
/// `d` (top-down). This is the exact check the on-chain force-exit verifier runs.
pub fn verify_proof(root: &Hash, key: &Hash, leaf: &Hash, siblings: &[Hash]) -> bool {
    if siblings.len() != DEPTH {
        return false;
    }
    let mut cur = *leaf;
    let mut depth = DEPTH;
    while depth > 0 {
        depth -= 1;
        let sib = &siblings[depth];
        cur = if bit(key, depth) == 0 {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
    }
    &cur == root
}
