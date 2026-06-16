//! Compact (pass-through) sparse Merkle tree, the staged successor to [`crate::smt`].
//!
//! Same 256-bit keccak keys, same bit-indexed descent and same frontier-sibling
//! witness *structure* as the deployed depth-256 tree, so the partial-witness
//! reconstruction the guest runs and the full-tree builder the sequencer runs stay
//! structurally identical to the live scheme. Only three node-hashing primitives
//! change, and that change is what cuts proving cost:
//!
//!   * **Empty subtrees are one constant** (`[0u8; 32]`) at every depth, not a
//!     depth-dependent default.
//!   * **A node with one empty child *is* its non-empty child** (pass-through, no
//!     hash). So a leaf that is alone in its subtree collapses straight up to the
//!     first branch point: an isolated leaf costs **one** keccak instead of 256.
//!   * **An occupied leaf binds its full key** (`keccak(0x00 ‖ key ‖ content)`), so
//!     the collapse above cannot relocate it; internal nodes are domain-separated
//!     (`keccak(0x01 ‖ left ‖ right)`) so a leaf hash can never be read as a branch.
//!
//! Net: a batch's SMT hashing drops from `O(touched · 256)` to about
//! `O(touched · log₂ pool)`. This re-bakes the guest vkey, so it is gated behind
//! `compact_smt` (OFF in the deployed guest) and validated against the live scheme in
//! `tests/compact_smt.rs`, exactly as the in-proof `min_fee` floor is staged.
//!
//! The public surface mirrors [`crate::smt`] one-for-one so it is a drop-in under the
//! feature; the production scheme is selected by `use` redirects in `lib.rs`,
//! `transition.rs`, and `da.rs`.

use crate::hash::{keccak, Hash};
use std::collections::BTreeMap;

/// Tree depth = key length in bits (unchanged: keys are still 256-bit).
pub const DEPTH: usize = 256;

/// The empty leaf / empty subtree constant. In the compact scheme this single value
/// stands for "empty" at every depth (the depth-dependent defaults are gone).
pub const EMPTY_LEAF: Hash = [0u8; 32];

/// Compact hash of a single occupied leaf: binds the full key so a collapsed
/// (pass-through) path cannot move it. An absent leaf (`content == EMPTY_LEAF`)
/// contributes nothing and stays empty.
#[inline]
fn leaf_node(key: &Hash, content: &Hash) -> Hash {
    if *content == EMPTY_LEAF {
        return EMPTY_LEAF;
    }
    let mut b = [0u8; 1 + 32 + 32];
    b[0] = 0x00;
    b[1..33].copy_from_slice(key);
    b[33..].copy_from_slice(content);
    keccak(&b)
}

/// Compact internal-node hash. A node with one empty child *is* the other child (no
/// hash); a node with two real children is domain-separated from a leaf by the `0x01`
/// tag so the two kinds can never collide.
#[inline]
fn combine(left: &Hash, right: &Hash) -> Hash {
    if *left == EMPTY_LEAF {
        return *right;
    }
    if *right == EMPTY_LEAF {
        return *left;
    }
    let mut b = [0u8; 1 + 32 + 32];
    b[0] = 0x01;
    b[1..33].copy_from_slice(left);
    b[33..].copy_from_slice(right);
    keccak(&b)
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

    /// Current root. The empty tree's root is `EMPTY_LEAF` (`[0u8; 32]`).
    pub fn root(&self) -> Hash {
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        subtree(&entries, 0)
    }

    /// Sibling hashes from the root down to the leaf (`siblings[d]` is the sibling at
    /// depth `d`). Works for membership and non-membership (`leaf` = empty). The list
    /// is still `DEPTH` long; empty levels carry `EMPTY_LEAF`, which `combine`
    /// passes through, so verification skips the keccak at every collapsed level.
    pub fn proof(&self, key: &Hash) -> Vec<Hash> {
        let entries: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let mut sib = Vec::with_capacity(DEPTH);
        collect_siblings(&entries, key, 0, &mut sib);
        sib
    }

    /// Frontier sibling hashes for a multi-leaf proof over `touched` (sorted, unique).
    /// Identical traversal to the live scheme; empty-of-everything subtrees emit
    /// `EMPTY_LEAF`.
    pub fn frontier_siblings(&self, touched: &[Hash]) -> Vec<Hash> {
        if touched.is_empty() {
            return Vec::new();
        }
        let full: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let mut out = Vec::new();
        frontier(&full, touched, 0, &mut out);
        out
    }
}

/// Hash of the subtree spanned by `entries` (all sharing the first `depth` bits),
/// sorted ascending by key.
fn subtree(entries: &[(Hash, Hash)], depth: usize) -> Hash {
    if entries.is_empty() {
        return EMPTY_LEAF;
    }
    if depth == DEPTH {
        // 256-bit keys are unique => exactly one entry here.
        return leaf_node(&entries[0].0, &entries[0].1);
    }
    let mid = entries.partition_point(|(k, _)| bit(k, depth) == 0);
    let (l, r) = entries.split_at(mid);
    combine(&subtree(l, depth + 1), &subtree(r, depth + 1))
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

fn frontier(full: &[(Hash, Hash)], touched: &[Hash], depth: usize, out: &mut Vec<Hash>) {
    if depth == DEPTH {
        return;
    }
    let fmid = full.partition_point(|(k, _)| bit(k, depth) == 0);
    let (fl, fr) = full.split_at(fmid);
    let tmid = touched.partition_point(|k| bit(k, depth) == 0);
    let (tl, tr) = touched.split_at(tmid);
    if tl.is_empty() {
        out.push(subtree(fl, depth + 1));
    } else {
        frontier(fl, tl, depth + 1, out);
    }
    if tr.is_empty() {
        out.push(subtree(fr, depth + 1));
    } else {
        frontier(fr, tr, depth + 1, out);
    }
}

/// Reconstruct a root from a multi-leaf witness. `entries` are the `(key, leaf_hash)`
/// pairs (sorted by key, exactly the touched set); `siblings` are the frontier hashes
/// from [`Smt::frontier_siblings`]. Returns `None` on a malformed witness (sibling
/// under/overflow). The guest runs this twice, over pre-state and post-state entries
/// with the *same* siblings, to verify `prev_root` and compute `new_root`.
pub fn root_from_witness(entries: &[(Hash, Hash)], siblings: &[Hash]) -> Option<Hash> {
    if entries.is_empty() {
        return None;
    }
    let mut idx = 0usize;
    let r = wrec(entries, 0, siblings, &mut idx)?;
    if idx != siblings.len() {
        return None; // leftover siblings => malformed
    }
    Some(r)
}

fn wrec(entries: &[(Hash, Hash)], depth: usize, siblings: &[Hash], idx: &mut usize) -> Option<Hash> {
    if depth == DEPTH {
        return Some(leaf_node(&entries[0].0, &entries[0].1));
    }
    let mid = entries.partition_point(|(k, _)| bit(k, depth) == 0);
    let (l, r) = entries.split_at(mid);
    let lh = if l.is_empty() {
        let h = *siblings.get(*idx)?;
        *idx += 1;
        h
    } else {
        wrec(l, depth + 1, siblings, idx)?
    };
    let rh = if r.is_empty() {
        let h = *siblings.get(*idx)?;
        *idx += 1;
        h
    } else {
        wrec(r, depth + 1, siblings, idx)?
    };
    Some(combine(&lh, &rh))
}

/// Sparse-encode a 256-long single-leaf proof (from [`Smt::proof`]) for the on-chain escape hatch:
/// a 256-bit bitmap (bit `d` set iff `siblings[d]` is non-empty, MSB-first within each byte) followed
/// by ONLY the non-empty siblings, in increasing-depth order. In the compact tree almost every
/// sibling on a single-leaf path is `EMPTY_LEAF`, so this shrinks the ~8 KB full-sibling witness to
/// `32 + 32·(non-empty count)` bytes (a few hundred for a realistic pool). The on-chain
/// `escape::smt_root` (sparse arm) reverses this exactly: it walks all 256 depths, supplying
/// `EMPTY_LEAF` where the bitmap bit is 0 and the next non-empty sibling where it is 1. The format is
/// duplicated by the no_std contract (which cannot depend on this crate), so the
/// `crates/ckb-contract-tests` force-exit/force-refund suites validate the round-trip.
pub fn sparse_encode_proof(siblings: &[Hash]) -> Vec<u8> {
    let mut bitmap = [0u8; 32];
    let mut present: Vec<u8> = Vec::new();
    for (d, s) in siblings.iter().enumerate() {
        if *s != EMPTY_LEAF {
            bitmap[d >> 3] |= 1 << (7 - (d & 7));
            present.extend_from_slice(s);
        }
    }
    let mut out = Vec::with_capacity(32 + present.len());
    out.extend_from_slice(&bitmap);
    out.extend_from_slice(&present);
    out
}

/// Inverse of [`sparse_encode_proof`]: expand a `bitmap(32) ‖ present` sparse proof back to the full
/// 256-long sibling vector (empty depths filled with `EMPTY_LEAF`). `None` if malformed (too short,
/// `present` length not a multiple of 32, or bitmap popcount != present count). Lets a client
/// re-verify a witness it built against a committed root; the on-chain contract decodes independently
/// (`escape::smt_root_sparse`), and the `ckb-contract-tests` escape suites pin the two to agree.
pub fn sparse_decode_proof(sparse: &[u8]) -> Option<Vec<Hash>> {
    if sparse.len() < 32 {
        return None;
    }
    let bitmap = &sparse[..32];
    let present = &sparse[32..];
    if present.len() % 32 != 0 {
        return None;
    }
    let k = present.len() / 32;
    let popcount: usize = bitmap.iter().map(|b| b.count_ones() as usize).sum();
    if popcount != k {
        return None;
    }
    let mut out = Vec::with_capacity(DEPTH);
    let mut pi = 0usize;
    for d in 0..DEPTH {
        if (bitmap[d >> 3] >> (7 - (d & 7))) & 1 == 1 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&present[pi * 32..pi * 32 + 32]);
            out.push(s);
            pi += 1;
        } else {
            out.push(EMPTY_LEAF);
        }
    }
    Some(out)
}

/// Verify a proof produced by [`Smt::proof`]. `siblings[d]` is the sibling at depth
/// `d` (top-down). This is the exact check the on-chain force-exit verifier runs once
/// the compact scheme is deployed.
pub fn verify_proof(root: &Hash, key: &Hash, leaf: &Hash, siblings: &[Hash]) -> bool {
    if siblings.len() != DEPTH {
        return false;
    }
    let mut cur = leaf_node(key, leaf);
    let mut depth = DEPTH;
    while depth > 0 {
        depth -= 1;
        let sib = &siblings[depth];
        cur = if bit(key, depth) == 0 {
            combine(&cur, sib)
        } else {
            combine(sib, &cur)
        };
    }
    &cur == root
}
