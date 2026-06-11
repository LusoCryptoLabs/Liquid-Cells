//! The state-transition function.
//!
//! [`prove_transition`] is the heart of the protocol and the *exact* code the SP1
//! guest proves. It operates on a **partial witness** — only the leaves the batch
//! touches plus the frontier sibling hashes — so proving cost scales with batch
//! size, not pool size. It:
//!
//!   1. checks the witness leaves + siblings reconstruct `prev_root`,
//!   2. applies deposits/transfers/withdrawals over the touched leaves, and
//!   3. recomputes `new_root` from the same siblings.
//!
//! Its safety contract is two invariants the on-chain verifier relies on:
//!
//!   1. **No debit without a signature** — a leaf's balance only decreases via a
//!      `Transfer`/`Withdrawal` carrying a valid signature from that leaf's owner.
//!   2. **Value conservation** — `total` only changes by deposits (+) and
//!      withdrawals (−); fees move *within* the pool into `fee_acc`. Because the
//!      pre-state root is bound and every step uses checked arithmetic, the
//!      relation `Σ balances + fee_acc == total` is preserved transitively from
//!      genesis without re-summing the whole tree.
//!
//! The full-tree [`State`] is the sequencer/test view: it builds a witness from the
//! complete tree, runs the identical [`prove_transition`] logic, and keeps its tree
//! in sync — asserting (in debug builds) that the full-tree root equals the
//! witness-derived `new_root`.

use crate::error::StfError;
use crate::hash::{keccak, Hash};
use crate::smt::{root_from_witness, Smt};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// Partial state handed to the guest: the pre-state of every touched leaf (sorted
/// by key, == the batch's touched set) and the frontier siblings tying them to the
/// root. Both `prev_root` verification and `new_root` computation use these siblings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Witness {
    pub leaves: Vec<(Hash, Leaf)>,
    pub siblings: Vec<Hash>,
}

/// Keys a batch reads/writes, sorted and deduplicated. Derivable from the batch
/// alone, so the guest can independently check the witness covers exactly these.
pub fn touched_keys(batch: &Batch) -> Vec<Hash> {
    let mut set = BTreeSet::new();
    for d in &batch.deposits {
        set.insert(d.to_key);
    }
    for t in &batch.transfers {
        set.insert(key_of_pubkey(&t.from_pubkey));
        set.insert(t.to_key);
    }
    for w in &batch.withdrawals {
        set.insert(key_of_pubkey(&w.from_pubkey));
    }
    set.into_iter().collect()
}

struct OpsResult {
    new_total: u128,
    fee_delta: u128,
    deposits_commitment: Hash,
    withdrawals_commitment: Hash,
}

#[inline]
fn fold_commit(acc: Hash, key: &Hash, amount: u128) -> Hash {
    let mut b = [0u8; 32 + 32 + 16];
    b[..32].copy_from_slice(&acc);
    b[32..64].copy_from_slice(key);
    b[64..].copy_from_slice(&amount.to_be_bytes());
    keccak(&b)
}

/// Pure op logic over a working map pre-seeded with every touched leaf. Mutates
/// values only — never inserts or removes keys — so the post-state key set (and
/// therefore the witness sibling layout) is identical to the pre-state.
fn apply_ops(
    work: &mut BTreeMap<Hash, Leaf>,
    prev: &PoolState,
    batch: &Batch,
) -> Result<OpsResult, StfError> {
    let mut total = prev.total;
    let mut fee_delta: u128 = 0;
    let mut dep_commit = domain_deposits();
    let mut wd_commit = domain_withdrawals();

    // deposits: authority is the on-chain cell, no signature.
    for d in &batch.deposits {
        let leaf = work.get_mut(&d.to_key).ok_or(StfError::MalformedWitness)?;
        leaf.balance = leaf.balance.checked_add(d.amount).ok_or(StfError::Overflow)?;
        total = total.checked_add(d.amount).ok_or(StfError::Overflow)?;
        dep_commit = fold_commit(dep_commit, &d.to_key, d.amount);
    }

    // transfers: payer signature is the only debit authority.
    for t in &batch.transfers {
        let from_key = key_of_pubkey(&t.from_pubkey);
        if from_key == t.to_key {
            return Err(StfError::SelfTransfer);
        }
        let from = *work.get(&from_key).ok_or(StfError::MalformedWitness)?;
        if t.nonce != from.nonce {
            return Err(StfError::BadNonce);
        }
        if t.expiry < batch.current_epoch {
            return Err(StfError::Expired);
        }
        let msg = transfer_msg(
            prev.chain_id, &prev.pool_id, &from_key, &t.to_key, t.amount, t.fee, t.nonce, t.expiry,
        );
        if !crate::sig::verify(&t.from_pubkey, &msg, &t.sig) {
            return Err(StfError::BadSignature);
        }
        let debit = t.amount.checked_add(t.fee).ok_or(StfError::Overflow)?;
        if from.balance < debit {
            return Err(StfError::InsufficientBalance);
        }
        {
            let f = work.get_mut(&from_key).unwrap();
            f.balance -= debit;
            f.nonce += 1;
        }
        {
            let to = work.get_mut(&t.to_key).ok_or(StfError::MalformedWitness)?;
            to.balance = to.balance.checked_add(t.amount).ok_or(StfError::Overflow)?;
        }
        // Fee leaves the payer but stays in the pool as fee_acc => `total` unchanged.
        fee_delta = fee_delta.checked_add(t.fee).ok_or(StfError::Overflow)?;
    }

    // withdrawals: owner signature debits, value leaves the pool.
    for w in &batch.withdrawals {
        let from_key = key_of_pubkey(&w.from_pubkey);
        let from = *work.get(&from_key).ok_or(StfError::MalformedWitness)?;
        if w.nonce != from.nonce {
            return Err(StfError::BadNonce);
        }
        if w.expiry < batch.current_epoch {
            return Err(StfError::Expired);
        }
        let msg = withdraw_msg(
            prev.chain_id, &prev.pool_id, &from_key, &w.target_lock_hash, w.amount, w.nonce, w.expiry,
        );
        if !crate::sig::verify(&w.from_pubkey, &msg, &w.sig) {
            return Err(StfError::BadSignature);
        }
        if from.balance < w.amount {
            return Err(StfError::InsufficientBalance);
        }
        {
            let f = work.get_mut(&from_key).unwrap();
            f.balance -= w.amount;
            f.nonce += 1;
        }
        total = total.checked_sub(w.amount).ok_or(StfError::Overflow)?;
        wd_commit = fold_commit(wd_commit, &w.target_lock_hash, w.amount);
    }

    Ok(OpsResult {
        new_total: total,
        fee_delta,
        deposits_commitment: dep_commit,
        withdrawals_commitment: wd_commit,
    })
}

/// Core transition over a partial witness, returning the public values and the
/// post-state of the touched leaves. Both the guest ([`prove_transition`]) and the
/// sequencer ([`apply`]) go through here.
fn transition_inner(
    prev: &PoolState,
    witness: &Witness,
    batch: &Batch,
) -> Result<(PublicValues, BTreeMap<Hash, Leaf>), StfError> {
    let tk = touched_keys(batch);
    if witness.leaves.len() != tk.len() {
        return Err(StfError::MalformedWitness);
    }

    // The witness must provide exactly the touched keys, in sorted order.
    let mut work = BTreeMap::new();
    let mut pre_entries: Vec<(Hash, Hash)> = Vec::with_capacity(tk.len());
    for ((k, leaf), expected) in witness.leaves.iter().zip(tk.iter()) {
        if k != expected {
            return Err(StfError::MalformedWitness);
        }
        pre_entries.push((*k, leaf.hash()));
        work.insert(*k, *leaf);
    }

    // Bind the pre-state to prev_root.
    if !tk.is_empty() {
        let computed = root_from_witness(&pre_entries, &witness.siblings)
            .ok_or(StfError::MalformedWitness)?;
        if computed != prev.root {
            return Err(StfError::PrevRootMismatch);
        }
    } else if !witness.siblings.is_empty() {
        return Err(StfError::MalformedWitness);
    }

    let ops = apply_ops(&mut work, prev, batch)?;

    // Recompute new_root from the same siblings (key set, hence layout, is unchanged).
    let new_root = if tk.is_empty() {
        prev.root
    } else {
        let post_entries: Vec<(Hash, Hash)> = work.iter().map(|(k, l)| (*k, l.hash())).collect();
        root_from_witness(&post_entries, &witness.siblings).ok_or(StfError::MalformedWitness)?
    };

    let pv = PublicValues {
        pool_id: prev.pool_id,
        chain_id: prev.chain_id,
        prev_root: prev.root,
        prev_seq: prev.seq,
        new_root,
        new_seq: prev.seq + 1,
        deposits_commitment: ops.deposits_commitment,
        withdrawals_commitment: ops.withdrawals_commitment,
        prev_total: prev.total,
        new_total: ops.new_total,
        fee_delta: ops.fee_delta,
        current_epoch: batch.current_epoch,
    };
    Ok((pv, work))
}

/// The function the SP1 guest proves: validate a partial witness against `prev`,
/// apply `batch`, and emit the public values. No full tree, no global re-summing.
pub fn prove_transition(
    prev: &PoolState,
    witness: &Witness,
    batch: &Batch,
) -> Result<PublicValues, StfError> {
    transition_inner(prev, witness, batch).map(|(pv, _)| pv)
}

/// Full in-memory pool state — the sequencer and test view. Holds the complete
/// tree; builds witnesses for the guest and keeps itself in sync.
#[derive(Clone)]
pub struct State {
    pub pool: PoolState,
    pub smt: Smt,
    pub leaves: BTreeMap<Hash, Leaf>,
}

impl State {
    pub fn genesis(pool_id: Hash, chain_id: u64) -> Self {
        let smt = Smt::new();
        let pool = PoolState::genesis(pool_id, chain_id, smt.root());
        State { pool, smt, leaves: BTreeMap::new() }
    }

    pub fn get_leaf(&self, key: &Hash) -> Leaf {
        self.leaves.get(key).copied().unwrap_or_default()
    }

    /// Build the partial witness for `batch` from the full tree (sequencer side).
    pub fn build_witness(&self, batch: &Batch) -> Witness {
        let tk = touched_keys(batch);
        let leaves = tk.iter().map(|k| (*k, self.get_leaf(k))).collect();
        let siblings = self.smt.frontier_siblings(&tk);
        Witness { leaves, siblings }
    }
}

/// Apply a batch to the full-tree state: build a witness, run the identical
/// [`prove_transition`] logic, then fold the post-state back into the tree.
pub fn apply(state: &mut State, batch: &Batch) -> Result<PublicValues, StfError> {
    let witness = state.build_witness(batch);
    let (pv, work) = transition_inner(&state.pool, &witness, batch)?;

    for (k, leaf) in &work {
        state.smt.set_leaf_hash(*k, leaf.hash());
        if leaf.is_empty() {
            state.leaves.remove(k);
        } else {
            state.leaves.insert(*k, *leaf);
        }
    }
    state.pool.root = pv.new_root;
    state.pool.seq = pv.new_seq;
    state.pool.total = pv.new_total;
    state.pool.fee_acc = state.pool.fee_acc.checked_add(pv.fee_delta).ok_or(StfError::Overflow)?;

    // The witness-derived root must equal the independently recomputed full-tree root.
    debug_assert_eq!(state.smt.root(), pv.new_root, "witness/full-tree root divergence");
    Ok(pv)
}
