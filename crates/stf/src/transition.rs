//! The state-transition function.
//!
//! `apply(state, batch)` is the heart of the protocol: the *exact* code the
//! sequencer runs to advance the root and the SP1 guest proves verbatim. Its
//! safety contract is two invariants the on-chain verifier relies on:
//!
//!   1. **No debit without a signature.** A leaf's balance can only decrease via a
//!      `Transfer`/`Withdrawal` carrying a valid signature from that leaf's owner.
//!   2. **Value conservation.** `Σ balances + fee_acc == total`, and
//!      `new_total == prev_total + Σ deposits − Σ withdrawals`.
//!
//! Together they make operator theft and balance inflation impossible rather than
//! merely disputable.

use crate::error::StfError;
use crate::hash::{keccak, Hash};
use crate::smt::Smt;
use crate::types::*;
use std::collections::BTreeMap;

/// Full in-memory pool state (sequencer / test view). The SP1 guest will instead
/// take a partial witness (touched leaves + sibling hashes), but the transition
/// rules below are identical.
#[derive(Clone)]
pub struct State {
    pub pool: PoolState,
    pub smt: Smt,
    pub leaves: BTreeMap<Hash, Leaf>,
}

impl State {
    /// Fresh, empty pool.
    pub fn genesis(pool_id: Hash, chain_id: u64) -> Self {
        let smt = Smt::new();
        let pool = PoolState::genesis(pool_id, chain_id, smt.root());
        State { pool, smt, leaves: BTreeMap::new() }
    }

    pub fn get_leaf(&self, key: &Hash) -> Leaf {
        self.leaves.get(key).copied().unwrap_or_default()
    }

    fn set_leaf(&mut self, key: Hash, leaf: Leaf) {
        self.smt.set_leaf_hash(key, leaf.hash());
        if leaf.is_empty() {
            self.leaves.remove(&key);
        } else {
            self.leaves.insert(key, leaf);
        }
    }

    fn sum_balances(&self) -> Option<u128> {
        let mut acc: u128 = 0;
        for l in self.leaves.values() {
            acc = acc.checked_add(l.balance)?;
        }
        Some(acc)
    }
}

#[inline]
fn fold_commit(acc: Hash, key: &Hash, amount: u128) -> Hash {
    let mut b = [0u8; 32 + 32 + 16];
    b[..32].copy_from_slice(&acc);
    b[32..64].copy_from_slice(key);
    b[64..].copy_from_slice(&amount.to_be_bytes());
    keccak(&b)
}

/// Apply a batch, advancing the pool by one sequence number. On any error the
/// state is left logically unchanged from the caller's perspective (the caller
/// should discard a `State` clone on error rather than reuse the mutated one).
pub fn apply(state: &mut State, batch: &Batch) -> Result<PublicValues, StfError> {
    let pool_id = state.pool.pool_id;
    let chain_id = state.pool.chain_id;
    let prev_root = state.pool.root;
    let prev_seq = state.pool.seq;
    let prev_total = state.pool.total;

    let mut total = prev_total;
    let mut fee_delta: u128 = 0;
    let mut dep_commit = domain_deposits();
    let mut wd_commit = domain_withdrawals();

    // --- deposits: authority is the on-chain cell, no signature ---
    for d in &batch.deposits {
        let mut leaf = state.get_leaf(&d.to_key);
        leaf.balance = leaf.balance.checked_add(d.amount).ok_or(StfError::Overflow)?;
        total = total.checked_add(d.amount).ok_or(StfError::Overflow)?;
        state.set_leaf(d.to_key, leaf);
        dep_commit = fold_commit(dep_commit, &d.to_key, d.amount);
    }

    // --- transfers: payer signature is the only debit authority ---
    for t in &batch.transfers {
        let from_key = key_of_pubkey(&t.from_pubkey);
        if from_key == t.to_key {
            return Err(StfError::SelfTransfer);
        }
        let mut from = state.get_leaf(&from_key);
        if t.nonce != from.nonce {
            return Err(StfError::BadNonce);
        }
        if t.expiry < batch.current_epoch {
            return Err(StfError::Expired);
        }
        let msg = transfer_msg(
            chain_id, &pool_id, &from_key, &t.to_key, t.amount, t.fee, t.nonce, t.expiry,
        );
        if !crate::sig::verify(&t.from_pubkey, &msg, &t.sig) {
            return Err(StfError::BadSignature);
        }
        let debit = t.amount.checked_add(t.fee).ok_or(StfError::Overflow)?;
        if from.balance < debit {
            return Err(StfError::InsufficientBalance);
        }
        from.balance -= debit;
        from.nonce += 1;
        state.set_leaf(from_key, from);

        let mut to = state.get_leaf(&t.to_key);
        to.balance = to.balance.checked_add(t.amount).ok_or(StfError::Overflow)?;
        state.set_leaf(t.to_key, to);

        // Fee leaves the payer but stays in the pool as fee_acc => `total` unchanged.
        fee_delta = fee_delta.checked_add(t.fee).ok_or(StfError::Overflow)?;
    }

    // --- withdrawals: owner signature debits, value leaves the pool ---
    for w in &batch.withdrawals {
        let from_key = key_of_pubkey(&w.from_pubkey);
        let mut from = state.get_leaf(&from_key);
        if w.nonce != from.nonce {
            return Err(StfError::BadNonce);
        }
        if w.expiry < batch.current_epoch {
            return Err(StfError::Expired);
        }
        let msg = withdraw_msg(
            chain_id, &pool_id, &from_key, &w.target_lock_hash, w.amount, w.nonce, w.expiry,
        );
        if !crate::sig::verify(&w.from_pubkey, &msg, &w.sig) {
            return Err(StfError::BadSignature);
        }
        if from.balance < w.amount {
            return Err(StfError::InsufficientBalance);
        }
        from.balance -= w.amount;
        from.nonce += 1;
        state.set_leaf(from_key, from);
        total = total.checked_sub(w.amount).ok_or(StfError::Overflow)?;
        wd_commit = fold_commit(wd_commit, &w.target_lock_hash, w.amount);
    }

    let new_fee_acc = state.pool.fee_acc.checked_add(fee_delta).ok_or(StfError::Overflow)?;
    let new_root = state.smt.root();
    let new_seq = prev_seq + 1;

    // Conservation backstop: Σ balances + fee_acc must equal total.
    let sum = state.sum_balances().ok_or(StfError::Overflow)?;
    if sum.checked_add(new_fee_acc) != Some(total) {
        return Err(StfError::ConservationViolation);
    }

    state.pool.root = new_root;
    state.pool.seq = new_seq;
    state.pool.total = total;
    state.pool.fee_acc = new_fee_acc;

    Ok(PublicValues {
        pool_id,
        chain_id,
        prev_root,
        prev_seq,
        new_root,
        new_seq,
        deposits_commitment: dep_commit,
        withdrawals_commitment: wd_commit,
        prev_total,
        new_total: total,
        fee_delta,
        current_epoch: batch.current_epoch,
    })
}
