//! Resilient sealing, a single bad signed intent must not fail the whole checkpoint.
//!
//! `Sequencer::seal_batch` is **atomic**: if any intent is invalid the entire batch is rejected and
//! nothing is folded. That is the right *safety* property (no partial application), but on its own it
//! is a **liveness / censorship-resistance** footgun: one un-fundable or stale-nonce intent stalls a
//! whole checkpoint until an operator manually prunes it, and `ShardedSequencer` propagates that per
//! shard, so it gets K× worse as you scale.
//!
//! [`validate_batch`] closes that: it mirrors `liquid_cells_stf`'s `apply_ops` per-op logic, but
//! **drops** the offending *signed* intents (transfers, HTLC ops, withdrawals) instead of aborting,
//! and, crucially, never reorders, so a later intent that depended on a dropped one (e.g. a
//! transfer funded by a dropped transfer) is **transitively deferred** because it then fails its own
//! balance check against the un-credited working state. Deposits are never dropped (they are bound to
//! the L1 cells the checkpoint consumes); a deposit overflow is fatal. It lives here, in the
//! sequencer crate, deliberately: it must NOT enter the guest-compiled `liquid_cells_stf` (that would
//! move the proven vkey), and the **real `apply` stays the authority**, [`Sequencer::seal_resilient`]
//! feeds the accepted sub-batch to `seal_batch`, which re-validates atomically. A parity test pins
//! `validate_batch` to `apply_ops`.

use crate::FeePolicy;
use liquid_cells_stf::{
    htlc_id, htlc_lock_msg, keccak, key_of_pubkey, sig, touched_keys, transfer_msg, withdraw_msg,
    Batch, Hash, Leaf, PoolState, StfError,
};
use std::collections::BTreeMap;

/// Which signed intent was dropped, by its index in the corresponding mempool vec, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dropped {
    pub op: DroppedOp,
    pub error: StfError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DroppedOp {
    Transfer(usize),
    HtlcLock(usize),
    HtlcClaim(usize),
    HtlcRefund(usize),
    Withdrawal(usize),
}

/// Filter `batch` to the sub-batch that `apply` will accept, dropping invalid *signed* intents and
/// transitively deferring their dependents (order preserved). `leaf` reads a key's current leaf
/// (the sequencer's full tree). Returns the accepted sub-batch + the dropped intents, or a fatal
/// `StfError` for a batch-wide failure that is not a single intent's fault (a deposit overflow).
///
/// `policy` adds the operator's fee-admission floor: a transfer or HTLC-lock paying below
/// `policy.min_fee_per_intent` is dropped (as `InsufficientFees`) exactly where the staged
/// `liquid_cells_stf` `min_fee` check sits, so this mirrors `apply_ops` compiled either without the
/// floor (`policy` disabled, the deployed guest) or with `MIN_FEE_PER_LEAF = min_fee_per_intent`.
/// Dropping an underpayer is always safe: the policy is stricter than the STF, and `seal_batch`
/// re-validates the survivors atomically.
///
/// MUST mirror `liquid_cells_stf::transition::apply_ops`, pinned by the parity test below.
pub fn validate_batch(
    prev: &PoolState,
    batch: &Batch,
    policy: FeePolicy,
    leaf: impl Fn(&Hash) -> Leaf,
) -> Result<(Batch, Vec<Dropped>), StfError> {
    let mut work: BTreeMap<Hash, Leaf> =
        touched_keys(&prev.pool_id, batch).into_iter().map(|k| (k, leaf(&k))).collect();
    let mut total = prev.total;
    let mut dropped = Vec::new();
    let mut out = Batch {
        current_epoch: batch.current_epoch,
        fee_withdrawal: batch.fee_withdrawal,
        ..Default::default()
    };
    let epoch = batch.current_epoch;

    // deposits, never dropped (bound to consumed L1 cells); overflow is fatal.
    for d in &batch.deposits {
        let l = work.get_mut(&d.to_key).expect("seeded");
        l.balance = l.balance.checked_add(d.amount).ok_or(StfError::Overflow)?;
        total = total.checked_add(d.amount).ok_or(StfError::Overflow)?;
        out.deposits.push(*d);
    }

    // transfers
    for (i, t) in batch.transfers.iter().enumerate() {
        let from_key = key_of_pubkey(&t.from_pubkey);
        let r = (|| {
            if from_key == t.to_key {
                return Err(StfError::SelfTransfer);
            }
            let from = *work.get(&from_key).expect("seeded");
            if t.nonce != from.nonce {
                return Err(StfError::BadNonce);
            }
            if t.expiry < epoch {
                return Err(StfError::Expired);
            }
            if !policy.admits(t.fee) {
                return Err(StfError::InsufficientFees);
            }
            let msg = transfer_msg(prev.chain_id, &prev.pool_id, &from_key, &t.to_key, t.amount, t.fee, t.nonce, t.expiry);
            if !sig::verify(&t.from_pubkey, &msg, &t.sig) {
                return Err(StfError::BadSignature);
            }
            let debit = t.amount.checked_add(t.fee).ok_or(StfError::Overflow)?;
            if from.balance < debit {
                return Err(StfError::InsufficientBalance);
            }
            let to_new = work.get(&t.to_key).expect("seeded").balance.checked_add(t.amount).ok_or(StfError::Overflow)?;
            Ok((debit, to_new))
        })();
        match r {
            Ok((debit, to_new)) => {
                let f = work.get_mut(&from_key).unwrap();
                f.balance -= debit;
                f.nonce += 1;
                work.get_mut(&t.to_key).unwrap().balance = to_new;
                out.transfers.push(t.clone());
            }
            Err(e) => dropped.push(Dropped { op: DroppedOp::Transfer(i), error: e }),
        }
    }

    // HTLC locks
    for (i, l) in batch.htlc_locks.iter().enumerate() {
        let sender_key = key_of_pubkey(&l.sender_pubkey);
        let id = htlc_id(&prev.pool_id, &sender_key, &l.receiver_key, l.amount, &l.hashlock, l.timeout, l.nonce);
        let r = (|| {
            let from = *work.get(&sender_key).expect("seeded");
            if l.nonce != from.nonce {
                return Err(StfError::BadNonce);
            }
            if l.timeout <= epoch {
                return Err(StfError::Expired);
            }
            if !policy.admits(l.fee) {
                return Err(StfError::InsufficientFees);
            }
            let msg = htlc_lock_msg(prev.chain_id, &prev.pool_id, &sender_key, &l.receiver_key, l.amount, l.fee, &l.hashlock, l.timeout, l.nonce);
            if !sig::verify(&l.sender_pubkey, &msg, &l.sig) {
                return Err(StfError::BadSignature);
            }
            let debit = l.amount.checked_add(l.fee).ok_or(StfError::Overflow)?;
            if from.balance < debit {
                return Err(StfError::InsufficientBalance);
            }
            if !work.get(&id).expect("seeded").is_empty() {
                return Err(StfError::HtlcExists);
            }
            Ok(debit)
        })();
        match r {
            Ok(debit) => {
                let f = work.get_mut(&sender_key).unwrap();
                f.balance -= debit;
                f.nonce += 1;
                let e = work.get_mut(&id).unwrap();
                e.balance = l.amount;
                e.nonce = 0;
                out.htlc_locks.push(l.clone());
            }
            Err(e) => dropped.push(Dropped { op: DroppedOp::HtlcLock(i), error: e }),
        }
    }

    // HTLC claims
    for (i, c) in batch.htlc_claims.iter().enumerate() {
        let h = &c.htlc;
        let id = htlc_id(&prev.pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout, h.lock_nonce);
        let r = (|| {
            let escrow = *work.get(&id).expect("seeded");
            if escrow.balance != h.amount || escrow.nonce != 0 {
                return Err(StfError::HtlcMissing);
            }
            if h.timeout <= epoch {
                return Err(StfError::HtlcExpired);
            }
            if keccak(&c.preimage) != h.hashlock {
                return Err(StfError::BadPreimage);
            }
            work.get(&h.receiver_key).expect("seeded").balance.checked_add(h.amount).ok_or(StfError::Overflow)
        })();
        match r {
            Ok(to_new) => {
                work.get_mut(&id).unwrap().balance = 0;
                work.get_mut(&h.receiver_key).unwrap().balance = to_new;
                out.htlc_claims.push(c.clone());
            }
            Err(e) => dropped.push(Dropped { op: DroppedOp::HtlcClaim(i), error: e }),
        }
    }

    // HTLC refunds
    for (i, rf) in batch.htlc_refunds.iter().enumerate() {
        let h = &rf.htlc;
        let id = htlc_id(&prev.pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout, h.lock_nonce);
        let r = (|| {
            let escrow = *work.get(&id).expect("seeded");
            if escrow.balance != h.amount || escrow.nonce != 0 {
                return Err(StfError::HtlcMissing);
            }
            if h.timeout > epoch {
                return Err(StfError::HtlcNotExpired);
            }
            work.get(&h.sender_key).expect("seeded").balance.checked_add(h.amount).ok_or(StfError::Overflow)
        })();
        match r {
            Ok(to_new) => {
                work.get_mut(&id).unwrap().balance = 0;
                work.get_mut(&h.sender_key).unwrap().balance = to_new;
                out.htlc_refunds.push(rf.clone());
            }
            Err(e) => dropped.push(Dropped { op: DroppedOp::HtlcRefund(i), error: e }),
        }
    }

    // withdrawals
    for (i, w) in batch.withdrawals.iter().enumerate() {
        let from_key = key_of_pubkey(&w.from_pubkey);
        let r = (|| {
            let from = *work.get(&from_key).expect("seeded");
            if w.nonce != from.nonce {
                return Err(StfError::BadNonce);
            }
            if w.expiry < epoch {
                return Err(StfError::Expired);
            }
            let msg = withdraw_msg(prev.chain_id, &prev.pool_id, &from_key, &w.target_lock_hash, w.amount, w.nonce, w.expiry);
            if !sig::verify(&w.from_pubkey, &msg, &w.sig) {
                return Err(StfError::BadSignature);
            }
            if from.balance < w.amount {
                return Err(StfError::InsufficientBalance);
            }
            total.checked_sub(w.amount).ok_or(StfError::Overflow)
        })();
        match r {
            Ok(new_total) => {
                let f = work.get_mut(&from_key).unwrap();
                f.balance -= w.amount;
                f.nonce += 1;
                total = new_total;
                out.withdrawals.push(w.clone());
            }
            Err(e) => dropped.push(Dropped { op: DroppedOp::Withdrawal(i), error: e }),
        }
    }

    Ok((out, dropped))
}
