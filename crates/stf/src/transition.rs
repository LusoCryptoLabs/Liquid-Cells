//! The state-transition function.
//!
//! [`prove_transition`] is the heart of the protocol and the *exact* code the SP1
//! guest proves. It operates on a **partial witness**, only the leaves the batch
//! touches plus the frontier sibling hashes, so proving cost scales with batch
//! size, not pool size. It:
//!
//!   1. checks the witness leaves + siblings reconstruct `prev_root`,
//!   2. applies deposits/transfers/withdrawals over the touched leaves, and
//!   3. recomputes `new_root` from the same siblings.
//!
//! Its safety contract is two invariants the on-chain verifier relies on:
//!
//!   1. **No debit without a signature**, a leaf's balance only decreases via a
//!      `Transfer`/`Withdrawal` carrying a valid signature from that leaf's owner.
//!   2. **Value conservation**, `total` only changes by deposits (+), withdrawals
//!      (−), and the sequencer's `fee_withdrawal` (−); in-pool fees move *within* the
//!      pool into `fee_acc`, and the `fee_withdrawal` draws back down out of `fee_acc`
//!      to pay the L1 miner fee. Because the pre-state root is bound, the draw is
//!      capped at accumulated fee revenue, and every step uses checked arithmetic, the
//!      relation `Σ balances + fee_acc == total` is preserved transitively from
//!      genesis without re-summing the whole tree, and user balances are never the
//!      source of an L1 fee.
//!
//! The full-tree [`State`] is the sequencer/test view: it builds a witness from the
//! complete tree, runs the identical [`prove_transition`] logic, and keeps its tree
//! in sync, asserting (in debug builds) that the full-tree root equals the
//! witness-derived `new_root`.

use crate::error::StfError;
use crate::hash::{keccak, Hash};
#[cfg(not(feature = "compact_smt"))]
use crate::smt::{root_from_witness, Smt};
#[cfg(feature = "compact_smt")]
use crate::smt_compact::{root_from_witness, Smt};
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

/// Hard protocol ceiling on the number of leaves one batch may touch. Bounds the
/// proof size so checkpoints have predictable cost, and lets the on-chain verifier
/// assume batches are bounded. Basis (SP1 6.2, k256 + keccak precompiles): ~0.62M
/// SP1 cycles per touched leaf measured by the host driver, so 1024 leaves ≈ 0.64B
/// cycles, a generous periodic-checkpoint ceiling. The sequencer picks smaller
/// batches to hit its own latency target; this is only the upper bound.
pub const MAX_LEAVES_PER_BATCH: usize = 1024;

/// Protocol minimum fee a signed *fee-paying* intent (a transfer or an HTLC-lock) must pay.
/// Enforced **in-proof** only when the `min_fee` feature is compiled in, which is OFF in the
/// deployed SP1 guest, so this constant is absent from the proven ELF and the guest vkey
/// (0x00213af5…) is unchanged. It is staged here for the post-audit upgrade bundle: each such
/// intent already debits `amount + fee` from the payer, so the floor simply guarantees every
/// intent that costs the operator a leaf's worth of DA + cycles contributes at least this much
/// fee revenue, closing the zero-fee griefing gap *provably*. Until the upgrade flips it on,
/// the running sequencer enforces the identical floor as admission policy
/// ([`liquid_cells_sequencer::FeePolicy`]), so the economics hold operationally now. The value
/// is a placeholder unit (1 shannon-equivalent); the production figure is an audit-time choice
/// calibrated to the marginal per-leaf checkpoint cost.
#[cfg(feature = "min_fee")]
pub const MIN_FEE_PER_LEAF: u128 = 1;

/// Keys a batch reads/writes, sorted and deduplicated. Derivable from the batch (and the
/// `pool_id`, which HTLC ids are bound to), so the guest can independently check the
/// witness covers exactly these.
pub fn touched_keys(pool_id: &Hash, batch: &Batch) -> Vec<Hash> {
    let mut set = BTreeSet::new();
    for d in &batch.deposits {
        set.insert(d.to_key);
    }
    for t in &batch.transfers {
        set.insert(key_of_pubkey(&t.from_pubkey));
        set.insert(t.to_key);
    }
    for l in &batch.htlc_locks {
        let sk = key_of_pubkey(&l.sender_pubkey);
        set.insert(sk);
        set.insert(htlc_id(pool_id, &sk, &l.receiver_key, l.amount, &l.hashlock, l.timeout, l.nonce));
    }
    for c in &batch.htlc_claims {
        let h = &c.htlc;
        set.insert(h.receiver_key);
        set.insert(htlc_id(pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout, h.lock_nonce));
    }
    for r in &batch.htlc_refunds {
        let h = &r.htlc;
        set.insert(h.sender_key);
        set.insert(htlc_id(pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout, h.lock_nonce));
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
/// values only, never inserts or removes keys, so the post-state key set (and
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
        // (staged, `min_fee` off in the deployed guest) every fee-paying intent must clear the
        // protocol floor, so a checkpoint's fee revenue always covers its per-leaf cost.
        #[cfg(feature = "min_fee")]
        if t.fee < MIN_FEE_PER_LEAF {
            return Err(StfError::FeeBelowMinimum);
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

    // HTLC locks: escrow `amount` into a leaf keyed by all the lock terms (`htlc_id`).
    // The sender's signature is the only debit authority. The escrowed funds stay in the
    // pool (total unchanged) until claimed by preimage or refunded after timeout.
    for l in &batch.htlc_locks {
        let sender_key = key_of_pubkey(&l.sender_pubkey);
        let from = *work.get(&sender_key).ok_or(StfError::MalformedWitness)?;
        if l.nonce != from.nonce {
            return Err(StfError::BadNonce);
        }
        if l.timeout <= batch.current_epoch {
            return Err(StfError::Expired); // an HTLC must have a future claim deadline
        }
        #[cfg(feature = "min_fee")]
        if l.fee < MIN_FEE_PER_LEAF {
            return Err(StfError::FeeBelowMinimum);
        }
        let msg = htlc_lock_msg(
            prev.chain_id, &prev.pool_id, &sender_key, &l.receiver_key, l.amount, l.fee,
            &l.hashlock, l.timeout, l.nonce,
        );
        if !crate::sig::verify(&l.sender_pubkey, &msg, &l.sig) {
            return Err(StfError::BadSignature);
        }
        let debit = l.amount.checked_add(l.fee).ok_or(StfError::Overflow)?;
        if from.balance < debit {
            return Err(StfError::InsufficientBalance);
        }
        let id = htlc_id(
            &prev.pool_id, &sender_key, &l.receiver_key, l.amount, &l.hashlock, l.timeout, l.nonce,
        );
        let slot = *work.get(&id).ok_or(StfError::MalformedWitness)?;
        // Deployed: the escrow slot must be empty, else a pre-credit at `id` blocks the lock and an
        // attacker can grief a swap (H-1). Under the staged `htlc_keyspace` fix the lock instead
        // *accumulates* onto any pre-existing balance (and claim/refund SWEEP the whole leaf to the
        // fixed counterparty), so a hostile pre-credit/top-up can neither block the lock nor freeze
        // the in-pool escrow. Statement-level `#[cfg]` keeps the off path byte-identical (vkey
        // unchanged). H-1 is staged across FOUR coordinated halves, all gated by `htlc_keyspace`,
        // that flip together at the re-bake: this guest STF, the sequencer (resilient.rs mirror), the
        // on-chain contract (escape.rs force-refund reconstructs/sweeps the real committed balance via
        // a 16-byte-widened witness), and the client (force_refund_witness carries that balance).
        // Flipping only a subset is unsafe (guest-without-contract would brick force-refund of a
        // griefed escrow), so they ship as one bundle.
        #[cfg(not(feature = "htlc_keyspace"))]
        if !slot.is_empty() {
            return Err(StfError::HtlcExists);
        }
        #[cfg(feature = "htlc_keyspace")]
        let _ = slot; // read to fault the escrow leaf into the witness; balance is accumulated below
        {
            let f = work.get_mut(&sender_key).unwrap();
            f.balance -= debit;
            f.nonce += 1;
        }
        {
            let e = work.get_mut(&id).unwrap();
            #[cfg(not(feature = "htlc_keyspace"))]
            {
                e.balance = l.amount;
            }
            #[cfg(feature = "htlc_keyspace")]
            {
                e.balance = e.balance.checked_add(l.amount).ok_or(StfError::Overflow)?;
            }
            e.nonce = 0;
        }
        fee_delta = fee_delta.checked_add(l.fee).ok_or(StfError::Overflow)?;
    }

    // HTLC claims: reveal the preimage before `timeout` ⇒ pay the receiver. The receiver
    // is fixed by `htlc_id`, so a claim can only ever pay the agreed party.
    for c in &batch.htlc_claims {
        let h = &c.htlc;
        let id = htlc_id(
            &prev.pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout,
            h.lock_nonce,
        );
        let escrow = *work.get(&id).ok_or(StfError::MalformedWitness)?;
        #[cfg(not(feature = "htlc_keyspace"))]
        if escrow.balance != h.amount || escrow.nonce != 0 {
            return Err(StfError::HtlcMissing);
        }
        #[cfg(feature = "htlc_keyspace")]
        if escrow.balance < h.amount || escrow.nonce != 0 {
            return Err(StfError::HtlcMissing); // `>=`: a top-up cannot freeze the claim (H-1)
        }
        if h.timeout <= batch.current_epoch {
            return Err(StfError::HtlcExpired);
        }
        // The hashlock check. Deployed: `keccak(preimage)`. Under the staged `htlc_sha256`,
        // `sha256(preimage)` instead, so the pool leg can share one hashlock with a Fiber /
        // Bitcoin-Lightning HTLC (whose hash is SHA-256) for a trustless atomic swap. The
        // statement-level `#[cfg]` keeps the off path byte-identical (vkey unchanged).
        #[cfg(not(feature = "htlc_sha256"))]
        if keccak(&c.preimage) != h.hashlock {
            return Err(StfError::BadPreimage);
        }
        #[cfg(feature = "htlc_sha256")]
        if crate::hash::sha256(&c.preimage) != h.hashlock {
            return Err(StfError::BadPreimage);
        }
        work.get_mut(&id).unwrap().balance = 0;
        let to = work.get_mut(&h.receiver_key).ok_or(StfError::MalformedWitness)?;
        // Deployed: credit the receiver exactly `amount`. Under `htlc_keyspace`: credit the WHOLE
        // swept leaf (`amount` + any hostile top-up/front-run surplus). The leaf is consumed (zeroed
        // above), so a surplus can neither freeze the claim nor be drained by a repeated claim (a
        // second claim finds an empty leaf). Any surplus is the griefer's own funds, reaches only the
        // htlc_id-fixed receiver, and value is conserved.
        #[cfg(not(feature = "htlc_keyspace"))]
        let credit = h.amount;
        #[cfg(feature = "htlc_keyspace")]
        let credit = escrow.balance;
        to.balance = to.balance.checked_add(credit).ok_or(StfError::Overflow)?;
    }

    // HTLC refunds: at/after `timeout` ⇒ return the amount to the sender (fixed by id).
    for r in &batch.htlc_refunds {
        let h = &r.htlc;
        let id = htlc_id(
            &prev.pool_id, &h.sender_key, &h.receiver_key, h.amount, &h.hashlock, h.timeout,
            h.lock_nonce,
        );
        let escrow = *work.get(&id).ok_or(StfError::MalformedWitness)?;
        #[cfg(not(feature = "htlc_keyspace"))]
        if escrow.balance != h.amount || escrow.nonce != 0 {
            return Err(StfError::HtlcMissing);
        }
        #[cfg(feature = "htlc_keyspace")]
        if escrow.balance < h.amount || escrow.nonce != 0 {
            return Err(StfError::HtlcMissing); // `>=`: a top-up cannot freeze the refund (H-1)
        }
        if h.timeout > batch.current_epoch {
            return Err(StfError::HtlcNotExpired);
        }
        work.get_mut(&id).unwrap().balance = 0;
        let to = work.get_mut(&h.sender_key).ok_or(StfError::MalformedWitness)?;
        // Deployed: refund the sender exactly `amount`. Under `htlc_keyspace`: sweep the WHOLE leaf
        // (`amount` + any surplus) back to the sender; the leaf is consumed (zeroed above), so a
        // surplus cannot freeze the refund nor be double-refunded. Value is conserved.
        #[cfg(not(feature = "htlc_keyspace"))]
        let credit = h.amount;
        #[cfg(feature = "htlc_keyspace")]
        let credit = escrow.balance;
        to.balance = to.balance.checked_add(credit).ok_or(StfError::Overflow)?;
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
    let tk = touched_keys(&prev.pool_id, batch);
    if tk.len() > MAX_LEAVES_PER_BATCH {
        return Err(StfError::BatchTooLarge);
    }
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

    // L1 fee draw. The sequencer may extract up to the pool's accumulated fee revenue
    // (`prev.fee_acc + fee_delta`) to fund the checkpoint's on-chain miner fee. Capping
    // at fee revenue is what makes "an L1 fee can never be skimmed from a user balance"
    // a *proven* fact: the draw reduces `total` and `fee_acc` by the same amount, so
    // `Σ balances` is invariant under it.
    let fee_available = prev.fee_acc.checked_add(ops.fee_delta).ok_or(StfError::Overflow)?;
    if batch.fee_withdrawal > fee_available {
        return Err(StfError::InsufficientFees);
    }
    let new_total = ops.new_total.checked_sub(batch.fee_withdrawal).ok_or(StfError::Overflow)?;

    // Recompute new_root from the same siblings (key set, hence layout, is unchanged).
    let new_root = if tk.is_empty() {
        prev.root
    } else {
        let post_entries: Vec<(Hash, Hash)> = work.iter().map(|(k, l)| (*k, l.hash())).collect();
        root_from_witness(&post_entries, &witness.siblings).ok_or(StfError::MalformedWitness)?
    };

    // Data-availability commitment over the touched leaves' post-state, in batch's
    // sorted key order (the `work` BTreeMap is already sorted). The anchor binds this
    // to the published blob bytes, so the diff cannot be withheld.
    let da_entries: Vec<(Hash, Leaf)> = work.iter().map(|(k, l)| (*k, *l)).collect();
    let da_commitment = crate::da::da_commitment(&crate::da::encode_da_blob(&da_entries));

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
        new_total,
        fee_delta: ops.fee_delta,
        current_epoch: batch.current_epoch,
        fee_withdrawal: batch.fee_withdrawal,
        da_commitment,
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

/// Full in-memory pool state, the sequencer and test view. Holds the complete
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
        let tk = touched_keys(&self.pool.pool_id, batch);
        let leaves = tk.iter().map(|k| (*k, self.get_leaf(k))).collect();
        let siblings = self.smt.frontier_siblings(&tk);
        Witness { leaves, siblings }
    }

    /// The canonical DA blob for `batch` against THIS state. Call it on the *post-apply*
    /// state: it reads the touched leaves' post-state (sorted by key), so
    /// `keccak(state.da_blob(batch)) == pv.da_commitment`. This is the byte string the
    /// sequencer publishes in the checkpoint tx witness.
    pub fn da_blob(&self, batch: &Batch) -> Vec<u8> {
        let tk = touched_keys(&self.pool.pool_id, batch);
        let entries: Vec<(Hash, Leaf)> = tk.iter().map(|k| (*k, self.get_leaf(k))).collect();
        crate::da::encode_da_blob(&entries)
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
    state.pool.fee_acc = state
        .pool
        .fee_acc
        .checked_add(pv.fee_delta)
        .ok_or(StfError::Overflow)?
        .checked_sub(pv.fee_withdrawal)
        .ok_or(StfError::Overflow)?;

    // The witness-derived root must equal the independently recomputed full-tree root.
    debug_assert_eq!(state.smt.root(), pv.new_root, "witness/full-tree root divergence");
    Ok(pv)
}
