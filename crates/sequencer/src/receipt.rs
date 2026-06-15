//! Soft-confirmation receipts: a sequencer's signed promise to include an accepted intent.
//!
//! When a client submits a signed intent, the sequencer can immediately hand back a [`Receipt`]:
//! a signature over (pool, the intent's signed digest, the sequencer's committed seq, the epoch).
//! That gives **sub-second perceived confirmation** while final settlement still lands at the next
//! checkpoint.
//!
//! HONEST FRAMING, **liveness, not finality**: a receipt is a *promise*, not a guarantee. The
//! sequencer could still fail to include the intent; the user's real, unilateral guarantee remains
//! **force-exit** against the last committed root, which needs no sequencer cooperation. A
//! receipt's value is two-fold: (1) UX, an instant "accepted" before the checkpoint lands; and (2)
//! ATTRIBUTABILITY, the receipt is non-repudiable, the sequencer cannot later deny it issued it, so
//! a receipt it then fails to honor (the intent never appears in the on-chain checkpoint's DA,
//! though it was valid and funded) is portable evidence of misbehavior, the basis for
//! slashing/reputation in a federated or permissionless operator set. This module provides the
//! signing/verification primitive; checking a receipt against the on-chain checkpoint is the
//! client's DA-reconstruction step, not part of the trust model.

use liquid_cells_stf::{keccak, sig, Hash};

/// Domain tag so a receipt signature can never be replayed as (or forged from) an intent signature.
pub fn domain_receipt() -> Hash {
    keccak(b"LIQUIDCELLS/v1/soft-receipt")
}

/// A sequencer's signed soft confirmation that it accepted an intent into the batch building on
/// `committed_seq` (so the intent is promised for a checkpoint with `seq > committed_seq`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub pool_id: Hash,
    /// The intent's signed-message digest (the same `transfer_msg` / `withdraw_msg` /
    /// `htlc_lock_msg` the client signed), so the receipt binds exactly the intent the user
    /// authorized, no separate id scheme.
    pub intent_msg: Hash,
    /// The sequencer's committed sequence number at acceptance.
    pub committed_seq: u64,
    /// The epoch at which the sequencer accepted it.
    pub accepted_epoch: u64,
    /// The sequencer's identity (compressed secp256k1 pubkey) that signed this receipt.
    pub sequencer_pubkey: [u8; 33],
    pub sig: [u8; 64],
}

fn receipt_msg(pool_id: &Hash, intent_msg: &Hash, committed_seq: u64, accepted_epoch: u64) -> Hash {
    let mut b = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
    b.extend_from_slice(&domain_receipt());
    b.extend_from_slice(pool_id);
    b.extend_from_slice(intent_msg);
    b.extend_from_slice(&committed_seq.to_be_bytes());
    b.extend_from_slice(&accepted_epoch.to_be_bytes());
    keccak(&b)
}

/// Issue a receipt with the sequencer's `secret` key over the intent's signed digest `intent_msg`.
pub fn issue(
    secret: &[u8; 32],
    pool_id: Hash,
    intent_msg: Hash,
    committed_seq: u64,
    accepted_epoch: u64,
) -> Receipt {
    let msg = receipt_msg(&pool_id, &intent_msg, committed_seq, accepted_epoch);
    let (sequencer_pubkey, sig) = sig::sign(secret, &msg);
    Receipt { pool_id, intent_msg, committed_seq, accepted_epoch, sequencer_pubkey, sig }
}

impl Receipt {
    /// The signature is valid and was made by `sequencer_pubkey` over these exact fields.
    pub fn verify(&self) -> bool {
        let msg =
            receipt_msg(&self.pool_id, &self.intent_msg, self.committed_seq, self.accepted_epoch);
        sig::verify(&self.sequencer_pubkey, &msg, &self.sig)
    }

    /// [`verify`](Self::verify) AND that it was signed by the sequencer identity the client trusts
    /// for soft confirmations. Returns false on any mismatch.
    pub fn verify_from(&self, expected_sequencer_pubkey: &[u8; 33]) -> bool {
        &self.sequencer_pubkey == expected_sequencer_pubkey && self.verify()
    }
}
