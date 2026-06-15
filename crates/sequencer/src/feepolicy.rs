//! Fee-admission policy, the operator's defence against zero-fee griefing, enforced *now*.
//!
//! The proven STF charges whatever `fee` an intent carries, with **no minimum**. A flood of
//! correctly-signed, fully-funded, zero-fee transfers is therefore valid: each one costs the
//! operator a leaf's worth of DA bytes + SP1 cycles to checkpoint, while contributing nothing to
//! the `fee_acc` that funds the on-chain checkpoint fee. Left unchecked the operator subsidises
//! every such intent.
//!
//! [`FeePolicy`] closes that at the sequencer boundary: a configurable per-intent floor that the
//! sequencer refuses to seal below. It is **policy, not proof**, an honest operator's self-
//! protection, not a trustless guarantee, and it is deliberately *stricter* than the STF, so
//! dropping an underpayer is always safe (the authoritative atomic `seal_batch` re-validates the
//! kept intents). The matching *provable* floor lives in `liquid_cells_stf` behind the `min_fee`
//! feature (OFF in the deployed guest, so it does not move the vkey); flipping that on at a
//! coordinated upgrade makes the identical floor unforgeable. Until then, this is the live
//! enforcement and the economics already hold operationally.

use liquid_cells_stf::{Batch, StfError};

/// A per-intent minimum-fee floor applied to the *fee-paying* intents (transfers and HTLC-locks;
/// deposits/withdrawals/claims/refunds carry no `fee` field). `disabled()` (floor 0) is a no-op,
/// so a sequencer left at the default behaves exactly as before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FeePolicy {
    /// Minimum `fee` a transfer or HTLC-lock must pay to be admitted. Mirror of the staged
    /// `liquid_cells_stf::MIN_FEE_PER_LEAF`; set them to the same value at the upgrade.
    pub min_fee_per_intent: u128,
}

impl FeePolicy {
    /// A policy that admits everything (floor 0), the backward-compatible default.
    pub fn disabled() -> Self {
        FeePolicy { min_fee_per_intent: 0 }
    }

    /// A policy enforcing a per-intent fee floor.
    pub fn new(min_fee_per_intent: u128) -> Self {
        FeePolicy { min_fee_per_intent }
    }

    /// True if this policy admits everything (no work to do).
    pub fn is_disabled(&self) -> bool {
        self.min_fee_per_intent == 0
    }

    /// True if `fee` clears the floor. (A disabled policy admits any fee.)
    pub fn admits(&self, fee: u128) -> bool {
        fee >= self.min_fee_per_intent
    }

    /// Strict check (for the atomic [`crate::Sequencer::seal_batch`] path): `Err(InsufficientFees)`
    /// if **any** fee-paying intent underpays, else `Ok`. Leaves the batch untouched. The resilient
    /// path instead *drops* the underpayers inside [`crate::resilient::validate_batch`].
    pub fn check(&self, batch: &Batch) -> Result<(), StfError> {
        if self.is_disabled() {
            return Ok(());
        }
        let underpays = batch.transfers.iter().any(|t| !self.admits(t.fee))
            || batch.htlc_locks.iter().any(|l| !self.admits(l.fee));
        if underpays {
            return Err(StfError::InsufficientFees);
        }
        Ok(())
    }
}
