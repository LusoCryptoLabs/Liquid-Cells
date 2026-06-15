//! Hybrid fee schedule for pricing intents client-side.
//!
//! Each touched leaf costs the operator the same DA bytes + proving cycles regardless of the
//! payment size, so a flat per-intent floor is the honest minimum (it is what
//! `liquid_cells_sequencer::FeePolicy` admits on and the staged `min_fee` proves). But a flat fee
//! alone either over-taxes tiny tips or under-charges whales. The hybrid schedule prices a fee as
//! `max(floor, amount · bps / 10000)`: small payments pay the fixed floor, large ones pay a
//! basis-point share. This is **client policy**, the protocol charges whatever `fee` an intent
//! carries; the SDK just helps clients pick a sane one (see [`crate::Account::transfer_scheduled`]).
//!
//! It pairs with **fee sponsorship** ([`crate::Account::sponsor_fee`]): when a sub-cent tip's
//! floor fee would exceed the tip itself, a platform funds the fee so the user's marginal cost is
//! just the tip. Both are pure composition over the existing `Transfer`, no protocol change.

/// A per-intent fee priced as `max(floor, amount · bps / 10000)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSchedule {
    /// The fixed minimum every fee-paying intent owes (covers the operator's per-leaf cost).
    pub floor: u128,
    /// Basis points (1/10000) of the payment amount charged above the floor. `0` = flat floor.
    pub bps: u32,
}

impl FeeSchedule {
    pub const fn new(floor: u128, bps: u32) -> Self {
        Self { floor, bps }
    }

    /// A flat schedule: every intent pays exactly `floor`.
    pub const fn flat(floor: u128) -> Self {
        Self { floor, bps: 0 }
    }

    /// The fee for a payment of `amount`: `max(floor, amount · bps / 10000)`. Saturating, so an
    /// adversarially huge `amount` clamps instead of overflowing.
    pub fn fee_for(&self, amount: u128) -> u128 {
        let pct = amount.saturating_mul(self.bps as u128) / 10_000;
        if pct > self.floor {
            pct
        } else {
            self.floor
        }
    }
}
