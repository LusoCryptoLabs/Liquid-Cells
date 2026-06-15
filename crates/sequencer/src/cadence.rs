//! Adaptive seal cadence: *when* to seal the next checkpoint.
//!
//! The sequencer is a pure orderer, so cadence is **policy, not protocol**: tightening or
//! loosening it trades perceived latency against `$/payment` (proving + L1 cost amortized over
//! the batch), and never touches safety. Each checkpoint costs one Groth16 proof plus an L1
//! miner fee regardless of batch size, so sealing one intent at a time is ruinously expensive
//! and sealing only when full starves latency. [`CadencePolicy`] expresses the middle ground:
//! seal when the batch is full, **or** when accumulated fee revenue covers the checkpoint's
//! cost (break-even), **or** when a liveness deadline elapses, whichever comes first.
//!
//! A driver polls [`crate::Sequencer::should_seal`] and calls `seal_batch`/`seal_resilient`
//! when it returns `Some`. This crate stays the deterministic loop; the wall-clock/epoch source
//! and the prover live in the driver.

/// Why the cadence policy says to seal now (returned by [`crate::Sequencer::should_seal`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealTrigger {
    /// The mempool reached `max_batch`: bounds proof size and worst-case inclusion latency.
    BatchFull,
    /// Accumulated fee revenue reached `min_fee_revenue`: the checkpoint's amortized proving +
    /// L1 cost is covered, so sealing now is economically rational ("break-even").
    BreakEven,
    /// `max_interval_epochs` elapsed since the last checkpoint: a liveness floor so a few cheap
    /// intents are not stranded indefinitely below the size and revenue thresholds.
    Interval,
}

/// When to seal the next checkpoint. Evaluated in priority order BatchFull > BreakEven >
/// Interval by [`crate::Sequencer::should_seal`]. A `0` disables the corresponding trigger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CadencePolicy {
    /// Seal once this many intents are pending (caps proof size and per-intent latency).
    pub max_batch: usize,
    /// Seal once the drawable fee revenue (undrawn `fee_acc` + this mempool's fees) reaches this,
    /// so each checkpoint pays for itself. The break-even figure is an operator estimate of the
    /// per-checkpoint proving + L1 cost; `0` disables this trigger.
    pub min_fee_revenue: u128,
    /// Seal once this many epochs have elapsed since the last checkpoint even below the size and
    /// revenue thresholds (liveness floor); `0` disables this trigger.
    pub max_interval_epochs: u64,
}

impl CadencePolicy {
    pub fn new(max_batch: usize, min_fee_revenue: u128, max_interval_epochs: u64) -> Self {
        Self { max_batch, min_fee_revenue, max_interval_epochs }
    }

    /// Latency-first: seal as soon as anything is pending and the short interval elapses (low
    /// perceived latency, weaker amortization). Still bounded by `max_batch`.
    pub fn latency_first(max_batch: usize, max_interval_epochs: u64) -> Self {
        Self { max_batch, min_fee_revenue: 0, max_interval_epochs }
    }

    /// Cost-first: only seal at a full batch or once revenue covers the cost floor (best
    /// amortization, higher tail latency, so keep a generous `max_interval_epochs` as a backstop).
    pub fn cost_first(max_batch: usize, min_fee_revenue: u128, max_interval_epochs: u64) -> Self {
        Self { max_batch, min_fee_revenue, max_interval_epochs }
    }
}
