//! Adaptive seal-cadence policy: the triggers and their priority order. Cadence is pure
//! accounting over the mempool (pending count + fee revenue) and the epoch clock, so these
//! tests build intents with the fees/counts they need; nothing here seals or validates.

use liquid_cells_sequencer::{CadencePolicy, SealTrigger, Sequencer};
use liquid_cells_stf::{keccak, Deposit, Transfer};

fn pool() -> Sequencer {
    Sequencer::genesis(keccak(b"cadence-pool"), 0x434b42)
}

fn deposit(n: u8) -> Deposit {
    Deposit { to_key: keccak(&[n]), amount: 1 }
}

/// A transfer carrying `fee`; other fields are placeholders (cadence only reads the pending
/// count and the `fee`, it never seals or signature-checks).
fn transfer_with_fee(fee: u128, n: u8) -> Transfer {
    Transfer {
        from_pubkey: [n; 33],
        to_key: keccak(&[n, 0xff]),
        amount: 1,
        fee,
        nonce: 0,
        expiry: u64::MAX,
        sig: [0u8; 64],
    }
}

#[test]
fn empty_mempool_never_seals() {
    let seq = pool();
    let p = CadencePolicy::new(4, 100, 10);
    assert_eq!(seq.should_seal(0, &p), None);
    assert_eq!(seq.should_seal(1_000_000, &p), None, "even far in the future, nothing to seal");
}

#[test]
fn batch_full_triggers_and_takes_priority() {
    let mut seq = pool();
    // every trigger is armed; BatchFull must win once the count is reached.
    let p = CadencePolicy::new(3, 1, 1);
    seq.submit_deposit(deposit(1));
    seq.submit_deposit(deposit(2));
    assert_eq!(seq.should_seal(0, &p), None, "2 < max_batch, no fees, no interval elapsed");
    seq.submit_deposit(deposit(3));
    assert_eq!(seq.should_seal(0, &p), Some(SealTrigger::BatchFull));
}

#[test]
fn break_even_triggers_below_batch_size() {
    let mut seq = pool();
    // big batch cap and disabled interval, so only the revenue threshold can fire.
    let p = CadencePolicy::new(1000, 50, 0);
    seq.submit_transfer(transfer_with_fee(20, 1));
    seq.submit_transfer(transfer_with_fee(20, 2));
    assert_eq!(seq.should_seal(0, &p), None, "revenue 40 < 50");
    assert_eq!(seq.pending_fee_revenue(), 40);
    seq.submit_transfer(transfer_with_fee(20, 3));
    assert_eq!(seq.available_fee_revenue(), 60);
    assert_eq!(seq.should_seal(0, &p), Some(SealTrigger::BreakEven), "revenue 60 >= 50");
}

#[test]
fn interval_triggers_as_a_liveness_floor() {
    let mut seq = pool();
    // only the interval is armed (no size/revenue trigger), seal after 5 epochs.
    let p = CadencePolicy::new(1000, 0, 5);
    seq.submit_deposit(deposit(1)); // a single cheap intent that would otherwise wait
    assert_eq!(seq.should_seal(4, &p), None, "4 epochs since genesis < 5");
    assert_eq!(seq.should_seal(5, &p), Some(SealTrigger::Interval));
    assert_eq!(seq.should_seal(9, &p), Some(SealTrigger::Interval));
}

#[test]
fn priority_order_is_batchfull_then_breakeven_then_interval() {
    let mut seq = pool();
    let p = CadencePolicy::new(2, 10, 1);
    // 1 fat-fee transfer: revenue >= 10 and interval elapsed, but batch not full (1 < 2).
    seq.submit_transfer(transfer_with_fee(50, 1));
    assert_eq!(seq.should_seal(100, &p), Some(SealTrigger::BreakEven), "break-even before interval");
    // add one more => batch full now wins over both.
    seq.submit_transfer(transfer_with_fee(50, 2));
    assert_eq!(seq.should_seal(100, &p), Some(SealTrigger::BatchFull));
}

#[test]
fn below_all_thresholds_returns_none() {
    let mut seq = pool();
    let p = CadencePolicy::new(10, 1_000_000, 100);
    seq.submit_transfer(transfer_with_fee(5, 1));
    assert_eq!(seq.should_seal(50, &p), None, "1 < 10 pending, 5 < 1e6 revenue, 50 < 100 epochs");
}

#[test]
fn zero_thresholds_disable_their_triggers() {
    let mut seq = pool();
    // only batch is armed; revenue (0) and interval (0) are disabled.
    let p = CadencePolicy::new(2, 0, 0);
    seq.submit_transfer(transfer_with_fee(u128::MAX, 1));
    assert_eq!(seq.should_seal(u64::MAX, &p), None, "huge fee + far future, but both triggers off");
    seq.submit_transfer(transfer_with_fee(1, 2));
    assert_eq!(seq.should_seal(0, &p), Some(SealTrigger::BatchFull));
}

#[test]
fn presets_behave() {
    let lat = CadencePolicy::latency_first(64, 2);
    assert_eq!(lat.min_fee_revenue, 0);
    let cost = CadencePolicy::cost_first(256, 1_000, 600);
    assert_eq!(cost.max_batch, 256);
    assert_eq!(cost.min_fee_revenue, 1_000);
}

#[test]
fn fee_revenue_saturates_and_does_not_panic() {
    let mut seq = pool();
    seq.submit_transfer(transfer_with_fee(u128::MAX, 1));
    seq.submit_transfer(transfer_with_fee(u128::MAX, 2));
    // saturating add => no overflow panic; just clamps.
    assert_eq!(seq.pending_fee_revenue(), u128::MAX);
}
