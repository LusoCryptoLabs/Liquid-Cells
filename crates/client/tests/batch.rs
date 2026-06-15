//! `Account::batch_transfer`, N-recipient fan-out (payroll / disbursement / split) over the
//! existing `Transfer` primitive, with NO protocol change. Proves the "de-facto per-payer
//! atomicity" claim: legs share the payer + chain nonces, so in one checkpoint they either all
//! land (funded) or an underfunded leg and every later leg defer together under `seal_resilient`.
//! This is why the protocol does NOT need an atomic multi-output transfer (see ROADMAP Tier C).
use liquid_cells_client::{latest_leaf, Account};
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::*;

const CHAIN: u64 = 0x434b_42;
fn pool() -> Hash {
    keccak(b"payroll-pool")
}
fn acct(n: u8) -> Account {
    let mut s = [0u8; 32];
    s[31] = n;
    Account::new(pool(), CHAIN, s)
}

#[test]
fn funded_batch_all_legs_land_in_one_checkpoint() {
    let mut operator = Sequencer::genesis(pool(), CHAIN);
    let mut payer = acct(1);
    let (a, b, c) = (acct(2), acct(3), acct(4));

    operator.submit_deposit(Deposit { to_key: payer.key(), amount: 100_000_000_000 });
    let job0 = operator.seal_batch(0, 0).unwrap();
    payer.sync_from_da(&[job0.da_blob.clone()]);

    // One signed batch to three recipients.
    let outs = [(a.key(), 10_000_000_000), (b.key(), 20_000_000_000), (c.key(), 30_000_000_000)];
    for t in payer.batch_transfer(&outs, 0, 1_000_000) {
        operator.submit_transfer(t);
    }
    let (job1, dropped) = operator.seal_resilient(1, 0).expect("seal");
    assert!(dropped.is_empty(), "a funded batch lands entirely");

    let blobs = vec![job0.da_blob, job1.da_blob];
    assert_eq!(latest_leaf(&blobs, &a.key()).unwrap().balance, 10_000_000_000);
    assert_eq!(latest_leaf(&blobs, &b.key()).unwrap().balance, 20_000_000_000);
    assert_eq!(latest_leaf(&blobs, &c.key()).unwrap().balance, 30_000_000_000);
    assert_eq!(latest_leaf(&blobs, &payer.key()).unwrap().balance, 40_000_000_000);
}

#[test]
fn underfunded_batch_defers_the_unaffordable_tail_together() {
    let mut operator = Sequencer::genesis(pool(), CHAIN);
    let mut payer = acct(1);
    let (a, b, c) = (acct(2), acct(3), acct(4));

    // Fund only enough for the first leg and part of the second.
    operator.submit_deposit(Deposit { to_key: payer.key(), amount: 15_000_000_000 });
    let job0 = operator.seal_batch(0, 0).unwrap();
    payer.sync_from_da(&[job0.da_blob.clone()]);

    let outs = [(a.key(), 10_000_000_000), (b.key(), 20_000_000_000), (c.key(), 5_000_000_000)];
    for t in payer.batch_transfer(&outs, 0, 1_000_000) {
        operator.submit_transfer(t);
    }
    let (job1, dropped) = operator.seal_resilient(1, 0).expect("seal");

    // Leg a (10) affords; leg b (20) can't (only 5 left) and is dropped; leg c chains on b's nonce
    // so it defers too, the tail moves together, never a partial mid-batch state.
    let blobs = vec![job0.da_blob, job1.da_blob];
    assert_eq!(latest_leaf(&blobs, &a.key()).unwrap().balance, 10_000_000_000, "first leg landed");
    assert_eq!(latest_leaf(&blobs, &b.key()).map(|l| l.balance).unwrap_or(0), 0, "unaffordable leg deferred");
    assert_eq!(latest_leaf(&blobs, &c.key()).map(|l| l.balance).unwrap_or(0), 0, "its successor deferred too");
    assert_eq!(dropped.len(), 2, "leg b (unaffordable) + leg c (nonce-chained) both defer");
}
