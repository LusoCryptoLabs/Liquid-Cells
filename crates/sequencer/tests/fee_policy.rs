//! Fee-admission policy: the sequencer's defence against zero-fee griefing. The strict
//! `seal_batch` rejects a batch with any underpayer; the resilient `seal_resilient` drops just
//! the underpayers and seals the rest. A disabled policy (the default) changes nothing.
use liquid_cells_sequencer::{DroppedOp, FeePolicy, Sequencer};
use liquid_cells_stf::*;

const CHAIN: u64 = 0x434b_42;
const FLOOR: u128 = 100;

fn pool() -> Hash {
    keccak(b"fee-policy-pool")
}
fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn key(n: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}
fn xfer(from: u8, to: Hash, amount: u128, fee: u128, nonce: u64) -> Transfer {
    let sk = secret(from);
    let pk = sig::pubkey(&sk);
    let fk = key_of_pubkey(&pk);
    let msg = transfer_msg(CHAIN, &pool(), &fk, &to, amount, fee, nonce, 1_000_000);
    let (_p, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey: pk, to_key: to, amount, fee, nonce, expiry: 1_000_000, sig }
}
fn lock(from: u8, receiver: Hash, amount: u128, fee: u128, nonce: u64) -> HtlcLock {
    let sk = secret(from);
    let pk = sig::pubkey(&sk);
    let sender_key = key_of_pubkey(&pk);
    let hashlock = keccak(b"x");
    let msg = htlc_lock_msg(CHAIN, &pool(), &sender_key, &receiver, amount, fee, &hashlock, 1_000_000, nonce);
    let (_p, sig) = sig::sign(&sk, &msg);
    HtlcLock { sender_pubkey: pk, receiver_key: receiver, amount, fee, hashlock, timeout: 1_000_000, nonce, sig }
}
/// A sequencer with account `from` funded with `amount` and the given fee policy.
fn funded(from: u8, amount: u128, policy: FeePolicy) -> Sequencer {
    let mut s = Sequencer::genesis(pool(), CHAIN).with_fee_policy(policy);
    s.submit_deposit(Deposit { to_key: key(from), amount });
    s.seal_batch(0, 0).expect("fund"); // deposits carry no fee, so the floor never blocks funding
    s
}

#[test]
fn strict_seal_rejects_an_underpayer_and_keeps_the_mempool() {
    let mut s = funded(1, 1_000_000, FeePolicy::new(FLOOR));
    s.submit_transfer(xfer(1, key(2), 1000, FLOOR - 1, 0)); // underpays
    let err = s.seal_batch(1, 0).unwrap_err();
    assert_eq!(err, StfError::InsufficientFees);
    // Atomic: the offending intent is still pending so the operator can drop/retry it.
    assert_eq!(s.pending(), 1);
    assert_eq!(s.seq(), 1, "no checkpoint advanced");
}

#[test]
fn strict_seal_accepts_a_batch_at_the_floor() {
    let mut s = funded(1, 1_000_000, FeePolicy::new(FLOOR));
    s.submit_transfer(xfer(1, key(2), 1000, FLOOR, 0)); // exactly the floor
    s.seal_batch(1, 0).expect("a batch paying the floor must seal");
    assert_eq!(s.fee_acc(), FLOOR);
}

#[test]
fn resilient_seal_drops_only_the_underpayers() {
    let mut s = funded(1, 1_000_000, FeePolicy::new(FLOOR));
    s.submit_transfer(xfer(1, key(2), 1000, FLOOR, 0)); // ok        -> key(1) nonce 0->1
    s.submit_transfer(xfer(1, key(3), 1000, FLOOR - 1, 1)); // underpays -> dropped (nonce unspent)
    s.submit_transfer(xfer(1, key(4), 1000, FLOOR, 1)); // ok        -> reuses nonce 1, key(1) 1->2
    let (job, dropped) = s.seal_resilient(1, 0).expect("resilient seals the rest");
    assert_eq!(dropped.len(), 1, "only the underpayer is dropped");
    assert_eq!(dropped[0].op, DroppedOp::Transfer(1));
    assert_eq!(dropped[0].error, StfError::InsufficientFees);
    // The two floor-paying transfers applied; revenue is exactly 2 × FLOOR.
    assert_eq!(s.fee_acc(), 2 * FLOOR);
    assert_eq!(job.new_seq(), 2);
}

#[test]
fn underpaying_htlc_lock_is_dropped_too() {
    let mut s = funded(1, 1_000_000, FeePolicy::new(FLOOR));
    s.submit_htlc_lock(lock(1, key(2), 1000, FLOOR - 1, 0)); // underpays
    let (_job, dropped) = s.seal_resilient(1, 0).expect("seals empty-but-valid");
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].op, DroppedOp::HtlcLock(0));
    assert_eq!(dropped[0].error, StfError::InsufficientFees);
    assert_eq!(s.fee_acc(), 0, "nothing paid in");
}

#[test]
fn a_dropped_underpayer_transitively_defers_its_dependent() {
    // key(2) is funded only by the underpaying (dropped) transfer, so its own spend can't fund and
    // defers — the same transitive-deferral guarantee, now driven by a fee drop.
    let mut s = funded(1, 1_000_000, FeePolicy::new(FLOOR));
    s.submit_transfer(xfer(1, key(2), 5000, FLOOR - 1, 0)); // underpays -> dropped, key(2) uncredited
    s.submit_transfer(xfer(2, key(3), 1000, FLOOR, 0)); // depends on key(2)'s credit -> defers
    let (_job, dropped) = s.seal_resilient(1, 0).expect("seal");
    assert_eq!(dropped.len(), 2);
    assert_eq!(dropped[0].op, DroppedOp::Transfer(0));
    assert_eq!(dropped[0].error, StfError::InsufficientFees);
    assert_eq!(dropped[1].op, DroppedOp::Transfer(1));
    assert_eq!(dropped[1].error, StfError::InsufficientBalance); // dependent couldn't fund
}

#[test]
fn disabled_policy_is_a_no_op() {
    // The default sequencer (no policy) admits zero-fee intents exactly as before.
    let mut s = funded(1, 1_000_000, FeePolicy::disabled());
    s.submit_transfer(xfer(1, key(2), 1000, 0, 0));
    s.seal_batch(1, 0).expect("zero-fee transfer admitted with no policy");
    assert_eq!(s.fee_acc(), 0);
}
