//! Resilient sealing: one bad signed intent drops out instead of failing the whole checkpoint,
//! dependents defer transitively, and the result stays identical to `seal_batch` when all-valid.
use liquid_cells_sequencer::{DroppedOp, Sequencer};
use liquid_cells_stf::*;

const CHAIN: u64 = 0x434b_42;
fn pool() -> Hash {
    keccak(b"resilient-pool")
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
/// A sequencer with account `from` funded with `amount` (sealed into checkpoint 1).
fn funded(from: u8, amount: u128) -> Sequencer {
    let mut s = Sequencer::genesis(pool(), CHAIN);
    s.submit_deposit(Deposit { to_key: key(from), amount });
    s.seal_batch(0, 0).expect("fund");
    s
}

#[test]
fn poison_intent_in_the_middle_seals_the_rest() {
    let mut s = funded(1, 1_000_000_000);
    s.submit_transfer(xfer(1, key(2), 1000, 0, 0)); // ok  -> nonce 1
    s.submit_transfer(xfer(1, key(3), 1000, 0, 9)); // BAD nonce (expects 1) -> dropped
    s.submit_transfer(xfer(1, key(4), 1000, 0, 1)); // ok  -> nonce 2
    let (job, dropped) = s.seal_resilient(0, 0).expect("resilient seal");
    assert_eq!(dropped.len(), 1, "exactly the mis-nonced transfer is dropped");
    assert_eq!(dropped[0].op, DroppedOp::Transfer(1));
    assert_eq!(dropped[0].error, StfError::BadNonce);
    assert_eq!(job.new_seq(), 2); // genesis(0) -> fund(1) -> this(2)
    // the two good transfers applied: key(1) nonce advanced to 2.
    assert_eq!(s.pool().total, 1_000_000_000); // transfers don't change total (fee 0)
}

#[test]
fn plain_seal_batch_would_have_failed_the_whole_checkpoint() {
    // same batch, but the atomic seal_batch rejects everything on the one bad intent.
    let mut s = funded(1, 1_000_000_000);
    s.submit_transfer(xfer(1, key(2), 1000, 0, 0));
    s.submit_transfer(xfer(1, key(3), 1000, 0, 9)); // bad nonce
    s.submit_transfer(xfer(1, key(4), 1000, 0, 1));
    assert_eq!(s.seal_batch(0, 0).unwrap_err(), StfError::BadNonce, "atomic seal fails closed");
    // mempool intact after the failed atomic seal — resilient seal then salvages the good ones.
    let (_job, dropped) = s.seal_resilient(0, 0).expect("resilient salvages");
    assert_eq!(dropped.len(), 1);
}

#[test]
fn dependent_of_a_dropped_funder_defers_transitively() {
    // A is funded; B is not. A->B would fund B->C. If A->B is dropped, B->C must also drop
    // (B never received), proving we defer dependents rather than strand them.
    let mut s = funded(1, 1_000_000_000);
    s.submit_transfer(xfer(1, key(2), 500_000, 0, 9)); // A->B, BAD nonce -> dropped (B unfunded)
    s.submit_transfer(xfer(2, key(3), 400_000, 0, 0)); // B->C, needs B's receipt -> must defer
    let (_job, dropped) = s.seal_resilient(0, 0).expect("seal");
    assert_eq!(dropped.len(), 2, "funder dropped, dependent transitively deferred");
    assert_eq!(dropped[0].op, DroppedOp::Transfer(0));
    assert_eq!(dropped[1].error, StfError::InsufficientBalance); // B->C had no funds
}

#[test]
fn all_valid_batch_is_identical_to_seal_batch() {
    // parity: with no bad intents, seal_resilient must produce the same checkpoint as seal_batch.
    let build = |resilient: bool| {
        let mut s = funded(1, 1_000_000_000);
        s.submit_transfer(xfer(1, key(2), 1000, 0, 0));
        s.submit_transfer(xfer(1, key(3), 2000, 0, 1));
        if resilient {
            let (j, d) = s.seal_resilient(0, 0).unwrap();
            assert!(d.is_empty(), "nothing dropped when all valid");
            j
        } else {
            s.seal_batch(0, 0).unwrap()
        }
    };
    let a = build(false);
    let b = build(true);
    assert_eq!(a.new_root(), b.new_root(), "same committed root");
    assert_eq!(a.new_seq(), b.new_seq());
    assert_eq!(a.sp1_input, b.sp1_input, "byte-identical guest input");
}

#[test]
fn batch_wide_failure_still_fails_closed() {
    // fee_withdrawal exceeding the accepted batch's fee revenue is not one intent's fault -> Err.
    let mut s = funded(1, 1_000_000_000);
    s.submit_transfer(xfer(1, key(2), 1000, 100, 0)); // contributes fee 100
    // ask to withdraw more fees than were collected -> seal_batch rejects -> resilient propagates.
    assert!(s.seal_resilient(0, 10_000).is_err(), "fee_withdrawal > revenue fails closed");
}
