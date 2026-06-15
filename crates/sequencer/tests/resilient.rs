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
    // mempool intact after the failed atomic seal, resilient seal then salvages the good ones.
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

#[cfg(feature = "htlc_keyspace")]
#[test]
fn resilient_seal_does_not_drop_an_h1_recovery_claim() {
    // Under htlc_keyspace the claim of a topped-up escrow is VALID in the proven STF, so
    // seal_resilient (which re-validates each intent) must mirror apply_ops and NOT drop it. This
    // pins that resilient.rs is gated to the same rules; on the deployed rules it would drop the
    // claim (escrow.balance != amount), defeating the H-1 recovery on the resilient cadence.
    use liquid_cells_stf::{htlc_id, htlc_lock_msg, HtlcClaim, HtlcLock, HtlcRef};
    let mut s = funded(1, 100_000_000);
    let bob = key(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    // The hashlock must use the SAME hash the active config locks with, else the claim is
    // legitimately unclaimable: keccak by default, sha256 under htlc_sha256 (the re-bake bundle
    // enables both). Using keccak unconditionally would build an unclaimable HTLC under the bundle.
    #[cfg(not(feature = "htlc_sha256"))]
    let h = keccak(b"recovery");
    #[cfg(feature = "htlc_sha256")]
    let h = liquid_cells_stf::hash::sha256(b"recovery");
    let sk = secret(1);
    let pk = sig::pubkey(&sk);
    let ak = key_of_pubkey(&pk);
    let msg = htlc_lock_msg(CHAIN, &pool(), &ak, &bob, amount, fee, &h, 50, 0);
    let (_p, sig) = sig::sign(&sk, &msg);
    s.submit_htlc_lock(HtlcLock { sender_pubkey: pk, receiver_key: bob, amount, fee, hashlock: h, timeout: 50, nonce: 0, sig });
    s.seal_batch(1, 0).expect("lock seals");

    let id = htlc_id(&pool(), &ak, &bob, amount, &h, 50, 0);
    s.submit_deposit(Deposit { to_key: id, amount: 1 }); // hostile top-up of the escrow key
    s.seal_batch(2, 0).expect("top-up seals");

    let claim = HtlcClaim {
        htlc: HtlcRef { sender_key: ak, receiver_key: bob, amount, hashlock: h, timeout: 50, lock_nonce: 0 },
        preimage: b"recovery".to_vec(),
    };
    s.submit_htlc_claim(claim);
    let (_job, dropped) = s.seal_resilient(3, 0).expect("resilient seal");
    assert!(dropped.is_empty(), "the H-1-recovery claim must NOT be dropped by seal_resilient");
}

#[cfg(feature = "htlc_sha256")]
#[test]
fn resilient_seal_settles_a_sha256_locked_claim() {
    // Audit A-1 regression. Under htlc_sha256 the HTLC hashlock is sha256(preimage) (the
    // Fiber-compatible egress hash, NOT keccak). seal_resilient re-validates each intent and MUST
    // mirror the proven STF's claim check, hashing with sha256; otherwise it computes
    // keccak(preimage) != sha256(preimage) and drops every valid sha256 claim as BadPreimage,
    // silently breaking the Fiber dust-egress leg on the resilient cadence. The existing
    // htlc_keyspace parity test cannot catch this (it uses a keccak hashlock), so this pins the
    // sha256 axis on its own (no htlc_keyspace needed: an exact-amount escrow claims under deployed
    // rules too, only the hash differs).
    use liquid_cells_stf::{hash::sha256, htlc_lock_msg, HtlcClaim, HtlcLock, HtlcRef};
    let mut s = funded(1, 100_000_000);
    let bob = key(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let preimage = b"fiber-egress-secret".to_vec();
    let h = sha256(&preimage); // a Fiber-style sha256 hashlock, not keccak
    let sk = secret(1);
    let pk = sig::pubkey(&sk);
    let ak = key_of_pubkey(&pk);
    let msg = htlc_lock_msg(CHAIN, &pool(), &ak, &bob, amount, fee, &h, 50, 0);
    let (_p, sig) = sig::sign(&sk, &msg);
    s.submit_htlc_lock(HtlcLock { sender_pubkey: pk, receiver_key: bob, amount, fee, hashlock: h, timeout: 50, nonce: 0, sig });
    s.seal_batch(1, 0).expect("lock seals");

    let claim = HtlcClaim {
        htlc: HtlcRef { sender_key: ak, receiver_key: bob, amount, hashlock: h, timeout: 50, lock_nonce: 0 },
        preimage,
    };
    s.submit_htlc_claim(claim);
    let (_job, dropped) = s.seal_resilient(2, 0).expect("resilient seal");
    assert!(dropped.is_empty(), "a valid sha256-locked claim must NOT be dropped by seal_resilient (A-1)");
}
