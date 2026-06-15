//! Audit finding H-1 (HTLC escrow keyspace-collision freeze), staged fix `htlc_keyspace`.
//!
//! HTLC escrows and ordinary accounts share one 256-bit SMT keyspace. Under the DEPLOYED rules a
//! signed `Transfer`/`Deposit` of as little as 1 unit into an escrow's `htlc_id` key bumps its
//! balance off `amount`, after which both claim and refund return `HtlcMissing` forever (a
//! permanent freeze), and a pre-credit at a predicted `htlc_id` blocks the lock itself (HtlcExists).
//! Under `htlc_keyspace` the lock ACCUMULATES onto any pre-existing balance and claim/refund SWEEP
//! the whole leaf (`amount` + any hostile surplus) to the htlc_id-fixed counterparty, then consume
//! it, so neither a top-up nor a front-run can freeze or block an in-pool swap, and a swept leaf
//! cannot be double-claimed. Runs under `--features htlc_keyspace`.
#![cfg(feature = "htlc_keyspace")]

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;
const PRE: &[u8] = b"liquid-cells/htlc-keyspace/secret";

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"htlc-keyspace-pool")
}
fn key_for(b: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(b)))
}

/// The active hashlock (keccak by default; sha256 if also under `htlc_sha256`).
fn hl(p: &[u8]) -> Hash {
    #[cfg(feature = "htlc_sha256")]
    {
        liquid_cells_stf::hash::sha256(p)
    }
    #[cfg(not(feature = "htlc_sha256"))]
    {
        keccak(p)
    }
}

fn funded(funding: &[(u8, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = funding.iter().map(|(b, a)| Deposit { to_key: key_for(*b), amount: *a }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    st
}

#[allow(clippy::too_many_arguments)]
fn signed_lock(sb: u8, receiver_key: Hash, amount: u128, fee: u128, hashlock: Hash, timeout: u64, nonce: u64) -> HtlcLock {
    let sk = secret(sb);
    let sender_pubkey = sig::pubkey(&sk);
    let sender_key = key_of_pubkey(&sender_pubkey);
    let msg = htlc_lock_msg(CHAIN_ID, &pool_id(), &sender_key, &receiver_key, amount, fee, &hashlock, timeout, nonce);
    let (_pk, sig) = sig::sign(&sk, &msg);
    HtlcLock { sender_pubkey, receiver_key, amount, fee, hashlock, timeout, nonce, sig }
}
fn href(sender: u8, receiver_key: Hash, amount: u128, hashlock: Hash, timeout: u64, lock_nonce: u64) -> HtlcRef {
    HtlcRef { sender_key: key_for(sender), receiver_key, amount, hashlock, timeout, lock_nonce }
}
fn id_of(amount: u128, hashlock: &Hash, timeout: u64, lock_nonce: u64) -> Hash {
    htlc_id(&pool_id(), &key_for(1), &key_for(2), amount, hashlock, timeout, lock_nonce)
}
fn conserved(st: &State) -> bool {
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    sum + st.pool.fee_acc == st.pool.total
}

#[test]
fn a_top_up_does_not_freeze_the_claim() {
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let h = hl(PRE);

    let lock = signed_lock(1, bob, amount, fee, h, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();
    let id = id_of(amount, &h, 50, 0);
    assert_eq!(st.get_leaf(&id).balance, amount);

    // Attacker tops up the escrow key with 1 unit (the freeze attempt under the deployed rules).
    apply(&mut st, &Batch { current_epoch: 1, deposits: vec![Deposit { to_key: id, amount: 1 }], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&id).balance, amount + 1);

    // Bob claims with the preimage: still succeeds, and the hostile unit is left orphaned (not frozen).
    let claim = HtlcClaim { htlc: href(1, bob, amount, h, 50, 0), preimage: PRE.to_vec() };
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob).balance, amount + 1, "the whole leaf (amount + the top-up) is swept to the receiver");
    assert_eq!(st.get_leaf(&id).balance, 0, "the escrow leaf is consumed, no recoverable surplus left");
    assert!(conserved(&st));
}

#[test]
fn a_top_up_does_not_freeze_the_refund() {
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let h = hl(PRE);

    let lock = signed_lock(1, bob, amount, fee, h, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();
    let id = id_of(amount, &h, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, deposits: vec![Deposit { to_key: id, amount: 1 }], ..Default::default() }).unwrap();

    // After timeout the sender refunds: still succeeds despite the top-up.
    let refund = HtlcRefund { htlc: href(1, bob, amount, h, 50, 0) };
    apply(&mut st, &Batch { current_epoch: 50, htlc_refunds: vec![refund], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&key_for(1)).balance, 100_000_000 - fee + 1, "the whole leaf (amount + top-up) is swept back to the sender");
    assert_eq!(st.get_leaf(&id).balance, 0, "the escrow leaf is consumed");
    assert!(conserved(&st));
}

#[test]
fn a_front_run_pre_credit_does_not_block_the_lock() {
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let h = hl(PRE);
    let id = id_of(amount, &h, 50, 0);

    // Attacker front-runs: pre-credits the PREDICTED htlc_id with 7 units before the lock exists.
    apply(&mut st, &Batch { current_epoch: 1, deposits: vec![Deposit { to_key: id, amount: 7 }], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&id).balance, 7);

    // The legitimate lock still succeeds (accumulates), it is NOT blocked by HtlcExists.
    let lock = signed_lock(1, bob, amount, fee, h, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&id).balance, amount + 7);

    // And the swap completes normally.
    let claim = HtlcClaim { htlc: href(1, bob, amount, h, 50, 0), preimage: PRE.to_vec() };
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob).balance, amount + 7, "the whole leaf (amount + the pre-credit) is swept to the receiver");
    assert_eq!(st.get_leaf(&id).balance, 0, "the escrow leaf is consumed");
    assert!(conserved(&st));
}

#[test]
fn a_repeated_claim_cannot_drain_a_topped_up_escrow() {
    // The defect the adversarial review caught in the first attempt: if claim merely DEBITED `amount`
    // (leaving a surplus) instead of sweeping the leaf, an escrow topped up to >= 2*amount could be
    // claimed twice and pay the receiver 2*amount. The sweep consumes the leaf, so a repeat (same
    // batch or later) finds it empty.
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let h = hl(PRE);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![signed_lock(1, bob, amount, fee, h, 50, 0)], ..Default::default() }).unwrap();
    let id = id_of(amount, &h, 50, 0);
    // Top up by a FULL `amount`, so the leaf holds 2*amount (the precondition for a double-claim).
    apply(&mut st, &Batch { current_epoch: 1, deposits: vec![Deposit { to_key: id, amount }], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&id).balance, 2 * amount);

    let claim = HtlcClaim { htlc: href(1, bob, amount, h, 50, 0), preimage: PRE.to_vec() };
    // Two identical claims in ONE batch must not both pay out: the second sees the swept (empty)
    // leaf, so the whole batch rejects (atomic). Under a `debit amount` rule this paid out 2*amount.
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim.clone(), claim.clone()], ..Default::default() }),
        Err(StfError::HtlcMissing),
        "two claims of one escrow in a batch cannot both succeed"
    );
    // A single claim sweeps the whole leaf once; a later repeat finds it consumed.
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim.clone()], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob).balance, 2 * amount, "the receiver is paid the whole swept leaf, exactly once");
    assert_eq!(st.get_leaf(&id).balance, 0);
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::HtlcMissing),
        "a repeated claim across batches also finds the escrow consumed"
    );
    assert!(conserved(&st));
}

#[test]
fn an_unfunded_escrow_key_still_rejects_claim_and_refund() {
    // The `>=` guard must not let a claim/refund succeed against a key that never held the escrow
    // (or holds less than `amount`): a stray small credit alone is not a claimable escrow.
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, _fee) = (5_000_000u128, 1_000u128);
    let h = hl(PRE);
    let id = id_of(amount, &h, 50, 0);
    // Only a sub-`amount` credit at the key, no real lock.
    apply(&mut st, &Batch { current_epoch: 1, deposits: vec![Deposit { to_key: id, amount: amount - 1 }], ..Default::default() }).unwrap();

    let claim = HtlcClaim { htlc: href(1, bob, amount, h, 50, 0), preimage: PRE.to_vec() };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::HtlcMissing),
        "a key holding less than `amount` is not a claimable escrow"
    );
    let refund = HtlcRefund { htlc: href(1, bob, amount, h, 50, 0) };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 50, htlc_refunds: vec![refund], ..Default::default() }),
        Err(StfError::HtlcMissing),
        "a key holding less than `amount` is not a refundable escrow"
    );
}
