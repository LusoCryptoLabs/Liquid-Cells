//! In-pool HTLC tests, the building block for trustless atomic-swap egress of dust.
//!
//! A swap moves an in-pool dust balance to a liquidity provider in exchange for an L1/Fiber
//! payment, atomically, via a shared hash preimage. Here we exercise the *in-pool* leg: a
//! sender escrows funds under a hashlock+timeout (`htlc_lock`), the receiver claims by
//! revealing the preimage before the timeout (`htlc_claim`), or the sender refunds after it
//! (`htlc_refund`). The escrow is keyed by `htlc_id`, which commits to every lock term, so
//! funds can only resolve to the agreed parties, and the escrow removes them from the
//! sender's spendable balance, so there is no double-spend.

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"htlc-pool")
}
fn key_for(b: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(b)))
}

fn funded_state(funding: &[(u8, u128)]) -> State {
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

const PRE: &[u8] = b"liquid-cells/atomic-swap/preimage";
fn hashlock() -> Hash {
    keccak(PRE)
}

#[test]
fn htlc_lock_then_claim_completes_the_swap() {
    let mut st = funded_state(&[(1, 100_000_000)]); // Alice
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128); // dust amount (< 61 CKB)

    // Alice escrows 5M to Bob under the hashlock, with a future timeout.
    let lock = signed_lock(1, bob, amount, fee, hashlock(), 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    // Escrow took the funds out of Alice's spendable balance immediately.
    assert_eq!(st.get_leaf(&key_for(1)).balance, 100_000_000 - amount - fee);
    assert_eq!(st.get_leaf(&bob).balance, 0);
    assert_eq!(st.pool.fee_acc, fee);
    assert_eq!(st.pool.total, 100_000_000); // value never left the pool

    // Anyone revealing the preimage before the timeout pays Bob (the fixed receiver).
    let claim = HtlcClaim { htlc: href(1, bob, amount, hashlock(), 50, 0), preimage: PRE.to_vec() };
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();

    assert_eq!(st.get_leaf(&bob).balance, amount);
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    assert_eq!(sum + st.pool.fee_acc, st.pool.total); // conservation across the whole swap
}

#[test]
fn htlc_refund_after_timeout_returns_to_sender() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128);
    let lock = signed_lock(1, bob, amount, fee, hashlock(), 10, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    // No claim; after the timeout Alice reclaims the escrowed amount.
    let refund = HtlcRefund { htlc: href(1, bob, amount, hashlock(), 10, 0) };
    apply(&mut st, &Batch { current_epoch: 10, htlc_refunds: vec![refund], ..Default::default() }).unwrap();

    // Alice is whole except the fee she paid to lock.
    assert_eq!(st.get_leaf(&key_for(1)).balance, 100_000_000 - fee);
    assert_eq!(st.get_leaf(&bob).balance, 0);
}

#[test]
fn htlc_wrong_preimage_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let lock = signed_lock(1, bob, 5_000_000, 1_000, hashlock(), 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let claim = HtlcClaim {
        htlc: href(1, bob, 5_000_000, hashlock(), 50, 0),
        preimage: b"not-the-secret".to_vec(),
    };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::BadPreimage)
    );
}

#[test]
fn htlc_claim_after_timeout_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let lock = signed_lock(1, bob, 5_000_000, 1_000, hashlock(), 10, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let claim = HtlcClaim { htlc: href(1, bob, 5_000_000, hashlock(), 10, 0), preimage: PRE.to_vec() };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 10, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::HtlcExpired)
    );
}

#[test]
fn htlc_refund_before_timeout_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let lock = signed_lock(1, bob, 5_000_000, 1_000, hashlock(), 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let refund = HtlcRefund { htlc: href(1, bob, 5_000_000, hashlock(), 50, 0) };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 9, htlc_refunds: vec![refund], ..Default::default() }),
        Err(StfError::HtlcNotExpired)
    );
}

#[test]
fn htlc_id_binds_the_receiver() {
    // Escrow to Bob; a claim that names a different receiver addresses a different htlc_id,
    // where there is no escrow, so the sequencer cannot redirect the funds.
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let lock = signed_lock(1, bob, 5_000_000, 1_000, hashlock(), 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let carol = key_for(3);
    let claim = HtlcClaim { htlc: href(1, carol, 5_000_000, hashlock(), 50, 0), preimage: PRE.to_vec() };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::HtlcMissing)
    );
}

#[test]
fn htlc_lock_removes_funds_from_spendable_balance() {
    // The escrowed amount is no longer in the sender's account, so it can't be double-spent
    // (e.g. force-exited or transferred) while the swap is pending.
    let mut st = funded_state(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let lock = signed_lock(1, bob, 40_000_000, 1_000, hashlock(), 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    // Alice now has < 100M spendable; a transfer of 70M (covered by the original balance but
    // not after escrow) must fail.
    let sk = secret(1);
    let from_key = key_for(1);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &key_for(2), 70_000_000, 0, 1, 100);
    let (_pk, sig) = sig::sign(&sk, &msg);
    let t = Transfer { from_pubkey: sig::pubkey(&sk), to_key: key_for(2), amount: 70_000_000, fee: 0, nonce: 1, expiry: 100, sig };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, transfers: vec![t], ..Default::default() }),
        Err(StfError::InsufficientBalance)
    );
}
