//! Staged `min_fee` in-proof floor. These tests compile only with `--features min_fee` (the
//! feature that is deliberately OFF in the deployed guest, so it does not touch the vkey). They
//! prove the floor, once flipped on at a coordinated upgrade, makes "every fee-paying intent
//! contributes ≥ MIN_FEE_PER_LEAF" an unforgeable, proven invariant, not just operator policy.
//!
//! Run: `cargo test -p liquid-cells-stf --features min_fee --test min_fee` (this file only). The
//! *rest* of the stf suite is written against the deployed, floor-OFF rule (it uses zero-fee
//! transfers), so running the whole package with `--features min_fee` is not a supported config,
//! the floor is a behaviour change, validated here in isolation.
#![cfg(feature = "min_fee")]

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"min-fee-pool")
}
fn key_for(b: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(b)))
}
fn signed_transfer(b: u8, to_key: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(b);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to_key, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key, amount, fee, nonce, expiry, sig }
}
fn signed_htlc_lock(
    b: u8,
    receiver_key: Hash,
    amount: u128,
    fee: u128,
    nonce: u64,
    timeout: u64,
) -> HtlcLock {
    let sk = secret(b);
    let sender_pubkey = sig::pubkey(&sk);
    let sender_key = key_of_pubkey(&sender_pubkey);
    let hashlock = keccak(b"preimage");
    let msg = htlc_lock_msg(
        CHAIN_ID, &pool_id(), &sender_key, &receiver_key, amount, fee, &hashlock, timeout, nonce,
    );
    let (_pk, sig) = sig::sign(&sk, &msg);
    HtlcLock { sender_pubkey, receiver_key, amount, fee, hashlock, timeout, nonce, sig }
}
fn funded_state(funding: &[(u8, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = funding.iter().map(|(b, a)| Deposit { to_key: key_for(*b), amount: *a }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    st
}
fn conserved(st: &State) -> bool {
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    sum.checked_add(st.pool.fee_acc) == Some(st.pool.total)
}

#[test]
fn the_floor_is_positive() {
    // A zero floor would make this feature a no-op; the staged value must actually bite.
    assert!(MIN_FEE_PER_LEAF >= 1, "the staged per-intent floor must be positive");
}

#[test]
fn transfer_below_floor_rejects() {
    let mut st = funded_state(&[(1, 1_000)]);
    // fee one below the floor: a valid, funded, correctly-signed transfer that underpays.
    let t = signed_transfer(1, key_for(2), 10, MIN_FEE_PER_LEAF - 1, 0, 100);
    let err = apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() })
        .unwrap_err();
    assert_eq!(err, StfError::FeeBelowMinimum);
    // Atomic: the underpaying batch advanced nothing.
    assert_eq!(st.pool.seq, 1, "genesis deposit was the only applied batch");
}

#[test]
fn transfer_at_floor_accepts() {
    let mut st = funded_state(&[(1, 1_000)]);
    let t = signed_transfer(1, key_for(2), 10, MIN_FEE_PER_LEAF, 0, 100);
    apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() })
        .expect("a transfer paying exactly the floor must apply");
    assert_eq!(st.pool.fee_acc, MIN_FEE_PER_LEAF);
    assert!(conserved(&st));
}

#[test]
fn htlc_lock_below_floor_rejects() {
    let mut st = funded_state(&[(1, 1_000)]);
    let l = signed_htlc_lock(1, key_for(2), 10, MIN_FEE_PER_LEAF - 1, 0, 100);
    let err =
        apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![l], ..Default::default() })
            .unwrap_err();
    assert_eq!(err, StfError::FeeBelowMinimum);
}

#[test]
fn htlc_lock_at_floor_accepts() {
    let mut st = funded_state(&[(1, 1_000)]);
    let l = signed_htlc_lock(1, key_for(2), 10, MIN_FEE_PER_LEAF, 0, 100);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![l], ..Default::default() })
        .expect("an HTLC-lock paying exactly the floor must apply");
    assert_eq!(st.pool.fee_acc, MIN_FEE_PER_LEAF);
    assert!(conserved(&st));
}

#[test]
fn one_underpayer_fails_the_whole_atomic_batch() {
    // In the *atomic* seal an underpayer rejects the batch (the resilient seal/FeePolicy is what
    // drops just the underpayer; here we pin the proven all-or-nothing semantics).
    let mut st = funded_state(&[(1, 1_000), (2, 1_000)]);
    let ok = signed_transfer(1, key_for(3), 10, MIN_FEE_PER_LEAF, 0, 100);
    let bad = signed_transfer(2, key_for(3), 10, MIN_FEE_PER_LEAF - 1, 0, 100);
    let err = apply(
        &mut st,
        &Batch { current_epoch: 1, transfers: vec![ok, bad], ..Default::default() },
    )
    .unwrap_err();
    assert_eq!(err, StfError::FeeBelowMinimum);
    // Nothing folded: the good transfer did not apply either.
    assert_eq!(st.pool.fee_acc, 0);
}
