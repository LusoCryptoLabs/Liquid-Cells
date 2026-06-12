//! Client SDK ⇄ STF agreement tests.
//!
//! The SDK's whole value is that it can never disagree with the sequencer or the on-chain
//! contract, because it signs and reconstructs with the *same* `liquid-cells-stf`. These tests
//! prove exactly that: every intent the client builds is accepted by the canonical STF, and
//! every recovery/exit artifact it produces verifies against the committed root the contract
//! checks.

use liquid_cells_client::*;
use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x0043_4b42;
fn pool_id() -> Hash {
    keccak(b"client-pool")
}
fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}

/// Apply a batch and return the DA blob the checkpoint would publish (post-state of touched
/// leaves), the bytes a client later reconstructs from L1.
fn apply_and_blob(st: &mut State, batch: &Batch) -> Vec<u8> {
    apply(st, batch).expect("apply");
    st.da_blob(batch)
}

fn parse_siblings(b: &[u8]) -> Vec<Hash> {
    b.chunks(32)
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect()
}

/// Re-run the contract's force-exit inclusion check on a client-built witness.
fn force_exit_includes(w: &[u8], root: &Hash) -> bool {
    assert_eq!(w.len(), FORCE_EXIT_WITNESS_LEN);
    let key = keccak(&w[0..33]); // contract uses keccak(pubkey)
    let balance = u128::from_be_bytes(w[33..49].try_into().unwrap());
    let nonce = u64::from_be_bytes(w[49..57].try_into().unwrap());
    let siblings = parse_siblings(&w[57..]);
    verify_proof(root, &key, &Leaf { balance, nonce }.hash(), &siblings)
}

#[test]
fn signed_transfer_is_accepted_by_the_stf() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    let bob = Account::new(pool_id(), CHAIN_ID, secret(2));

    apply(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: alice.key(), amount: 1_000_000 }],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(alice.nonce(), 0, "deposits do not bump the account nonce");

    let t = alice.transfer(bob.key(), 1000, 10, 100);
    assert_eq!(alice.nonce(), 1, "the client advances its own nonce on a spend");
    apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() }).unwrap();

    assert_eq!(st.get_leaf(&bob.key()).balance, 1000);
    assert_eq!(st.get_leaf(&alice.key()).balance, 1_000_000 - 1010);
    assert_eq!(st.get_leaf(&alice.key()).nonce, 1, "STF nonce matches the client's view");
}

#[test]
fn two_sequential_transfers_track_nonce() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    let bob = Account::new(pool_id(), CHAIN_ID, secret(2));
    apply(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: alice.key(), amount: 1_000_000 }],
            ..Default::default()
        },
    )
    .unwrap();

    let t1 = alice.transfer(bob.key(), 100, 1, 100); // nonce 0
    let t2 = alice.transfer(bob.key(), 200, 1, 100); // nonce 1
    apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t1, t2], ..Default::default() }).unwrap();

    assert_eq!(st.get_leaf(&bob.key()).balance, 300);
    assert_eq!(alice.nonce(), 2);
    assert_eq!(st.get_leaf(&alice.key()).nonce, 2);
}

#[test]
fn withdrawal_is_accepted_by_the_stf() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    apply(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: alice.key(), amount: 1_000_000 }],
            ..Default::default()
        },
    )
    .unwrap();
    let target = keccak(b"some-l1-lock-hash");
    let w = alice.withdraw(target, 400_000, 100);
    apply(&mut st, &Batch { current_epoch: 1, withdrawals: vec![w], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&alice.key()).balance, 600_000);
    assert_eq!(st.pool.total, 600_000, "withdrawn value left the pool");
}

#[test]
fn reconstruct_leaf_and_force_exit_witness_from_da() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    let bob = Account::new(pool_id(), CHAIN_ID, secret(2));

    let mut blobs = Vec::new();
    blobs.push(apply_and_blob(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![
                Deposit { to_key: alice.key(), amount: 1_000_000 },
                Deposit { to_key: bob.key(), amount: 5 },
            ],
            ..Default::default()
        },
    ));
    let t = alice.transfer(bob.key(), 1000, 10, 100);
    blobs.push(apply_and_blob(
        &mut st,
        &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() },
    ));

    // Recover Alice's leaf from L1 DA alone (no sequencer), and verify its inclusion proof.
    let (leaf, siblings) = proof_from_da(&blobs, &alice.key()).unwrap();
    assert_eq!(leaf, st.get_leaf(&alice.key()), "DA reconstruction recovers the true leaf");
    assert!(verify_proof(&st.pool.root, &alice.key(), &leaf.hash(), &siblings));

    // sync_from_da resets the local nonce to the authoritative L1 value...
    let lp = alice.sync_from_da(&blobs).unwrap();
    assert_eq!(lp.leaf, st.get_leaf(&alice.key()));
    assert_eq!(alice.nonce(), st.get_leaf(&alice.key()).nonce);

    // ...and the force-exit witness the client builds includes against the committed root, 
    // exactly the check the on-chain force-exit mode performs.
    let w = alice.force_exit_witness(&blobs).unwrap();
    assert!(force_exit_includes(&w, &st.pool.root), "client force-exit witness must verify on-chain");
}

#[test]
fn htlc_lock_and_force_refund_witness_from_da() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    let bob = Account::new(pool_id(), CHAIN_ID, secret(2));

    let mut blobs = Vec::new();
    blobs.push(apply_and_blob(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: alice.key(), amount: 1_000_000 }],
            ..Default::default()
        },
    ));

    let hashlock = keccak(b"client-preimage");
    let (lock, r) = alice.htlc_lock(bob.key(), 5000, 1, hashlock, 50);
    blobs.push(apply_and_blob(
        &mut st,
        &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() },
    ));

    // The client builds a valid force-refund witness for its own timed-out escrow, and the
    // escrow leaf includes against the committed root (mirrors the contract's force-refund mode).
    let w = alice.force_refund_witness(&blobs, &r).unwrap();
    assert_eq!(w.len(), FORCE_REFUND_WITNESS_LEN);
    let id = htlc_id(&pool_id(), &r.sender_key, &r.receiver_key, r.amount, &r.hashlock, r.timeout, r.lock_nonce);
    let siblings = parse_siblings(&w[129..]);
    assert!(verify_proof(&st.pool.root, &id, &Leaf { balance: 5000, nonce: 0 }.hash(), &siblings));

    // A claim the client builds round-trips through the STF (cooperative path).
    let claim = htlc_claim(r, b"client-preimage".to_vec());
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob.key()).balance, 5000, "preimage claim pays the receiver");
}

#[test]
fn force_refund_witness_rejects_a_foreign_htlc() {
    // An HtlcRef whose sender is not this account yields no witness, a client can only
    // force-refund its own escrows.
    let alice = Account::new(pool_id(), CHAIN_ID, secret(1));
    let foreign = HtlcRef {
        sender_key: keccak(b"not-alice"),
        receiver_key: keccak(b"someone"),
        amount: 1,
        hashlock: keccak(b"h"),
        timeout: 1,
        lock_nonce: 0,
    };
    assert!(alice.force_refund_witness(&[], &foreign).is_none());
}
