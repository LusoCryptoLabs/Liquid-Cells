//! Property tests for the state-transition function.
//!
//! These pin the two safety invariants (no debit without signature; value
//! conservation) plus replay protection, expiry, and SMT proof correctness.

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42; // "CKB"

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n; // small nonzero secret, fine for tests
    s
}

fn pool_id() -> Hash {
    keccak(b"test-pool")
}

fn key_for(secret_byte: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(secret_byte)))
}

#[allow(clippy::too_many_arguments)]
fn signed_transfer(
    secret_byte: u8,
    to_key: Hash,
    amount: u128,
    fee: u128,
    nonce: u64,
    expiry: u64,
) -> Transfer {
    let sk = secret(secret_byte);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to_key, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key, amount, fee, nonce, expiry, sig }
}

fn signed_withdrawal(
    secret_byte: u8,
    target_lock_hash: Hash,
    amount: u128,
    nonce: u64,
    expiry: u64,
) -> Withdrawal {
    let sk = secret(secret_byte);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target_lock_hash, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash, amount, nonce, expiry, sig }
}

fn funded_state(funding: &[(u8, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = funding
        .iter()
        .map(|(b, amt)| Deposit { to_key: key_for(*b), amount: *amt })
        .collect();
    let batch =
        Batch { current_epoch: 0, deposits, transfers: vec![], withdrawals: vec![], fee_withdrawal: 0 };
    apply(&mut st, &batch).expect("funding deposit applies");
    st
}

#[test]
fn happy_path_transfer_moves_balance_and_advances_root() {
    let mut st = funded_state(&[(1, 100_000_000)]); // Alice = 1 CKB
    let root_before = st.pool.root;
    let seq_before = st.pool.seq;

    let bob = key_for(2);
    let t = signed_transfer(1, bob, 25_000_000, 1_000, 0, 100);
    let batch = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    let pv = apply(&mut st, &batch).expect("transfer applies");

    assert_eq!(st.get_leaf(&key_for(1)).balance, 100_000_000 - 25_000_000 - 1_000);
    assert_eq!(st.get_leaf(&key_for(1)).nonce, 1);
    assert_eq!(st.get_leaf(&bob).balance, 25_000_000);
    assert_eq!(st.pool.fee_acc, 1_000);
    assert_ne!(st.pool.root, root_before);
    assert_eq!(st.pool.seq, seq_before + 1);
    assert_eq!(pv.new_root, st.pool.root);
    assert_eq!(pv.prev_root, root_before);
}

#[test]
fn no_debit_without_valid_signature() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let mut t = signed_transfer(1, key_for(2), 10_000_000, 0, 0, 100);
    t.sig[0] ^= 0xff; // corrupt the signature
    let batch = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::BadSignature));
}

#[test]
fn tampering_amount_after_signing_is_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let mut t = signed_transfer(1, key_for(2), 10_000_000, 0, 0, 100);
    t.amount = 90_000_000; // signature no longer covers this amount
    let batch = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::BadSignature));
}

#[test]
fn replay_is_rejected_by_nonce() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let t = signed_transfer(1, key_for(2), 10_000_000, 0, 0, 100);
    let b1 = Batch { current_epoch: 1, transfers: vec![t.clone()], ..Default::default() };
    apply(&mut st, &b1).expect("first applies");
    // Replaying the identical (nonce 0) intent must fail; the leaf is now at nonce 1.
    let b2 = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &b2), Err(StfError::BadNonce));
}

#[test]
fn insufficient_balance_is_rejected() {
    let mut st = funded_state(&[(1, 1_000)]);
    let t = signed_transfer(1, key_for(2), 10_000_000, 0, 0, 100);
    let batch = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::InsufficientBalance));
}

#[test]
fn self_transfer_is_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let t = signed_transfer(1, key_for(1), 1, 0, 0, 100); // to == from
    let batch = Batch { current_epoch: 1, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::SelfTransfer));
}

#[test]
fn expired_intent_is_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let t = signed_transfer(1, key_for(2), 1_000, 0, 0, 5); // expiry 5
    let batch = Batch { current_epoch: 6, transfers: vec![t], ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::Expired));
}

#[test]
fn withdrawal_leaves_pool_and_conserves_value() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let total_before = st.pool.total;
    let target = keccak(b"alice-l1-lock");
    let w = signed_withdrawal(1, target, 40_000_000, 0, 100);
    let batch = Batch { current_epoch: 1, withdrawals: vec![w], ..Default::default() };
    let pv = apply(&mut st, &batch).expect("withdrawal applies");

    assert_eq!(st.get_leaf(&key_for(1)).balance, 60_000_000);
    assert_eq!(st.pool.total, total_before - 40_000_000);
    assert_eq!(pv.new_total, total_before - 40_000_000);
    // Commitment binds target + amount in order.
    let expected = {
        let mut acc = domain_withdrawals();
        let mut b = [0u8; 80];
        b[..32].copy_from_slice(&acc);
        b[32..64].copy_from_slice(&target);
        b[64..].copy_from_slice(&40_000_000u128.to_be_bytes());
        acc = keccak(&b);
        acc
    };
    assert_eq!(pv.withdrawals_commitment, expected);
}

#[test]
fn l1_fee_withdrawal_draws_only_from_accumulated_fees() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    let total_before = st.pool.total;
    let alice_before = st.get_leaf(&key_for(1)).balance;

    // Alice pays Bob with a 1_000 in-pool fee; the sequencer draws 600 of that fee to
    // fund the L1 miner fee, leaving 400 as fee revenue.
    let t = signed_transfer(1, key_for(2), 25_000_000, 1_000, 0, 100);
    let batch = Batch { current_epoch: 1, transfers: vec![t], fee_withdrawal: 600, ..Default::default() };
    let pv = apply(&mut st, &batch).expect("fee draw applies");

    // The draw reduces `total` and `fee_acc` by the same 600; user balances are untouched
    // by it (Alice only lost amount + the in-pool fee she signed for).
    assert_eq!(pv.fee_withdrawal, 600);
    assert_eq!(st.pool.total, total_before - 600);
    assert_eq!(pv.new_total, total_before - 600);
    assert_eq!(st.pool.fee_acc, 1_000 - 600);
    assert_eq!(st.get_leaf(&key_for(1)).balance, alice_before - 25_000_000 - 1_000);
    assert_eq!(st.get_leaf(&key_for(2)).balance, 25_000_000);

    // The conservation relation still holds after the draw.
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    assert_eq!(sum + st.pool.fee_acc, st.pool.total);
}

#[test]
fn over_drawing_l1_fee_is_rejected() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    // Only 1_000 of fee revenue accrues this batch (fee_acc starts at 0), so a 5_000
    // draw must be rejected — the sequencer cannot reach into user balances.
    let t = signed_transfer(1, key_for(2), 25_000_000, 1_000, 0, 100);
    let batch = Batch { current_epoch: 1, transfers: vec![t], fee_withdrawal: 5_000, ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::InsufficientFees));
}

#[test]
fn conservation_holds_across_a_mixed_batch() {
    // Alice 5 CKB, Bob 2 CKB.
    let mut st = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let transfers = vec![
        signed_transfer(1, key_for(2), 100_000_000, 500, 0, 100), // Alice -> Bob
        signed_transfer(2, key_for(3), 50_000_000, 250, 0, 100),  // Bob -> Carol
    ];
    let withdrawals = vec![signed_withdrawal(1, keccak(b"l1"), 30_000_000, 1, 100)];
    let batch = Batch { current_epoch: 1, transfers, withdrawals, ..Default::default() };
    apply(&mut st, &batch).expect("mixed batch applies");

    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    assert_eq!(sum + st.pool.fee_acc, st.pool.total);
}

#[test]
fn smt_proof_membership_and_nonmembership() {
    let mut st = funded_state(&[(1, 100_000_000)]);
    // Move once so Alice has a non-trivial leaf and a sibling exists.
    let t = signed_transfer(1, key_for(2), 1_000_000, 0, 0, 100);
    apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() }).unwrap();

    let root = st.pool.root;

    // Membership: Alice's leaf proves against the root.
    let alice_key = key_for(1);
    let alice_leaf = st.get_leaf(&alice_key).hash();
    let proof = st.smt.proof(&alice_key);
    assert!(verify_proof(&root, &alice_key, &alice_leaf, &proof));

    // Wrong leaf value must fail.
    assert!(!verify_proof(&root, &alice_key, &keccak(b"wrong"), &proof));

    // Non-membership: an unused key proves as the empty leaf.
    let ghost = key_for(99);
    let gproof = st.smt.proof(&ghost);
    assert!(verify_proof(&root, &ghost, &smt::EMPTY_LEAF, &gproof));
}

#[test]
fn deposits_commitment_is_order_sensitive() {
    let st_a = {
        let mut s = State::genesis(pool_id(), CHAIN_ID);
        let b = Batch {
            current_epoch: 0,
            deposits: vec![
                Deposit { to_key: key_for(1), amount: 1 },
                Deposit { to_key: key_for(2), amount: 2 },
            ],
            ..Default::default()
        };
        (apply(&mut s, &b).unwrap().deposits_commitment, ())
    };
    let st_b = {
        let mut s = State::genesis(pool_id(), CHAIN_ID);
        let b = Batch {
            current_epoch: 0,
            deposits: vec![
                Deposit { to_key: key_for(2), amount: 2 },
                Deposit { to_key: key_for(1), amount: 1 },
            ],
            ..Default::default()
        };
        (apply(&mut s, &b).unwrap().deposits_commitment, ())
    };
    assert_ne!(st_a.0, st_b.0, "commitment must bind ordering");
}
