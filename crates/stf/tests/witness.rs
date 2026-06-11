//! Partial-witness tests: the witness-derived transition must match the full-tree
//! transition exactly, malformed/tampered witnesses must be rejected, and the guest
//! I/O codec must round-trip.

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"witness-pool")
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
fn signed_withdrawal(b: u8, target: Hash, amount: u128, nonce: u64, expiry: u64) -> Withdrawal {
    let sk = secret(b);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash: target, amount, nonce, expiry, sig }
}
fn funded_state(funding: &[(u8, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = funding.iter().map(|(b, a)| Deposit { to_key: key_for(*b), amount: *a }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    st
}

fn mixed_batch() -> Batch {
    Batch {
        current_epoch: 1,
        transfers: vec![
            signed_transfer(1, key_for(2), 100_000_000, 500, 0, 100),
            signed_transfer(2, key_for(3), 50_000_000, 250, 0, 100),
        ],
        withdrawals: vec![signed_withdrawal(1, keccak(b"l1-lock"), 30_000_000, 1, 100)],
        ..Default::default()
    }
}

#[test]
fn witness_transition_matches_full_tree() {
    let mut full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let batch = mixed_batch();

    // Capture the witness and prev state before mutating the full tree.
    let witness = full.build_witness(&batch);
    let prev = full.pool;

    let pv_witness = prove_transition(&prev, &witness, &batch).expect("witness transition");
    let pv_full = apply(&mut full, &batch).expect("full transition");

    // Identical public values, identical new root.
    assert_eq!(pv_witness, pv_full);
    assert_eq!(pv_witness.new_root, full.pool.root);
}

#[test]
fn single_isolated_key_gives_full_depth_proof() {
    let st = State::genesis(pool_id(), CHAIN_ID);
    let batch = Batch {
        current_epoch: 0,
        deposits: vec![Deposit { to_key: key_for(7), amount: 123_456 }],
        ..Default::default()
    };
    let witness = st.build_witness(&batch);
    assert_eq!(witness.siblings.len(), 256, "one isolated leaf => a 256-deep path");

    // prev_root reconstructs (empty tree) and the transition is accepted.
    let pv = prove_transition(&st.pool, &witness, &batch).expect("isolated deposit");
    assert_eq!(pv.prev_root, st.pool.root);
    assert_ne!(pv.new_root, st.pool.root);
}

#[test]
fn tampered_witness_leaf_is_rejected() {
    let full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let batch = mixed_batch();
    let mut witness = full.build_witness(&batch);

    // Inflate a provided pre-leaf balance: it no longer reconstructs prev_root.
    witness.leaves[0].1.balance += 1;
    assert_eq!(
        prove_transition(&full.pool, &witness, &batch),
        Err(StfError::PrevRootMismatch)
    );
}

#[test]
fn missing_witness_leaf_is_rejected() {
    let full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let batch = mixed_batch();
    let mut witness = full.build_witness(&batch);
    witness.leaves.pop(); // drop a required leaf
    assert_eq!(
        prove_transition(&full.pool, &witness, &batch),
        Err(StfError::MalformedWitness)
    );
}

#[test]
fn extra_sibling_is_rejected() {
    let full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let batch = mixed_batch();
    let mut witness = full.build_witness(&batch);
    witness.siblings.push([0u8; 32]); // one too many
    assert_eq!(
        prove_transition(&full.pool, &witness, &batch),
        Err(StfError::MalformedWitness)
    );
}

#[test]
fn wrong_prev_root_is_rejected() {
    let full = funded_state(&[(1, 500_000_000)]);
    let batch = Batch {
        current_epoch: 1,
        transfers: vec![signed_transfer(1, key_for(2), 1_000, 0, 0, 100)],
        ..Default::default()
    };
    let witness = full.build_witness(&batch);
    let mut prev = full.pool;
    prev.root[0] ^= 0xff;
    assert_eq!(prove_transition(&prev, &witness, &batch), Err(StfError::PrevRootMismatch));
}

#[test]
fn batch_exceeding_leaf_cap_is_rejected() {
    use liquid_cells_stf::transition::MAX_LEAVES_PER_BATCH;
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    // One more distinct deposit key than the cap allows (deposits need no signatures;
    // keys are just distinct hashes here).
    let deposits = (0..=MAX_LEAVES_PER_BATCH as u32)
        .map(|i| Deposit { to_key: keccak(&i.to_be_bytes()), amount: 1 })
        .collect();
    let batch = Batch { current_epoch: 0, deposits, ..Default::default() };
    assert_eq!(apply(&mut st, &batch), Err(StfError::BatchTooLarge));
}

#[test]
fn codec_input_round_trips() {
    let full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let batch = mixed_batch();
    let witness = full.build_witness(&batch);
    let prev = full.pool;

    let bytes = codec::encode_input(&prev, &witness, &batch);
    let (p2, w2, b2) = codec::decode_input(&bytes).expect("decode");
    assert_eq!(p2, prev);
    assert_eq!(w2, witness);
    assert_eq!(b2, batch);

    // And the decoded bundle proves to the same public values.
    let pv1 = prove_transition(&prev, &witness, &batch).unwrap();
    let pv2 = prove_transition(&p2, &w2, &b2).unwrap();
    assert_eq!(pv1, pv2);
}

#[test]
fn codec_public_values_round_trips() {
    let mut full = funded_state(&[(1, 500_000_000), (2, 200_000_000)]);
    let pv = apply(&mut full, &mixed_batch()).unwrap();
    let decoded = codec::decode_public_values(&pv.encode()).expect("decode pv");
    assert_eq!(decoded, pv);
}
