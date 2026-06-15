//! Data-availability tests.
//!
//! Two properties: (1) every checkpoint's `da_commitment` equals keccak of the blob the
//! sequencer publishes, and (2) an independent party can rebuild the *exact* tree, and a
//! valid force-exit inclusion proof for any leaf, from the published blobs alone, with no
//! cooperation from the sequencer. That second property is what makes the protocol
//! trustless against data withholding.

use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"da-pool")
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

/// Apply a checkpoint and return the blob the sequencer must publish, asserting it
/// matches the proven `da_commitment`.
fn checkpoint(st: &mut State, batch: &Batch) -> Vec<u8> {
    let pv = apply(st, batch).expect("checkpoint applies");
    let blob = st.da_blob(batch);
    assert_eq!(keccak(&blob), pv.da_commitment, "published blob must match the proven da_commitment");
    blob
}

#[test]
fn da_blobs_reconstruct_tree_and_prove_leaf() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut blobs: Vec<Vec<u8>> = Vec::new();

    // Checkpoint 1: fund Alice (1) and Bob (2).
    blobs.push(checkpoint(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![
                Deposit { to_key: key_for(1), amount: 500_000_000 },
                Deposit { to_key: key_for(2), amount: 200_000_000 },
            ],
            ..Default::default()
        },
    ));

    // Checkpoint 2: Alice -> Carol (3) with a fee; the sequencer draws part of that fee.
    blobs.push(checkpoint(
        &mut st,
        &Batch {
            current_epoch: 1,
            transfers: vec![signed_transfer(1, key_for(3), 100_000_000, 1_000, 0, 100)],
            fee_withdrawal: 400,
            ..Default::default()
        },
    ));

    // Checkpoint 3: Alice tops Carol up again; Bob withdraws to L1. (Fee 1, not 0, so the batch is
    // also valid under the staged `min_fee` floor; the fee is Alice's, so it does not affect Carol's
    // asserted balance or the reconstruction.)
    blobs.push(checkpoint(
        &mut st,
        &Batch {
            current_epoch: 2,
            transfers: vec![signed_transfer(1, key_for(3), 50_000_000, 1, 1, 100)],
            withdrawals: vec![signed_withdrawal(2, keccak(b"bob-l1"), 30_000_000, 0, 100)],
            ..Default::default()
        },
    ));

    let final_root = st.pool.root;

    // Independent verifier: rebuild from the blobs ONLY (no access to `st`'s tree).
    let rebuilt = reconstruct(&blobs).expect("blobs parse");
    assert_eq!(rebuilt.root(), final_root, "reconstructed root must equal the on-chain root");

    // Carol's balance reconstructed (100M + 50M), and a membership proof that verifies
    // against the on-chain root, exactly what a force-exit submits.
    let carol = key_for(3);
    let carol_leaf = st.get_leaf(&carol);
    assert_eq!(carol_leaf, Leaf { balance: 150_000_000, nonce: 0 });
    let proof = rebuilt.proof(&carol);
    assert!(
        verify_proof(&final_root, &carol, &carol_leaf.hash(), &proof),
        "force-exit inclusion proof from the reconstructed tree must verify"
    );

    // Non-membership: an untouched key proves as the empty leaf.
    let ghost = key_for(200);
    let gproof = rebuilt.proof(&ghost);
    assert!(verify_proof(&final_root, &ghost, &smt::EMPTY_LEAF, &gproof));
}

#[test]
fn tampered_da_blob_breaks_commitment() {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let batch = Batch {
        current_epoch: 0,
        deposits: vec![Deposit { to_key: key_for(1), amount: 1_000 }],
        ..Default::default()
    };
    let pv = apply(&mut st, &batch).unwrap();
    let mut blob = st.da_blob(&batch);
    let last = blob.len() - 1; // a balance/nonce byte in either DA layout (fixed or varint)
    blob[last] ^= 0xff;
    assert_ne!(keccak(&blob), pv.da_commitment, "a tampered blob must not match the commitment");
}
