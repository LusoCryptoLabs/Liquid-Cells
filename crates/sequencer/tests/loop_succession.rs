//! Sequencer loop: successive checkpoints chain, conserve value, and stay reconstructable.
//!
//! The single Pudge checkpoint proved one transition lands on-chain. This proves the *loop*:
//! drive a stream of signed intents through several `seal_batch()` calls and check the four
//! properties that make a chain of checkpoints a real rollup, not a one-shot demo:
//!
//!   1. **Succession** — each checkpoint's `prev_anchor` is the previous one's `new_anchor`
//!      (byte-identical), and `seq` increments by exactly 1. So checkpoint *n+1* consumes the
//!      cell checkpoint *n* created.
//!   2. **Genesis pinning** — the first checkpoint's `prev_anchor` is the canonical empty
//!      anchor (the cell created at pool genesis).
//!   3. **Value conservation across the chain** — final `total` equals
//!      Σdeposits − Σwithdrawals − Σfee_withdrawals, and `Σ balances + fee_acc == total`
//!      holds at the end.
//!   4. **Data availability across the chain** — replaying every checkpoint's published DA
//!      blob (oldest first) rebuilds the exact tree, so any user can recover their leaf and a
//!      force-exit inclusion proof from L1 data alone.

use liquid_cells_sequencer::{chain_reconstructs_to, encode_anchor, Sequencer, ANCHOR_LEN};
use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x0043_4b42; // matches the deployed contract's baked CHAIN_ID
fn pool_id() -> Hash {
    keccak(b"sp1-pool") // matches the contract's baked POOL_ID
}

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn key_for(n: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}
fn signed_transfer(payer: u8, to: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key: to, amount, fee, nonce, expiry, sig }
}
fn signed_withdrawal(payer: u8, target: Hash, amount: u128, nonce: u64, expiry: u64) -> Withdrawal {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash: target, amount, nonce, expiry, sig }
}

/// anchor root field (bytes 0..32).
fn anchor_root(a: &[u8; ANCHOR_LEN]) -> Hash {
    let mut r = [0u8; 32];
    r.copy_from_slice(&a[0..32]);
    r
}
fn anchor_seq(a: &[u8; ANCHOR_LEN]) -> u64 {
    u64::from_be_bytes(a[32..40].try_into().unwrap())
}

#[test]
fn successive_checkpoints_chain_conserve_and_reconstruct() {
    let mut seq = Sequencer::genesis(pool_id(), CHAIN_ID);

    // The empty anchor the pool is created with — what checkpoint 1 must consume.
    let genesis_anchor = encode_anchor(seq.pool(), 0);
    assert_eq!(anchor_root(&genesis_anchor), Smt::new().root(), "genesis root is the empty SMT");
    assert_eq!(anchor_seq(&genesis_anchor), 0);

    let (alice, bob, carol, dave) = (key_for(1), key_for(2), key_for(3), key_for(4));
    let wd_target = keccak(b"liquid-cells/seq-test/withdraw-target");

    // running ledger expectations
    let mut sum_deposits: u128 = 0;
    let mut sum_withdrawals: u128 = 0;
    let mut sum_fee_withdrawals: u128 = 0;
    let mut jobs = Vec::new();

    // --- Checkpoint 1 (epoch 0): fund Alice, she dust-transfers to Bob with a fee, the
    //     sequencer draws that fee to pay the L1 miner fee (mirrors the live genesis batch). ---
    seq.submit_deposit(Deposit { to_key: alice, amount: 10_000_000_000 });
    seq.submit_transfer(signed_transfer(1, bob, 1_000, 100_000, 0, 1_000_000));
    assert_eq!(seq.pending(), 2);
    let j1 = seq.seal_batch(0, 100_000).unwrap();
    sum_deposits += 10_000_000_000;
    sum_fee_withdrawals += 100_000;
    assert_eq!(seq.pending(), 0, "mempool drained on a successful seal");

    assert_eq!(j1.prev_anchor, genesis_anchor, "checkpoint 1 consumes the genesis anchor");
    assert_eq!(j1.new_seq(), 1);
    assert_eq!(seq.total(), 10_000_000_000 - 100_000);
    jobs.push(j1.clone());

    // --- Checkpoint 2 (epoch 1): Bob pays Carol with a fee; draw the fee. ---
    seq.submit_transfer(signed_transfer(2, carol, 400, 100, 0, 1_000_000));
    let j2 = seq.seal_batch(1, 100).unwrap();
    sum_fee_withdrawals += 100;

    assert_eq!(j2.prev_anchor, j1.new_anchor, "checkpoint 2 chains onto checkpoint 1");
    assert_eq!(j2.new_seq(), 2);
    jobs.push(j2.clone());

    // --- Checkpoint 3 (epoch 2): Carol pays Dave with a fee AND withdraws to L1; draw the
    //     fee. Exercises every value-moving op in one sealed batch. ---
    seq.submit_transfer(signed_transfer(3, dave, 50, 50, 0, 1_000_000)); // Carol nonce 0 -> 1
    seq.submit_withdrawal(signed_withdrawal(3, wd_target, 200, 1, 1_000_000)); // then nonce 1
    let j3 = seq.seal_batch(2, 50).unwrap();
    sum_withdrawals += 200;
    sum_fee_withdrawals += 50;

    assert_eq!(j3.prev_anchor, j2.new_anchor, "checkpoint 3 chains onto checkpoint 2");
    assert_eq!(j3.new_seq(), 3);
    assert_eq!(j3.withdrawals, vec![(wd_target, 200u128)], "withdrawal cell spec is carried");
    jobs.push(j3.clone());

    // --- (1)+(2) succession over the whole chain. ---
    for pair in jobs.windows(2) {
        assert_eq!(pair[1].prev_anchor, pair[0].new_anchor, "anchors form an unbroken chain");
        assert_eq!(pair[1].new_seq(), pair[0].new_seq() + 1, "seq increments by 1");
    }

    // --- (3) value conservation across the chain. ---
    let expected_total = sum_deposits - sum_withdrawals - sum_fee_withdrawals;
    assert_eq!(seq.total(), expected_total, "final total = Σdep − Σwd − Σfee_wd");
    let balances: u128 = seq.state().leaves.values().map(|l| l.balance).sum();
    assert_eq!(balances + seq.fee_acc(), seq.total(), "Σ balances + fee_acc == total");

    // --- (4) data availability: the published blobs alone rebuild the exact final tree. ---
    let blobs: Vec<Vec<u8>> = jobs.iter().map(|j| j.da_blob.clone()).collect();
    let final_root = anchor_root(&j3.new_anchor);
    assert!(chain_reconstructs_to(&blobs, final_root), "DA blobs reconstruct the latest root");

    // ...and that a reconstructed tree yields a real force-exit inclusion proof for a user.
    let smt = reconstruct(&blobs).unwrap();
    let alice_leaf = seq.state().get_leaf(&alice);
    let proof = smt.proof(&alice);
    assert!(
        verify_proof(&final_root, &alice, &alice_leaf.hash(), &proof),
        "a user can derive a force-exit inclusion proof from L1 DA alone"
    );
}

#[test]
fn failed_seal_leaves_state_and_mempool_intact() {
    // A batch whose fee_withdrawal exceeds fee revenue must reject atomically: the root does
    // not move and the intents stay queued, so the operator can fix and retry.
    let mut seq = Sequencer::genesis(pool_id(), CHAIN_ID);
    seq.submit_deposit(Deposit { to_key: key_for(1), amount: 1_000_000_000 });
    let root_before = seq.root();

    // No fee revenue in a deposit-only batch, so drawing 5 must fail.
    let err = seq.seal_batch(0, 5).unwrap_err();
    assert_eq!(err, StfError::InsufficientFees);
    assert_eq!(seq.root(), root_before, "rejected seal does not advance the root");
    assert_eq!(seq.seq(), 0);
    assert_eq!(seq.pending(), 1, "intents remain queued after a failed seal");

    // Retrying with a valid draw (0) now succeeds and advances exactly one step.
    let job = seq.seal_batch(0, 0).unwrap();
    assert_eq!(job.new_seq(), 1);
    assert_eq!(seq.pending(), 0);
}
