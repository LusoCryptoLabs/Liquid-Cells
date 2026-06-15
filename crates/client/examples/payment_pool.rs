//! A complete, generic Liquid Cells lifecycle in ~60 lines, no tipping, no L1, no prover.
//!
//! This is the "hello world" for reusing Liquid Cells in ANY use case: a pooled-balance ledger
//! where the operator provably can't steal or mint, and any user can exit unilaterally. It runs the
//! real STF + sequencer + client in memory so you can read the whole shape end-to-end:
//!
//!   genesis pool → deposit → signed transfer → seal a checkpoint → reconstruct balances from the
//!   published data-availability (DA) blobs alone → build a force-exit witness from L1 data.
//!
//! Run: `cargo run -p liquid-cells-client --example payment_pool`
//!
//! What a real deployment adds around this (see DEPLOY.md / docs/): proving `job.sp1_input` to a
//! Groth16 proof and submitting a CKB tx that pins `job.new_anchor` and publishes `job.da_blob`.
//! The off-chain logic, everything below, is unchanged regardless of use case.

use liquid_cells_client::{latest_leaf, Account};
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::{keccak, Deposit};

fn main() {
    // --- 0. Pool identity. `pool_id` and `chain_id` MUST match the deployed anchor contract's
    // baked constants. You REUSE the fixed, vkey-proven STF, you do not fork it. ---
    let pool_id = keccak(b"my-app/payment-pool/v1");
    let chain_id = 0x434b_42; // CKB

    // --- 1. Stand up the off-chain sequencer over an empty pool. ---
    let mut operator = Sequencer::genesis(pool_id, chain_id);

    // Two users. An Account is just a keypair + nonce; receiving needs no registration
    // (a leaf key is keccak(pubkey)), so we can pay `bob` before he has ever acted.
    let mut alice = Account::new(pool_id, chain_id, secret(1));
    let bob = Account::new(pool_id, chain_id, secret(2));

    // --- 2. Deposit: a user funds the pool. On L1 this is a cell under the deposit lock, staged
    // through the confirmation-depth gate; here we submit it straight in. ---
    operator.submit_deposit(Deposit { to_key: alice.key(), amount: 100_000_000_000 }); // 1000 CKB
    let job0 = operator.seal_batch(0, 0).expect("deposit checkpoint"); // (epoch 0, fee_withdrawal 0)

    // --- 3. Transfer: Alice signs a transfer to Bob. The operator only ORDERS it; it cannot forge
    // or alter a signed intent. `fee` accrues to the pool's fee_acc (0 here for clarity). ---
    alice.sync_from_da(&[job0.da_blob.clone()]); // learn Alice's current nonce from L1
    let pay = alice.transfer(bob.key(), 25_000_000_000, 0, 1_000_000); // 250 CKB, expiry epoch
    operator.submit_transfer(pay);
    let job1 = operator.seal_batch(1, 0).expect("transfer checkpoint");

    // --- 4. Anyone reconstructs any balance from the published DA blobs alone, zero trust in the
    // operator's database. This is the data-availability pillar. ---
    let blobs = vec![job0.da_blob.clone(), job1.da_blob.clone()];
    let alice_bal = latest_leaf(&blobs, &alice.key()).map(|l| l.balance).unwrap_or(0);
    let bob_bal = latest_leaf(&blobs, &bob.key()).map(|l| l.balance).unwrap_or(0);
    println!("after transfer: alice = {alice_bal} shannon, bob = {bob_bal} shannon");
    assert_eq!(alice_bal, 75_000_000_000);
    assert_eq!(bob_bal, 25_000_000_000);
    assert_eq!(operator.total(), 100_000_000_000, "value is conserved across the pool");

    // --- 5. Force-exit: if the operator ever stalls, Bob exits unilaterally against the last
    // committed root. He reconstructs his leaf + inclusion proof from L1 and emits the witness the
    // anchor's escape-hatch mode consumes (payout forced to his own lock). No operator cooperation. ---
    let witness = bob.force_exit_witness(&blobs).expect("force-exit witness from L1 data");
    println!("bob can force-exit unilaterally: {}-byte witness built from L1 alone", witness.len());

    println!("\nThat's the whole off-chain shape, reuse it for payments, payroll, escrow, etc.");
}

/// Toy deterministic secret key (DON'T do this in production, use real entropy).
fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
