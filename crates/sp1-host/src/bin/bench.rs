//! Proving-cost benchmark for the Liquid Cells SP1 guest.
//!
//! Answers the operator-sizing question: "how heavy is a checkpoint, and how does
//! it scale with batch size?" For each batch size it builds a real `n`-payer batch
//! (each payer pays one shared recipient, so the batch touches `n + 1` leaves),
//! runs the guest, and reports the proving cost.
//!
//! Usage:
//!   bench <elf_path> [sizes] [groth16]
//!     <elf_path>   the guest ELF (same one the sequencer proves).
//!     [sizes]      comma-separated batch sizes, e.g. `1,256,1023`. Default: 1,256,1023.
//!                  (`MAX_LEAVES_PER_BATCH = 1024`; n payers + 1 recipient = n+1 leaves,
//!                   so 1023 transfers = a full 1024-leaf checkpoint.)
//!     groth16      run the full Groth16 wrap and report setup/prove wall-time + peak
//!                  RSS. Heavy (~minutes, GBs). Omit it for a fast cycles-only pass.
//!
//! Cycles-only (default) runs anywhere in seconds; `groth16` is meant to be run on the
//! actual operator hardware to get real time/RAM sizing numbers.

use liquid_cells_stf::transition::MAX_LEAVES_PER_BATCH;
use liquid_cells_stf::*;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, ProvingKey, SP1Stdin};
use std::fs;
use std::time::Instant;

const CHAIN_ID: u64 = 0x434b_42;

fn secret(n: u32) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[28..].copy_from_slice(&n.to_be_bytes());
    s
}
fn pool_id() -> Hash {
    keccak(b"sp1-pool")
}
fn key_for(n: u32) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}
fn signed_transfer(payer: u32, to_key: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to_key, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key, amount, fee, nonce, expiry, sig }
}

/// Peak resident set size (VmHWM) in KiB, from /proc. `None` if unavailable.
fn peak_rss_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Reset the kernel's peak-RSS watermark to the current RSS, so the next
/// measurement reflects only the upcoming operation. No-op if unsupported.
fn reset_peak_rss() {
    let _ = fs::write("/proc/self/clear_refs", "5\n");
}

/// One measured batch: returns (touched_leaves, input_bytes, cycles).
fn build_and_execute(client: &impl Prover, elf: &[u8], n: u32) -> (usize, usize, u64) {
    // Fund n distinct payers, each with 1 CKB of headroom.
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = (1..=n).map(|i| Deposit { to_key: key_for(i), amount: 1_000_000_000 }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).expect("fund payers");

    // Each payer pays one shared recipient (fee 3) => n payers + 1 recipient = n+1 leaves.
    let recipient = key_for(1_000_000);
    let transfers = (1..=n).map(|i| signed_transfer(i, recipient, 1_000, 3, 0, 100)).collect();
    let batch = Batch { current_epoch: 1, transfers, fee_withdrawal: 2, ..Default::default() };

    let witness = st.build_witness(&batch);
    let prev = st.pool;
    let native_pv = prove_transition(&prev, &witness, &batch).expect("native transition");
    let input = codec::encode_input(&prev, &witness, &batch);

    // Execute the guest to count cycles and assert it matches the native result.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let (output, report) = client.execute(Elf::from(elf.to_vec()), stdin).run().expect("execute");
    let guest_pv = codec::decode_public_values(output.as_slice()).expect("decode committed pv");
    assert_eq!(guest_pv, native_pv, "guest output diverged from native prove_transition");

    (witness.leaves.len(), input.len(), report.total_instruction_count())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bench <elf_path> [sizes=1,256,1023] [groth16]");
        std::process::exit(2);
    }
    let elf = fs::read(&args[1]).expect("read elf");
    let do_groth16 = args.iter().any(|a| a == "groth16" || a == "prove");
    let sizes: Vec<u32> = args[2..]
        .iter()
        .find(|a| a.chars().all(|c| c.is_ascii_digit() || c == ','))
        .map(|s| s.split(',').filter_map(|t| t.parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 256, 1023]);

    let client = ProverClient::builder().cpu().build();

    // Groth16 setup is batch-size-independent; do it once and report it separately.
    let pk = if do_groth16 {
        reset_peak_rss();
        let t = Instant::now();
        let pk = client.setup(Elf::from(elf.clone())).expect("setup");
        let setup_s = t.elapsed().as_secs_f64();
        let setup_mb = peak_rss_kb().map(|k| k as f64 / 1024.0).unwrap_or(f64::NAN);
        println!("groth16 setup (one-time): {setup_s:.1}s, peak_rss={setup_mb:.0} MB\n");
        Some(pk)
    } else {
        None
    };

    println!(
        "| transfers | leaves | input KB | cycles | {} |",
        if do_groth16 { "prove s | peak RSS MB | proof B" } else { "(cycles only)" }
    );
    println!("|---|---|---|---|---|");

    for &n in &sizes {
        if n as usize + 1 > MAX_LEAVES_PER_BATCH {
            eprintln!("skip n={n}: n+1 > MAX_LEAVES_PER_BATCH ({MAX_LEAVES_PER_BATCH})");
            continue;
        }
        let (leaves, input_bytes, cycles) = build_and_execute(&client, &elf, n);

        if let Some(pk) = &pk {
            // Rebuild the same input for the prove path (execute consumed its stdin).
            let mut st = State::genesis(pool_id(), CHAIN_ID);
            let deposits = (1..=n).map(|i| Deposit { to_key: key_for(i), amount: 1_000_000_000 }).collect();
            apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
            let recipient = key_for(1_000_000);
            let transfers = (1..=n).map(|i| signed_transfer(i, recipient, 1_000, 3, 0, 100)).collect();
            let batch = Batch { current_epoch: 1, transfers, fee_withdrawal: 2, ..Default::default() };
            let witness = st.build_witness(&batch);
            let input = codec::encode_input(&st.pool, &witness, &batch);
            let mut stdin = SP1Stdin::new();
            stdin.write_slice(&input);

            reset_peak_rss();
            let t = Instant::now();
            let proof = client.prove(pk, stdin).groth16().run().expect("groth16 prove");
            let prove_s = t.elapsed().as_secs_f64();
            let peak_mb = peak_rss_kb().map(|k| k as f64 / 1024.0).unwrap_or(f64::NAN);
            client.verify(&proof, pk.verifying_key(), None).expect("verify");
            let proof_bytes = proof.bytes().len();
            println!(
                "| {n} | {leaves} | {:.1} | {cycles} | {prove_s:.1} | {peak_mb:.0} | {proof_bytes} |",
                input_bytes as f64 / 1024.0
            );
        } else {
            println!("| {n} | {leaves} | {:.1} | {cycles} | |", input_bytes as f64 / 1024.0);
        }
    }
}
