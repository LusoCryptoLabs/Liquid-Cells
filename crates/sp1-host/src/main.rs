//! Cycle-measurement / equivalence driver for the Liquid Cells SP1 guest.
//!
//! Usage: `liquid-cells-host <elf_path> [n_transfers]`
//!
//! Builds a pool funded with `n` payers, has each pay a common recipient (so the
//! batch touches `n + 1` leaves), executes the guest, and asserts the guest's
//! committed `PublicValues` equal the native ones. Prints the SP1 cycle count.

use liquid_cells_stf::*;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, ProvingKey, SP1Stdin};
use std::fs;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: liquid-cells-host <elf_path> [n_transfers]");
        std::process::exit(2);
    }
    let elf_path = &args[1];
    let n: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let do_prove = args.iter().any(|a| a == "prove");
    let elf = fs::read(elf_path).expect("read elf");

    // Fund n distinct payers.
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = (1..=n).map(|i| Deposit { to_key: key_for(i), amount: 1_000_000_000 }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();

    // Each payer pays a shared recipient => touches n payers + 1 recipient leaf.
    let recipient = key_for(1_000_000);
    let transfers = (1..=n)
        .map(|i| signed_transfer(i, recipient, 1_000, 1, 0, 100))
        .collect();
    let batch = Batch { current_epoch: 1, transfers, ..Default::default() };

    let witness = st.build_witness(&batch);
    let prev = st.pool;
    let native_pv = prove_transition(&prev, &witness, &batch).expect("native transition");

    let input = codec::encode_input(&prev, &witness, &batch);

    let client = ProverClient::builder().cpu().build();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    if do_prove {
        // Generate and verify a real SP1 core proof.
        let pk = client.setup(Elf::from(elf)).expect("setup");
        let proof = client.prove(&pk, stdin).core().run().expect("prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        let guest_pv =
            codec::decode_public_values(proof.public_values.as_slice()).expect("decode proven pv");
        assert_eq!(guest_pv, native_pv, "proven output diverged from native");
        println!("PROVED+VERIFIED n_transfers={n} new_root=0x{}", hex::encode(guest_pv.new_root));
    } else {
        let (output, report) = client.execute(Elf::from(elf), stdin).run().expect("execute");
        let cycles = report.total_instruction_count();
        let guest_pv =
            codec::decode_public_values(output.as_slice()).expect("decode committed pv");
        assert_eq!(guest_pv, native_pv, "guest output diverged from native prove_transition");
        println!(
            "n_transfers={n} touched_leaves={} siblings={} input_bytes={} cycles={cycles}",
            witness.leaves.len(),
            witness.siblings.len(),
            input.len(),
        );
        println!("new_root=0x{}", hex::encode(guest_pv.new_root));
    }
}
