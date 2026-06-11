//! Cycle-measurement / equivalence driver for the Liquid Cells SP1 guest.
//!
//! Usage: `liquid-cells-host <elf_path> [n_transfers]`
//!
//! Builds a pool funded with `n` payers, has each pay a common recipient (so the
//! batch touches `n + 1` leaves), executes the guest, and asserts the guest's
//! committed `PublicValues` equal the native ones. Prints the SP1 cycle count.

use liquid_cells_stf::*;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin, SP1_CIRCUIT_VERSION};
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

fn signed_withdrawal(payer: u32, target_lock_hash: Hash, amount: u128, nonce: u64, expiry: u64) -> Withdrawal {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target_lock_hash, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash, amount, nonce, expiry, sig }
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
    let do_groth16 = args.iter().any(|a| a == "groth16");
    let elf = fs::read(elf_path).expect("read elf");

    // Fund n distinct payers (skipped in `genesis` mode: the pool starts empty).
    let genesis_mode = args.iter().any(|a| a == "genesis");
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    if !genesis_mode {
        let deposits =
            (1..=n).map(|i| Deposit { to_key: key_for(i), amount: 1_000_000_000 }).collect();
        apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    }

    // `dw` => measured batch has a real deposit (fixtures/dw/). `wd` => deposit +
    // withdrawal (fixtures/wd/); the withdrawal target is the lock hash the wd_target
    // helper wrote, so the test can build the matching output cell.
    let dw = args.iter().any(|a| a == "dw");
    let wd = args.iter().any(|a| a == "wd");
    let dep_key = key_for(777);
    let dep_amount: u128 = 300_000_000;
    let wd_amount: u128 = 100_000_000;
    let deposits = if dw || wd { vec![Deposit { to_key: dep_key, amount: dep_amount }] } else { vec![] };
    let mut wd_target = [0u8; 32];
    let withdrawals = if wd {
        let h = std::fs::read("fixtures/wd/target_lock_hash.bin")
            .expect("run `cargo run --bin wd_target` first");
        wd_target.copy_from_slice(&h);
        // payer 1 withdraws after its transfer (nonce 1).
        vec![signed_withdrawal(1, wd_target, wd_amount, 1, 100)]
    } else {
        vec![]
    };
    let out_dir = if wd { "fixtures/wd" } else if dw { "fixtures/dw" } else { "fixtures" };

    // Each payer pays a shared recipient (fee 3) => touches n payers + 1 recipient leaf.
    let recipient = key_for(1_000_000);
    let transfers = (1..=n)
        .map(|i| signed_transfer(i, recipient, 1_000, 3, 0, 100))
        .collect();
    // L1 fee draw: the sequencer extracts 2 of the accumulated 3*n fee revenue to fund
    // the checkpoint's miner fee (a partial draw, so fee_acc stays positive). Bounded by
    // fee revenue in the STF, so it can never touch a user balance.
    let l1_fee: u128 = 2;
    let batch = Batch {
        current_epoch: 1,
        deposits,
        transfers,
        withdrawals,
        fee_withdrawal: l1_fee,
        ..Default::default()
    };

    // `genesis` => the very first checkpoint from the empty pool (fixtures/genesis/): deposit
    // 100 CKB to K, then K transfers a dust amount to L with a fee, and the sequencer draws
    // that fee to pay the L1 miner fee (a deposit-only batch has no fee revenue, and CKB
    // requires a positive miner fee). current_epoch 0 so the input `since` can be epoch 0.
    let (batch, out_dir) = if genesis_mode {
        let gfee: u128 = 100_000;
        let t = signed_transfer(1, key_for(2), 1_000, gfee, 0, 1_000_000);
        let b = Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: key_for(1), amount: 10_000_000_000 }],
            transfers: vec![t],
            fee_withdrawal: gfee,
            ..Default::default()
        };
        (b, "fixtures/genesis")
    } else {
        (batch, out_dir)
    };

    let witness = st.build_witness(&batch);
    let prev = st.pool;
    let native_pv = prove_transition(&prev, &witness, &batch).expect("native transition");

    // The DA blob the sequencer publishes (post-state of the touched leaves). Derived by
    // applying the measured batch to a clone, so keccak(blob) == the proof's da_commitment.
    let da_blob = {
        let mut after = st.clone();
        apply(&mut after, &batch).expect("apply measured batch");
        let blob = after.da_blob(&batch);
        assert_eq!(keccak(&blob), native_pv.da_commitment, "da blob must match da_commitment");
        blob
    };

    let input = codec::encode_input(&prev, &witness, &batch);

    let client = ProverClient::builder().cpu().build();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    if do_groth16 {
        // Generate + verify a Groth16-wrapped proof and dump on-chain fixtures
        // (proof bytes, public values, program vkey, circuit version) for the CKB
        // anchor type script to consume.
        let pk = client.setup(Elf::from(elf)).expect("setup");
        let proof = client.prove(&pk, stdin).groth16().run().expect("groth16 prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        let pv_bytes = proof.public_values.as_slice().to_vec();
        let proof_bytes = proof.bytes();
        let vkey = pk.verifying_key().bytes32();
        assert_eq!(
            codec::decode_public_values(&pv_bytes).expect("decode pv"),
            native_pv,
            "groth16 output diverged from native"
        );
        fs::create_dir_all(out_dir).expect("mkdir fixtures dir");
        fs::write(format!("{out_dir}/groth16_proof.bin"), &proof_bytes).unwrap();
        fs::write(format!("{out_dir}/public_values.bin"), &pv_bytes).unwrap();
        fs::write(format!("{out_dir}/vkey.txt"), &vkey).unwrap();
        fs::write(format!("{out_dir}/circuit_version.txt"), SP1_CIRCUIT_VERSION).unwrap();
        // da_blob.bin = the published state diff the checkpoint tx carries in its witness.
        fs::write(format!("{out_dir}/da_blob.bin"), &da_blob).unwrap();
        if dw || wd {
            // deposit.bin = to_key(32) ‖ amount(16 BE), for the test to build the deposit cell.
            let mut dep = Vec::with_capacity(48);
            dep.extend_from_slice(&dep_key);
            dep.extend_from_slice(&dep_amount.to_be_bytes());
            fs::write(format!("{out_dir}/deposit.bin"), &dep).unwrap();
            println!("deposit to_key=0x{} amount={dep_amount}", hex::encode(dep_key));
        }
        if genesis_mode {
            // deposit.bin = to_key(32) ‖ amount(16 BE) for the on-chain deposit cell.
            let k = key_for(1);
            let amt: u128 = 10_000_000_000;
            let mut dep = Vec::with_capacity(48);
            dep.extend_from_slice(&k);
            dep.extend_from_slice(&amt.to_be_bytes());
            fs::write(format!("{out_dir}/deposit.bin"), &dep).unwrap();
            println!("genesis deposit to_key=0x{} amount={amt}", hex::encode(k));
        }
        if wd {
            // withdrawal.bin = target_lock_hash(32) ‖ amount(16 BE).
            let mut w = Vec::with_capacity(48);
            w.extend_from_slice(&wd_target);
            w.extend_from_slice(&wd_amount.to_be_bytes());
            fs::write(format!("{out_dir}/withdrawal.bin"), &w).unwrap();
            println!("withdrawal target=0x{} amount={wd_amount}", hex::encode(wd_target));
        }
        println!("GROTH16+VERIFIED n_transfers={n} dw={dw} wd={wd}");
        println!("vkey={vkey}");
        println!("circuit_version={SP1_CIRCUIT_VERSION}");
        println!("proof_bytes={} public_values_bytes={}", proof_bytes.len(), pv_bytes.len());
        println!("new_root=0x{}", hex::encode(native_pv.new_root));
        println!(
            "fee_delta={} fee_withdrawal={} new_total={}",
            native_pv.fee_delta, native_pv.fee_withdrawal, native_pv.new_total
        );
        println!(
            "da_blob_bytes={} da_commitment=0x{}",
            da_blob.len(),
            hex::encode(native_pv.da_commitment)
        );
    } else if do_prove {
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
