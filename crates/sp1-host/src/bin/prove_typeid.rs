//! Seal + Groth16-prove ONE checkpoint for the live type-id'd pool (pool_id 0x06865b65...,
//! on-chain genesis root 0xa7ff9e28..., anchor type hash 0xf7dfded8...). The batch is a
//! deposit (routed through the deposit lock) plus a tiny fee-paying transfer that bootstraps
//! fee_acc, so the checkpoint can pay a real L1 miner fee (an empty pool has none).
//! The guest ELF must reproduce the deployed vkey 0x00213af5.
//!   prove_typeid <elf> <out_dir> [groth16]
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::*;
use sp1_sdk::blocking::{Prover, ProverClient, ProveRequest};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
use std::fs;

const CHAIN_ID: u64 = 0x0043_4b42;
const EXPECTED_VKEY: &str = "0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8";
const GENESIS_ROOT: &str = "a7ff9e28ffd3def443d324547688c2c4eb98edf7da757d6bfa22bff55b9ce24a";
const DEPOSIT_AMOUNT: u128 = 20_000_000_000; // 200 CKB; == on-chain deposit cell capacity
const XFER_FEE: u128 = 100_000;              // 0.001 CKB pool fee -> becomes the L1 miner fee
const XFER_AMOUNT: u128 = 1_000_000;
const EPOCH: u64 = 13267;

fn hx(b: &[u8]) -> String { let mut s = String::new(); for x in b { s.push_str(&format!("{:02x}", x)); } s }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let elf_path = &args[1];
    let out_dir = &args[2];
    let do_groth16 = args.iter().any(|a| a == "groth16");

    let pool_id: Hash = [
        0x06,0x86,0x5b,0x65,0xf8,0x67,0x97,0x0c,0x6d,0x89,0xf5,0xe8,0x2e,0xd5,0x30,0x36,
        0x2f,0x00,0xe5,0x05,0x1e,0xa7,0x26,0x55,0x56,0x64,0x6e,0x78,0x35,0xb6,0x32,0x95];
    let my_secret: Hash = keccak(b"liquid-cells/typeid-pool/depositor-secret");
    let my_pubkey = sig::pubkey(&my_secret);
    let my_key = key_of_pubkey(&my_pubkey);
    let sink_key: Hash = keccak(b"liquid-cells/typeid-pool/fee-sink");

    let mut seq = Sequencer::genesis(pool_id, CHAIN_ID);
    assert_eq!(hx(&seq.root()), GENESIS_ROOT, "genesis root != on-chain type-id'd anchor root");
    let prev_anchor = seq.anchor();

    // deposit -> my_key, then transfer my_key -> sink_key paying XFER_FEE (bootstraps fee_acc)
    seq.submit_deposit(Deposit { to_key: my_key, amount: DEPOSIT_AMOUNT });
    let msg = transfer_msg(CHAIN_ID, &pool_id, &my_key, &sink_key, XFER_AMOUNT, XFER_FEE, 0, 1_000_000);
    let (_pk, s) = sig::sign(&my_secret, &msg);
    seq.submit_transfer(Transfer { from_pubkey: my_pubkey, to_key: sink_key, amount: XFER_AMOUNT, fee: XFER_FEE, nonce: 0, expiry: 1_000_000, sig: s });
    let job = seq.seal_batch(EPOCH, XFER_FEE).expect("seal checkpoint");

    fs::create_dir_all(out_dir).unwrap();
    fs::write(format!("{out_dir}/sp1_input.bin"), &job.sp1_input).unwrap();
    println!("deposit_to   = 0x{} (my_key)", hx(&my_key));
    println!("deposit_amt  = {DEPOSIT_AMOUNT}");
    println!("prev_anchor  = 0x{}", hx(&prev_anchor));
    println!("new_anchor   = 0x{}", hx(&job.new_anchor));
    println!("new_root     = 0x{}", hx(&job.new_root()));
    println!("new_seq      = {}", job.new_seq());
    println!("new_total    = {}", rd_total(&job.new_anchor));
    println!("fee_withdraw = {}  (=> L1 miner fee)", job.fee_withdrawal);
    println!("current_epoch= {}", job.current_epoch);
    println!("da_blob_len  = {}", job.da_blob.len());
    println!("sp1_input_len= {}", job.sp1_input.len());

    if !do_groth16 {
        println!("SEAL OK (no proof). rerun with `groth16` to prove.");
        return;
    }
    let elf = fs::read(elf_path).expect("read elf");
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(elf)).expect("setup");
    let vkey = pk.verifying_key().bytes32();
    assert_eq!(vkey, EXPECTED_VKEY, "guest vkey != deployed baked VKEY_HASH");
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&job.sp1_input);
    println!("proving (groth16)...");
    let proof = client.prove(&pk, stdin).groth16().run().expect("groth16 prove");
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    let pv_bytes = proof.public_values.as_slice().to_vec();
    assert_eq!(codec::decode_public_values(&pv_bytes).expect("decode pv"), job.public_values,
        "proven public values diverged from the sequencer (format drift!)");
    fs::write(format!("{out_dir}/groth16_proof.bin"), proof.bytes()).unwrap();
    fs::write(format!("{out_dir}/public_values.bin"), &pv_bytes).unwrap();
    fs::write(format!("{out_dir}/da_blob.bin"), &job.da_blob).unwrap();
    fs::write(format!("{out_dir}/new_anchor.bin"), job.new_anchor).unwrap();
    println!("proof_len={} pv_len={}", proof.bytes().len(), pv_bytes.len());
    println!("vkey={vkey}");
    println!("PROVED + VERIFIED + pv-matched -> {out_dir}/");
}

fn rd_total(a: &[u8]) -> u128 { let mut b=[0u8;16]; b.copy_from_slice(&a[40..56]); u128::from_be_bytes(b) }
