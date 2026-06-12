//! Generalized thin Groth16 prover: prove ONE sealed checkpoint, bound to no scenario.
//!
//! Reads a raw SP1 guest input blob (a [`CheckpointJob::sp1_input`] produced by the sequencer's
//! `seal_batch`) and emits the two fixtures the on-chain submit driver puts in the anchor
//! witness: `groth16_proof.bin` (356 B) and `public_values.bin` (288 B). Unlike `lc-sequence`,
//! which is wired to reproduce specific live checkpoints, this proves whatever batch the caller
//! sealed, so deposits / tips / withdrawals of any shape can be proven on demand. The demo
//! operator seals a batch, drops its `sp1_input` here, and gets back a proof to submit.
//!
//!   prove_one <elf> <sp1_input.bin> <out_dir>
//!
//! One Groth16 per process (the native-gnark FFI does not reliably survive a second proof in the
//! same process), so this proves exactly one checkpoint per invocation.

use liquid_cells_stf::codec;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin};
use std::fs;

/// The guest vkey baked into the live anchor code cell (DEPLOY.md). The STF is unchanged for the
/// demo pool (only `pool_id`, a public input, differs), so the vkey must still match; asserting it
/// guarantees the proof verifies against the deployed contract.
const EXPECTED_VKEY: &str = "0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: prove_one <elf> <sp1_input.bin> <out_dir>");
        std::process::exit(2);
    }
    let elf_path = &args[1];
    let input_path = &args[2];
    let out_dir = &args[3];

    let elf = fs::read(elf_path).expect("read elf");
    let sp1_input = fs::read(input_path).expect("read sp1_input");
    println!("prove_one: elf={elf_path} input={} bytes -> {out_dir}", sp1_input.len());

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(elf)).expect("setup");
    let vkey = pk.verifying_key().bytes32();
    assert_eq!(vkey, EXPECTED_VKEY, "guest vkey != the deployed code cell's baked VKEY_HASH");

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&sp1_input);
    let proof = client.prove(&pk, stdin).groth16().run().expect("groth16 prove");
    client.verify(&proof, pk.verifying_key(), None).expect("verify");

    let pv_bytes = proof.public_values.as_slice().to_vec();
    // Sanity: the proven public values decode to the canonical layout the contract pins.
    let pv = codec::decode_public_values(&pv_bytes).expect("decode pv");

    fs::create_dir_all(out_dir).expect("mkdir");
    fs::write(format!("{out_dir}/groth16_proof.bin"), proof.bytes()).unwrap();
    fs::write(format!("{out_dir}/public_values.bin"), &pv_bytes).unwrap();

    println!(
        "PROVED: new_root=0x{} new_seq={} -> {out_dir}/groth16_proof.bin ({} B) + public_values.bin ({} B)",
        hex::encode(pv.new_root),
        pv.new_seq,
        proof.bytes().len(),
        pv_bytes.len(),
    );
    println!("vkey={vkey}");
}
