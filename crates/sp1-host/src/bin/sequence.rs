//! Sequencer prove-and-stage driver: turn successive `CheckpointJob`s into the fixtures a
//! submission driver lands on Pudge, proving that the sequencer loop composes *on the live
//! chain*, not just in memory.
//!
//! It seeds a [`Sequencer`] to the **exact current on-chain state** by replaying the genesis
//! batch (asserting the reproduced root equals the live seq-1 root from DEPLOY.md), then seals
//! two more checkpoints (transfer-only, so each on-chain tx is just anchor-in → anchor-out with
//! the miner fee paid from the proven `fee_withdrawal`, no deposit/withdrawal cells to
//! coordinate). For each it Groth16-proves the `CheckpointJob`'s SP1 input, verifies it,
//! asserts the proven public values equal the sequencer's, and writes
//! `fixtures/seq/cp{n}/{groth16_proof,public_values,da_blob,new_anchor}.bin`.
//!
//! Usage:
//!   lc-sequence <elf>                  # check only: reproduce state + chain, no proving (fast)
//!   lc-sequence <elf> groth16 cp2      # Groth16-prove + stage ONLY cp2
//!   lc-sequence <elf> groth16 cp3      # Groth16-prove + stage ONLY cp3
//!   lc-sequence <elf> groth16          # both (one process), AVOID: the native-gnark FFI
//!                                      #   does not reliably survive a second proof per process
//!
//! Prove one checkpoint per process invocation (`cp2`, then `cp3`): each run rebuilds the whole
//! chain in memory (genesis replay -> cp2 -> cp3, no proving for the others) and proves only the
//! selected checkpoint, so the gnark prover is invoked exactly once.
//!
//! The STF is unchanged from the deployed code cell, so the guest vkey still matches the
//! baked `VKEY_HASH`, asserted before proving.

use liquid_cells_sequencer::{CheckpointJob, Sequencer};
use liquid_cells_stf::*;
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey, SP1Stdin, SP1_CIRCUIT_VERSION};
use std::fs;

const CHAIN_ID: u64 = 0x434b_42;
/// The guest vkey baked into the live anchor code cell (DEPLOY.md). Any STF change would move
/// this; asserting it guarantees the proofs verify against the deployed contract.
const EXPECTED_VKEY: &str = "0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8";
/// The live seq-1 anchor root (first checkpoint, DEPLOY.md). The genesis replay must reproduce
/// it exactly, or cp2's `prev_root` would not match the on-chain anchor and the contract would
/// reject. This is the safety gate before any proving.
const LIVE_SEQ1_ROOT: &str = "f3283454dade507e46be473e99b0885b7a12abe024758171e4a8b387d4626843";
/// The live seq-3 anchor root (third checkpoint, currently the chain tip, DEPLOY.md / queried
/// on Pudge). The in-memory chain must reproduce it before cp4 is proved, or cp4's `prev_root`
/// would not match the on-chain anchor cp4 consumes. Safety gate before proving cp4.
const LIVE_SEQ3_ROOT: &str = "602001602cab52d01c6900e470799e3c8f31d5205f74e2a3ae3be6ea1b336985";

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
fn signed_transfer(payer: u32, to: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key: to, amount, fee, nonce, expiry, sig }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: lc-sequence <elf_path> [groth16]");
        std::process::exit(2);
    }
    let elf_path = &args[1];
    let do_groth16 = args.iter().any(|a| a == "groth16");

    // --- seed the sequencer to the live on-chain seq-1 state by replaying genesis ---
    let mut seq = Sequencer::genesis(pool_id(), CHAIN_ID);
    seq.submit_deposit(Deposit { to_key: key_for(1), amount: 10_000_000_000 });
    seq.submit_transfer(signed_transfer(1, key_for(2), 1_000, 100_000, 0, 1_000_000));
    let _genesis = seq.seal_batch(0, 100_000).expect("genesis replay");
    let root_hex = hex::encode(seq.root());
    assert_eq!(root_hex, LIVE_SEQ1_ROOT, "genesis replay did not reproduce the live seq-1 root");
    println!(
        "seeded to live seq-1: root=0x{root_hex} seq={} total={} fee_acc={}",
        seq.seq(),
        seq.total(),
        seq.fee_acc()
    );
    let live_anchor = seq.anchor(); // == the on-chain seq-1 anchor data (last_epoch 0)

    // --- seal two successive checkpoints (transfer-only; draw the fee to pay the miner) ---
    // key_for(1)'s account nonce is 1 after the genesis transfer.
    seq.submit_transfer(signed_transfer(1, key_for(3), 1_000, 100_000, 1, 1_000_000));
    let job2 = seq.seal_batch(1, 100_000).expect("cp2 seal");
    seq.submit_transfer(signed_transfer(1, key_for(4), 1_000, 100_000, 2, 1_000_000));
    let job3 = seq.seal_batch(2, 100_000).expect("cp3 seal");

    // cp3 is the live chain tip: its reproduced root MUST equal the on-chain seq-3 anchor,
    // or cp4's `prev_root` would not match the anchor cp4 consumes. Gate before proving cp4.
    assert_eq!(hex::encode(job3.new_root()), LIVE_SEQ3_ROOT, "cp3 root != live seq-3 anchor root");
    let seq3_anchor = job3.new_anchor; // == the on-chain seq-3 anchor data (last_epoch 2)

    // cp4 (seq 3 -> 4): one more transfer-only checkpoint chaining onto the live tip.
    // key_for(1)'s account nonce is 3 after the cp2/cp3 transfers.
    seq.submit_transfer(signed_transfer(1, key_for(5), 1_000, 100_000, 3, 1_000_000));
    let job4 = seq.seal_batch(3, 100_000).expect("cp4 seal");

    // succession sanity (the whole point): cp2 chains onto the live anchor, cp3 onto cp2,
    // cp4 onto the live seq-3 tip.
    assert_eq!(job2.prev_anchor, live_anchor, "cp2 must consume the live seq-1 anchor");
    assert_eq!(job3.prev_anchor, job2.new_anchor, "cp3 must consume cp2's output anchor");
    assert_eq!(job4.prev_anchor, seq3_anchor, "cp4 must consume the live seq-3 anchor");
    assert_eq!((job2.new_seq(), job3.new_seq(), job4.new_seq()), (2, 3, 4));

    for (i, job) in [(2u32, &job2), (3u32, &job3), (4u32, &job4)] {
        println!(
            "cp{i}: prev_root=0x{} -> new_root=0x{} new_seq={} fee_wd={} epoch={}",
            hex::encode(&job.prev_anchor[0..32]),
            hex::encode(job.new_root()),
            job.new_seq(),
            job.fee_withdrawal,
            job.current_epoch
        );
    }

    if !do_groth16 {
        println!("CHECK OK, state + chain reproduce; rerun with `groth16` to prove + stage.");
        return;
    }

    // --- Groth16-prove each checkpoint and stage the on-chain fixtures ---
    let elf = fs::read(elf_path).expect("read elf");
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(elf)).expect("setup");
    let vkey = pk.verifying_key().bytes32();
    assert_eq!(vkey, EXPECTED_VKEY, "guest vkey != the deployed code cell's baked VKEY_HASH");

    let stage = |i: u32, job: &CheckpointJob| {
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&job.sp1_input);
        let proof = client.prove(&pk, stdin).groth16().run().expect("groth16 prove");
        client.verify(&proof, pk.verifying_key(), None).expect("verify");
        let pv_bytes = proof.public_values.as_slice().to_vec();
        assert_eq!(
            codec::decode_public_values(&pv_bytes).expect("decode pv"),
            job.public_values,
            "cp{i}: proven public values diverged from the sequencer"
        );
        let dir = format!("fixtures/seq/cp{i}");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(format!("{dir}/groth16_proof.bin"), proof.bytes()).unwrap();
        fs::write(format!("{dir}/public_values.bin"), &pv_bytes).unwrap();
        fs::write(format!("{dir}/da_blob.bin"), &job.da_blob).unwrap();
        fs::write(format!("{dir}/new_anchor.bin"), job.new_anchor).unwrap();
        fs::write(
            format!("{dir}/info.txt"),
            format!(
                "new_seq={}\ncurrent_epoch={}\nfee_withdrawal={}\nnew_root=0x{}\n",
                job.new_seq(),
                job.current_epoch,
                job.fee_withdrawal,
                hex::encode(job.new_root())
            ),
        )
        .unwrap();
        println!("cp{i} PROVED+VERIFIED -> {dir}/ (new_seq={})", job.new_seq());
    };

    // One proof per process: select which checkpoint to prove (the native-gnark FFI does not
    // reliably survive two proofs in one process). With neither token, prove both (legacy).
    let want2 = args.iter().any(|a| a == "cp2");
    let want3 = args.iter().any(|a| a == "cp3");
    let want4 = args.iter().any(|a| a == "cp4");
    let both = !want2 && !want3 && !want4;
    if both || want2 {
        stage(2, &job2);
    }
    if both || want3 {
        stage(3, &job3);
    }
    if both || want4 {
        stage(4, &job4);
    }
    println!("vkey={vkey} circuit_version={SP1_CIRCUIT_VERSION}");
    println!("STAGED, ready to submit to Pudge.");
}
