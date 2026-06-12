//! Seal a single Liquid Cells checkpoint off a fresh genesis and write the fixtures the prover
//! (`prove_one`) and the CCC submit driver need. Bootstraps the on-chain demo pool. The pool
//! identity MUST be `keccak("sp1-pool")` / chain `0x434b42`, the values the deployed anchor type
//! script bakes and pins (it rejects any other).
//!
//!   sealjob genesis-bootstrap <out_dir> <op_secret_hex32> <deposit_shannons> <fee_reserve_shannons> <fee_withdrawal_shannons> <epoch>
//!
//! The bootstrap batch credits `deposit_shannons` to an operator key, then signs one transfer
//! (operator -> fee-sink, amount 1, fee `fee_reserve`) so `fee_acc` holds a reserve. Only
//! `fee_withdrawal` (a few thousandths of a CKB) is drawn to pay THIS checkpoint's L1 miner fee;
//! the rest of the reserve funds future checkpoints (and tip fees keep topping it up). A pure
//! deposit batch has no fees, so it could not pay any miner fee, this is why genesis must seed one.
//!
//! Writes: sp1_input.bin (feed to prove_one), new_anchor.bin (80-byte output anchor data),
//! da_blob.bin (anchor witness output_type), deposit.bin (32-byte to_key = the deposit cell data),
//! job.json (deposit_amount + fee_withdrawal + epoch for the submit driver), info.txt.

use liquid_cells_client::Account;
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::{key_of_pubkey, keccak, sig, Deposit, Hash};
use std::fs;

const CHAIN_ID: u64 = 0x0043_4b42;
const EXPIRY: u64 = 1_000_000;
fn pool_id() -> Hash {
    keccak(b"sp1-pool")
}
fn fee_sink_key() -> Hash {
    keccak(b"liquid-cells-demo/fee-sink")
}

fn parse_secret(s: &str) -> [u8; 32] {
    let v = hex::decode(s.trim_start_matches("0x")).expect("secret hex");
    assert_eq!(v.len(), 32, "secret must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 8 || a[1] != "genesis-bootstrap" {
        eprintln!("usage: sealjob genesis-bootstrap <out_dir> <op_secret_hex32> <deposit_shannons> <fee_reserve_shannons> <fee_withdrawal_shannons> <epoch>");
        std::process::exit(2);
    }
    let out = &a[2];
    let op_secret = parse_secret(&a[3]);
    let deposit: u128 = a[4].parse().expect("deposit");
    let fee_reserve: u128 = a[5].parse().expect("fee_reserve");
    let fee_withdrawal: u128 = a[6].parse().expect("fee_withdrawal");
    let epoch: u64 = a[7].parse().expect("epoch");

    let op_pubkey = sig::pubkey(&op_secret);
    let op_key = key_of_pubkey(&op_pubkey);

    let mut seq = Sequencer::genesis(pool_id(), CHAIN_ID);
    // 1) credit the operator key (the deposit cell on L1 will carry this to_key + capacity).
    seq.submit_deposit(Deposit { to_key: op_key, amount: deposit });
    // 2) one signed transfer op -> fee-sink moves `fee_reserve` into fee_acc (not to a balance),
    //    so the pool can pay miner fees. Signed by the operator account (we hold its secret).
    let mut op = Account::new(pool_id(), CHAIN_ID, op_secret);
    let t = op.transfer(fee_sink_key(), 1, fee_reserve, EXPIRY);
    seq.submit_transfer(t);

    let job = seq.seal_batch(epoch, fee_withdrawal).expect("seal genesis bootstrap");

    fs::create_dir_all(out).unwrap();
    fs::write(format!("{out}/sp1_input.bin"), &job.sp1_input).unwrap();
    fs::write(format!("{out}/new_anchor.bin"), job.new_anchor).unwrap();
    fs::write(format!("{out}/da_blob.bin"), &job.da_blob).unwrap();
    fs::write(format!("{out}/deposit.bin"), op_key).unwrap();
    fs::write(
        format!("{out}/job.json"),
        format!(
            "{{\n  \"mode\": \"genesis-bootstrap\",\n  \"toKey\": \"0x{}\",\n  \"depositShannons\": {},\n  \"feeWithdrawalShannons\": {},\n  \"epoch\": {},\n  \"newRoot\": \"0x{}\",\n  \"newSeq\": {}\n}}\n",
            hex::encode(op_key),
            deposit,
            fee_withdrawal,
            epoch,
            hex::encode(job.new_root()),
            job.new_seq()
        ),
    )
    .unwrap();
    fs::write(
        format!("{out}/info.txt"),
        format!(
            "op_to_key=0x{}\nop_pubkey=0x{}\ndeposit={}\nfee_reserve={}\nfee_withdrawal={}\nnew_root=0x{}\nnew_seq={}\nnew_total={}\nnew_fee_acc={}\nepoch={}\n",
            hex::encode(op_key),
            hex::encode(op_pubkey),
            deposit,
            fee_reserve,
            fee_withdrawal,
            hex::encode(job.new_root()),
            job.new_seq(),
            seq.total(),
            seq.fee_acc(),
            job.current_epoch
        ),
    )
    .unwrap();
    println!(
        "sealed genesis-bootstrap: op_to_key=0x{} deposit={} fee_reserve={} fee_wd={} new_root=0x{} new_seq={} total={} fee_acc={} -> {out}/",
        hex::encode(op_key),
        deposit,
        fee_reserve,
        fee_withdrawal,
        hex::encode(job.new_root()),
        job.new_seq(),
        seq.total(),
        seq.fee_acc()
    );
}
