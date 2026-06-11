//! Deposit-binding integration tests (Phase 2b-3, implicit cell format).
//!
//! Uses the `fixtures/dw/` proof, whose checkpoint includes one real deposit. The tx
//! carries the deposit as a non-anchor input (data = to_key, capacity = amount). The
//! type script must recompute `deposits_commitment` from that cell and match the
//! proof, and check value conservation (accounting total delta + anchor capacity
//! delta). Tampering the deposit's to_key / amount, dropping the cell, or breaking the
//! anchor capacity delta must all be rejected — before the pairing.
//!
//! Requires the contract built and `fixtures/dw/` generated (scripts/groth16.sh ... dw).

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const PROOF_PATH: &str = "../../fixtures/dw/groth16_proof.bin";
const PV_PATH: &str = "../../fixtures/dw/public_values.bin";
const DEPOSIT_PATH: &str = "../../fixtures/dw/deposit.bin";

const PV_PREV_ROOT: usize = 40;
const PV_PREV_SEQ: usize = 72;
const PV_NEW_ROOT: usize = 80;
const PV_NEW_SEQ: usize = 112;
const PV_PREV_TOTAL: usize = 184;
const PV_NEW_TOTAL: usize = 200;
const PV_FEE_DELTA: usize = 216;

fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_be_bytes(a)
}
fn rd_u128(b: &[u8], o: usize) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    u128::from_be_bytes(a)
}
fn anchor(root: &[u8], seq: u64, total: u128, fee: u128) -> Vec<u8> {
    let mut a = Vec::with_capacity(72);
    a.extend_from_slice(root);
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(&total.to_be_bytes());
    a.extend_from_slice(&fee.to_be_bytes());
    a
}

#[derive(Clone, Default)]
struct Cfg {
    bad_key: bool,     // tamper the deposit cell's to_key
    bad_amount: bool,  // tamper the deposit cell's capacity (amount)
    drop_deposit: bool, // omit the deposit cell entirely
    bad_anchor_cap: bool, // break the anchor capacity delta
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let proof = std::fs::read(PROOF_PATH).expect("fixtures/dw/groth16_proof.bin (run scripts/groth16.sh 1 dw)");
    let pv = std::fs::read(PV_PATH).expect("fixtures/dw/public_values.bin");
    let dep = std::fs::read(DEPOSIT_PATH).expect("fixtures/dw/deposit.bin");

    let mut to_key = dep[0..32].to_vec();
    let amount = rd_u128(&dep, 32);

    let prev_root = pv[PV_PREV_ROOT..PV_PREV_ROOT + 32].to_vec();
    let new_root = pv[PV_NEW_ROOT..PV_NEW_ROOT + 32].to_vec();
    let prev_seq = rd_u64(&pv, PV_PREV_SEQ);
    let new_seq = rd_u64(&pv, PV_NEW_SEQ);
    let prev_total = rd_u128(&pv, PV_PREV_TOTAL);
    let new_total = rd_u128(&pv, PV_NEW_TOTAL);
    let fee_delta = rd_u128(&pv, PV_FEE_DELTA);

    let prev_anchor = anchor(&prev_root, prev_seq, prev_total, 0);
    let new_anchor = anchor(&new_root, new_seq, new_total, fee_delta);

    // Anchor capacity == pool total, so the capacity delta equals the deposit amount.
    let in_cap = prev_total as u64;
    let mut out_cap = new_total as u64;
    if cfg.bad_anchor_cap {
        out_cap = in_cap; // delta 0 != Σdeposits
    }

    if cfg.bad_key {
        to_key[0] ^= 0xff;
    }
    let dep_cap = if cfg.bad_amount { amount as u64 + 1 } else { amount as u64 };

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let dep_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();

    // input[0] = anchor (carries this type script) -> its witness holds proof ‖ pv.
    let anchor_in = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(in_cap.pack())
            .lock(lock.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        Bytes::from(prev_anchor),
    );

    let mut witness = Vec::with_capacity(proof.len() + pv.len());
    witness.extend_from_slice(&proof);
    witness.extend_from_slice(&pv);
    let w0 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(witness)).pack())
        .build()
        .as_bytes();

    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in).build())
        .output(
            CellOutput::new_builder()
                .capacity(out_cap.pack())
                .lock(lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack());

    if !cfg.drop_deposit {
        // input[1] = deposit cell (non-anchor input): data = to_key, capacity = amount.
        let deposit_in = ctx.create_cell(
            CellOutput::new_builder().capacity(dep_cap.pack()).lock(dep_lock).build(),
            Bytes::from(to_key),
        );
        b = b
            .input(CellInput::new_builder().previous_output(deposit_in).build())
            .witness(WitnessArgs::default().as_bytes().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn valid_deposit_checkpoint_verifies() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a checkpoint with a matching deposit cell must verify");
}

#[test]
fn wrong_deposit_to_key_rejected() {
    let (ctx, tx) = build(Cfg { bad_key: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "deposit to_key != proof must reject");
}

#[test]
fn wrong_deposit_amount_rejected() {
    let (ctx, tx) = build(Cfg { bad_amount: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "deposit amount != proof must reject");
}

#[test]
fn missing_deposit_cell_rejected() {
    let (ctx, tx) = build(Cfg { drop_deposit: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a proof crediting a deposit with no matching cell must reject"
    );
}

#[test]
fn broken_anchor_capacity_rejected() {
    let (ctx, tx) = build(Cfg { bad_anchor_cap: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "anchor capacity delta != Σdeposits (insolvent) must reject"
    );
}
