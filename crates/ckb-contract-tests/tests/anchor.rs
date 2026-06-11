//! Real CKB-VM integration tests for the Liquid Cells anchor type script.
//!
//! Builds a checkpoint transaction — one input anchor cell (state n), one output
//! anchor cell (state n+1), and a witness carrying `proof ‖ public_values` — from the
//! Phase-2a fixtures, and runs it through ckb-testtool's VM. The positive case must
//! verify; tampering any pinned field must be rejected. Cheap pins are checked before
//! the BN254 pairing, so the cell-tampering negatives fail fast; the public-values
//! tamper is caught by the proof itself (the slow path).
//!
//! Requires the contract built first:
//!   (cd crates/ckb-contract && cargo build --release)

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const PROOF_PATH: &str = "../../fixtures/groth16_proof.bin";
const PV_PATH: &str = "../../fixtures/public_values.bin";
const DA_PATH: &str = "../../fixtures/da_blob.bin";

// PublicValues offsets (must match liquid_cells_stf::PublicValues::encode).
const PV_PREV_ROOT: usize = 40;
const PV_PREV_SEQ: usize = 72;
const PV_NEW_ROOT: usize = 80;
const PV_NEW_SEQ: usize = 112;
const PV_PREV_TOTAL: usize = 184;
const PV_NEW_TOTAL: usize = 200;
const PV_FEE_DELTA: usize = 216;
const PV_CURRENT_EPOCH: usize = 232;
const PV_FEE_WD: usize = 240;

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

/// anchor data = root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE) ‖ last_epoch(8 BE)
fn anchor(root: &[u8], seq: u64, total: u128, fee: u128, last_epoch: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(80);
    a.extend_from_slice(root);
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(&total.to_be_bytes());
    a.extend_from_slice(&fee.to_be_bytes());
    a.extend_from_slice(&last_epoch.to_be_bytes());
    a
}

/// A CKB `since` flagged absolute-epoch with epoch number `e` (whole epoch).
fn abs_epoch(e: u64) -> u64 {
    (0x20u64 << 56) | e
}

#[derive(Clone, Default)]
struct Cfg {
    tamper_out_root: bool,
    bad_new_seq: bool,
    fee_mismatch: bool,
    tamper_pv: bool,
    ignore_fee_cap: bool, // output capacity ignores the L1 fee draw (breaks solvency)
    tamper_da: bool,      // published DA blob != the committed diff
    drop_da: bool,        // no DA blob published at all
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let proof = std::fs::read(PROOF_PATH).expect("fixtures/groth16_proof.bin");
    let mut pv = std::fs::read(PV_PATH).expect("fixtures/public_values.bin");
    let da = std::fs::read(DA_PATH).expect("fixtures/da_blob.bin");

    // Anchor states derived from the (possibly tampered) public values, so the
    // positive case is self-consistent and bind() passes.
    let prev_root = pv[PV_PREV_ROOT..PV_PREV_ROOT + 32].to_vec();
    let new_root = pv[PV_NEW_ROOT..PV_NEW_ROOT + 32].to_vec();
    let prev_seq = rd_u64(&pv, PV_PREV_SEQ);
    let new_seq = rd_u64(&pv, PV_NEW_SEQ);
    let prev_total = rd_u128(&pv, PV_PREV_TOTAL);
    let new_total = rd_u128(&pv, PV_NEW_TOTAL);
    let prev_fee: u128 = 0;

    if cfg.tamper_pv {
        // Flip a public-values byte (fee_delta) and rebuild the anchor to match, so
        // bind() passes and only the proof can catch it.
        pv[PV_FEE_DELTA] ^= 0xff;
    }
    // new_fee_acc = prev_fee_acc + fee_delta − fee_withdrawal.
    let fee_wd = rd_u128(&pv, PV_FEE_WD);
    let new_fee = prev_fee + rd_u128(&pv, PV_FEE_DELTA) - fee_wd;

    let mut out_root = new_root.clone();
    if cfg.tamper_out_root {
        out_root[0] ^= 0xff;
    }
    let out_seq = if cfg.bad_new_seq { new_seq + 1 } else { new_seq };
    let out_fee = if cfg.fee_mismatch { new_fee ^ 1 } else { new_fee };

    // The checkpoint records its epoch: prev anchor at genesis (0), new anchor at
    // current_epoch, and the input `since` is an absolute epoch ≥ current_epoch.
    let cur_epoch = rd_u64(&pv, PV_CURRENT_EPOCH);
    let prev_anchor = anchor(&prev_root, prev_seq, prev_total, prev_fee, 0);
    let new_anchor = anchor(&out_root, out_seq, new_total, out_fee, cur_epoch);

    // Transfer-only checkpoint: no deposit/withdrawal cells, so the anchor capacity must
    // drop by exactly the L1 fee draw (out_cap − in_cap == −fee_withdrawal).
    let in_cap: u64 = 1000;
    let out_cap: u64 = if cfg.ignore_fee_cap { in_cap } else { in_cap - fee_wd as u64 };

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();

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
    // input_type = proof ‖ pv; output_type = the published DA blob.
    let mut wb = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack());
    if !cfg.drop_da {
        let mut d = da.clone();
        if cfg.tamper_da {
            d[0] ^= 0xff;
        }
        wb = wb.output_type(Some(Bytes::from(d)).pack());
    }
    let w0 = wb.build().as_bytes();

    let tx = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(anchor_in)
                .since(abs_epoch(cur_epoch).pack())
                .build(),
        )
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
        .witness(w0.pack())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn valid_checkpoint_verifies() {
    let (ctx, tx) = build(Cfg::default());
    let cyc = ctx.verify_tx(&tx, MAX_CYCLES).expect("a valid checkpoint must verify");
    // Regression guard: the 3-pairing verifier (precomputed e(alpha,beta)) must stay under
    // the CKB block cycle limit (~3.50B). The 4-pairing form was ~3.81B and un-includable.
    assert!(cyc < 3_498_000_000, "checkpoint cycles {cyc} must stay under the CKB block limit");
}

#[test]
fn tampered_output_root_rejected() {
    let (ctx, tx) = build(Cfg { tamper_out_root: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "output root != proof.new_root must reject");
}

#[test]
fn wrong_new_seq_rejected() {
    let (ctx, tx) = build(Cfg { bad_new_seq: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "new_seq != prev_seq+1 must reject");
}

#[test]
fn fee_acc_mismatch_rejected() {
    let (ctx, tx) = build(Cfg { fee_mismatch: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "broken fee_acc continuity must reject");
}

#[test]
fn tampered_public_values_caught_by_proof() {
    // bind() passes (anchor rebuilt to match), so only the Groth16 proof can reject —
    // this exercises the full pairing path.
    let (ctx, tx) = build(Cfg { tamper_pv: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "tampered public values must fail the proof");
}

#[test]
fn ignored_fee_draw_in_capacity_rejected() {
    // The anchor output keeps the full input capacity (ignoring the proven L1 fee draw),
    // so out_cap − in_cap == 0 != −fee_withdrawal: the solvency check must reject it.
    let (ctx, tx) = build(Cfg { ignore_fee_cap: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "anchor capacity that ignores the L1 fee draw must reject"
    );
}

#[test]
fn tampered_da_blob_rejected() {
    // The published DA blob differs from the committed diff -> keccak(blob) != da_commitment.
    let (ctx, tx) = build(Cfg { tamper_da: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a tampered DA blob must reject");
}

#[test]
fn missing_da_blob_rejected() {
    // No DA blob published at all: the operator cannot advance the root while withholding it.
    let (ctx, tx) = build(Cfg { drop_da: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a withheld DA blob must reject");
}
