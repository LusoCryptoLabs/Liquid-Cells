//! Adversarial red-team tests for the anchor type script's checkpoint accounting,
//! value conservation, fee model and solvency arithmetic. Mirrors anchor.rs's builder
//! but injects malicious cell layouts the contract should reject.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{abs_epoch, anchor, rd_u128, rd_u64};

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const PROOF_PATH: &str = "../../fixtures/groth16_proof.bin";
const PV_PATH: &str = "../../fixtures/public_values.bin";
const DA_PATH: &str = "../../fixtures/da_blob.bin";

const PV_NEW_ROOT: usize = 80;
const PV_PREV_ROOT: usize = 40;
const PV_PREV_SEQ: usize = 72;
const PV_NEW_SEQ: usize = 112;
const PV_PREV_TOTAL: usize = 184;
const PV_NEW_TOTAL: usize = 200;
const PV_FEE_DELTA: usize = 216;
const PV_CURRENT_EPOCH: usize = 232;
const PV_FEE_WD: usize = 240;

const REWARD_MARKER: &[u8] = b"LIQUIDCELLS/v1/fee-reward";

/// Describes an extra non-anchor cell to inject.
#[derive(Clone)]
struct Extra {
    cap: u64,
    data: Vec<u8>,
    is_input: bool, // true => add as input (deposit), false => add as output
}

#[derive(Clone, Default)]
struct Cfg {
    extras: Vec<Extra>,
    // Override anchor capacities directly (defaults: in=1000, out=1000-fee_wd).
    in_cap_override: Option<u64>,
    out_cap_override: Option<u64>,
    // Add a second anchor cell (same type script) at output index > 0.
    second_anchor_output: bool,
    second_anchor_input: bool,
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let proof = std::fs::read(PROOF_PATH).expect("fixtures/groth16_proof.bin");
    let pv = std::fs::read(PV_PATH).expect("fixtures/public_values.bin");
    let da = std::fs::read(DA_PATH).expect("fixtures/da_blob.bin");

    let prev_root = pv[PV_PREV_ROOT..PV_PREV_ROOT + 32].to_vec();
    let new_root = pv[PV_NEW_ROOT..PV_NEW_ROOT + 32].to_vec();
    let prev_seq = rd_u64(&pv, PV_PREV_SEQ);
    let new_seq = rd_u64(&pv, PV_NEW_SEQ);
    let prev_total = rd_u128(&pv, PV_PREV_TOTAL);
    let new_total = rd_u128(&pv, PV_NEW_TOTAL);
    let prev_fee: u128 = 0;
    let fee_wd = rd_u128(&pv, PV_FEE_WD);
    let new_fee = prev_fee + rd_u128(&pv, PV_FEE_DELTA) - fee_wd;

    let cur_epoch = rd_u64(&pv, PV_CURRENT_EPOCH);
    let prev_anchor = anchor(&prev_root, prev_seq, prev_total, prev_fee, 0);
    let new_anchor = anchor(&new_root, new_seq, new_total, new_fee, cur_epoch);

    let in_cap: u64 = cfg.in_cap_override.unwrap_or(1000);
    let out_cap: u64 = cfg.out_cap_override.unwrap_or(1000 - fee_wd as u64);

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::from(Vec::<u8>::new())).unwrap();
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
    let wb = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(witness)).pack())
        .output_type(Some(Bytes::from(da.clone())).pack())
        .build()
        .as_bytes();

    let mut b = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(anchor_in)
                .since(abs_epoch(cur_epoch).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(out_cap.pack())
                .lock(lock.clone())
                .type_(Some(type_script.clone()).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor.clone()).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .witness(wb.pack());

    // Extra input cells (deposits).
    for e in cfg.extras.iter().filter(|e| e.is_input) {
        let op = ctx.create_cell(
            CellOutput::new_builder().capacity(e.cap.pack()).lock(lock.clone()).build(),
            Bytes::from(e.data.clone()),
        );
        b = b.input(CellInput::new_builder().previous_output(op).build());
    }
    // Extra output cells (withdrawals / rewards).
    for e in cfg.extras.iter().filter(|e| !e.is_input) {
        b = b
            .output(CellOutput::new_builder().capacity(e.cap.pack()).lock(lock.clone()).build())
            .output_data(Bytes::from(e.data.clone()).pack());
    }

    // Second anchor cells (same type script).
    if cfg.second_anchor_input {
        let op = ctx.create_cell(
            CellOutput::new_builder()
                .capacity(1000u64.pack())
                .lock(lock.clone())
                .type_(Some(type_script.clone()).pack())
                .build(),
            Bytes::from(new_anchor.clone()),
        );
        b = b.input(CellInput::new_builder().previous_output(op).build());
    }
    if cfg.second_anchor_output {
        b = b
            .output(
                CellOutput::new_builder()
                    .capacity(1000u64.pack())
                    .lock(lock.clone())
                    .type_(Some(type_script.clone()).pack())
                    .build(),
            )
            .output_data(Bytes::from(new_anchor.clone()).pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

// ============ VECTOR 1: unaccounted non-anchor input (phantom deposit) ============
#[test]
fn extra_deposit_input_breaks_dep_commitment() {
    // An extra non-anchor input (a "deposit") that the proof never committed. fold_cells
    // folds it into dep_commit, which then mismatches the proof's empty commitment.
    let cfg = Cfg {
        extras: vec![Extra { cap: 5000, data: vec![0u8; 32], is_input: true }],
        // Keep the anchor solvency eq satisfiable in isolation; CKB conservation handles the rest.
        ..Default::default()
    };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "an uncommitted deposit input must reject (dep_commit mismatch, code 55)"
    );
}

// ============ VECTOR 1b: unaccounted non-anchor output (phantom withdrawal) ========
#[test]
fn extra_withdrawal_output_breaks_wd_commitment() {
    let cfg = Cfg {
        extras: vec![Extra { cap: 500, data: vec![0u8; 32], is_input: false }],
        ..Default::default()
    };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "an uncommitted withdrawal output must reject (wd_commit mismatch, code 56)"
    );
}

// ============ VECTOR 5: <32-byte deposit input data ============
#[test]
fn short_data_deposit_input_rejected() {
    // A non-anchor input with <32 bytes of data: fold_cells returns Err(51).
    let cfg = Cfg {
        extras: vec![Extra { cap: 5000, data: vec![0u8; 8], is_input: true }],
        ..Default::default()
    };
    let (ctx, tx) = build(cfg);
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a <32-byte deposit input must reject (code 51)");
}

// ============ VECTOR 3: reward cell laundering a withdrawal ============
// Try to pay a user/attacker a real withdrawal but mark it as a reward so it dodges the
// wd commitment AND the solvency eq. Bounded only by sum_reward <= fee_wd (code 47).
#[test]
fn reward_marker_within_fee_wd_but_phantom_value() {
    // fee_wd in the fixture is 2. A reward of 2 is allowed (code 47 passes). The reward cell's
    // capacity (2) is NOT in the solvency eq, so the anchor capacities are unchanged by it.
    // The reward's 2 shts must come from somewhere in the tx (CKB conservation). Here we make
    // the anchor output 2 less to fund it -> but that breaks solvency (out-in != -fee_wd).
    // This checks whether a reward can be funded from the *anchor balance* (stealing user funds).
    let mut data = REWARD_MARKER.to_vec();
    data.extend_from_slice(&[0u8; 8]);
    let cfg = Cfg {
        extras: vec![Extra { cap: 2, data, is_input: false }],
        // Fund the reward by shrinking the anchor output below the solvency-correct value.
        out_cap_override: Some(1000 - 2 /*fee_wd*/ - 2 /*reward*/),
        ..Default::default()
    };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "funding a reward by shrinking the anchor must break solvency (code 58)"
    );
}

#[test]
fn reward_marker_exceeds_fee_wd_rejected() {
    // A reward of fee_wd+1 must reject (code 47) even though it dodges the wd commitment.
    let fee_wd = {
        let pv = std::fs::read(PV_PATH).unwrap();
        rd_u128(&pv, PV_FEE_WD) as u64
    };
    let mut data = REWARD_MARKER.to_vec();
    data.extend_from_slice(&[0u8; 8]);
    let cfg = Cfg {
        extras: vec![Extra { cap: fee_wd + 1, data, is_input: false }],
        ..Default::default()
    };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a reward exceeding fee_withdrawal must reject (code 47)"
    );
}

// ============ VECTOR 2: anchor capacity solvency tamper ============
#[test]
fn anchor_out_cap_too_high_mints_value() {
    // Make the output anchor capacity larger than solvency allows (no extra cells). The miner-fee
    // identity out_cap - in_cap == -fee_wd is violated -> code 58.
    let cfg = Cfg { out_cap_override: Some(1000), ..Default::default() }; // should be 1000-fee_wd
    let (ctx, tx) = build(cfg);
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "inflated anchor out cap must reject (code 58)");
}

// ============ VECTOR 2b: second anchor output (multiple anchors) ============
#[test]
fn second_anchor_output_rejected() {
    let cfg = Cfg { second_anchor_output: true, ..Default::default() };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a second anchor output (same type) must reject (code 40)"
    );
}

#[test]
fn second_anchor_input_rejected() {
    let cfg = Cfg { second_anchor_input: true, ..Default::default() };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a second anchor input (same type) must reject (code 40)"
    );
}

// ============ VECTOR 5b: reward marker as deposit input (asymmetry) ============
#[test]
fn reward_marker_on_input_is_treated_as_deposit() {
    // The reward marker only special-cases OUTPUTS. A non-anchor INPUT whose data starts with
    // the marker is still a deposit (folded into dep_commit). It has >=32 bytes so no 51, but it
    // breaks dep_commit -> code 55.
    let mut data = REWARD_MARKER.to_vec();
    data.extend_from_slice(&[0u8; 32]); // ensure >=32 bytes after marker
    let cfg =
        Cfg { extras: vec![Extra { cap: 5000, data, is_input: true }], ..Default::default() };
    let (ctx, tx) = build(cfg);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a marker-prefixed input is still a deposit and must break dep_commit (code 55)"
    );
}

// ============ Sanity: the unmodified build still verifies ============
#[test]
fn baseline_redteam_build_verifies() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("baseline must verify");
}
