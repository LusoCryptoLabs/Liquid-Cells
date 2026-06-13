//! VECTOR 1 (decisive): the deposit lock unlocks on ANY input bearing pool_type_hash and
//! never inspects the sweep destination. The ONLY thing standing between that and theft is
//! the ANCHOR type script's solvency check, which forces the deposit capacity into the new
//! anchor. This e2e test uses the REAL anchor contract (dw fixture checkpoint) AND the REAL
//! deposit lock, then tries to route the deposit's capacity to an attacker output.
//!
//! Two variants:
//!   * `_into_anchor`: capacity flows into the anchor (legit sweep) => MUST verify.
//!   * `_to_attacker`: capacity diverted to an attacker output => MUST reject (solvency).
//! If `_to_attacker` ever VERIFIES, that is a real deposit theft.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{abs_epoch, anchor, rd_u128, rd_u64};

const MAX_CYCLES: u64 = 5_000_000_000;
const ANCHOR_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const LOCK_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-deposit-lock";
const PROOF_PATH: &str = "../../fixtures/dw/groth16_proof.bin";
const PV_PATH: &str = "../../fixtures/dw/public_values.bin";
const DEPOSIT_PATH: &str = "../../fixtures/dw/deposit.bin";
const DA_PATH: &str = "../../fixtures/dw/da_blob.bin";

const PV_PREV_ROOT: usize = 40;
const PV_PREV_SEQ: usize = 72;
const PV_NEW_ROOT: usize = 80;
const PV_NEW_SEQ: usize = 112;
const PV_PREV_TOTAL: usize = 184;
const PV_NEW_TOTAL: usize = 200;
const PV_FEE_DELTA: usize = 216;
const PV_CURRENT_EPOCH: usize = 232;
const PV_FEE_WD: usize = 240;

const TIMEOUT: u64 = 1000;

fn build(divert_to_attacker: bool) -> (Context, TransactionView) {
    let anchor_bin: Bytes = std::fs::read(ANCHOR_BIN).expect("build anchor").into();
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build deposit-lock").into();
    let proof = std::fs::read(PROOF_PATH).expect("dw proof");
    let pv = std::fs::read(PV_PATH).expect("dw pv");
    let dep = std::fs::read(DEPOSIT_PATH).expect("dw deposit");
    let da = std::fs::read(DA_PATH).expect("dw da");

    let to_key = dep[0..32].to_vec();
    let amount = rd_u128(&dep, 32);

    let prev_root = pv[PV_PREV_ROOT..PV_PREV_ROOT + 32].to_vec();
    let new_root = pv[PV_NEW_ROOT..PV_NEW_ROOT + 32].to_vec();
    let prev_seq = rd_u64(&pv, PV_PREV_SEQ);
    let new_seq = rd_u64(&pv, PV_NEW_SEQ);
    let prev_total = rd_u128(&pv, PV_PREV_TOTAL);
    let new_total = rd_u128(&pv, PV_NEW_TOTAL);
    let fee_delta = rd_u128(&pv, PV_FEE_DELTA);
    let fee_wd = rd_u128(&pv, PV_FEE_WD);
    let cur_epoch = rd_u64(&pv, PV_CURRENT_EPOCH);

    let prev_anchor = anchor(&prev_root, prev_seq, prev_total, 0, 0);
    let new_anchor = anchor(&new_root, new_seq, new_total, fee_delta - fee_wd, cur_epoch);

    let in_cap = prev_total as u64;
    // Legit: anchor absorbs the deposit (out_cap = new_total). Divert: keep anchor flat and
    // try to send the deposit capacity to the attacker instead.
    let out_cap = if divert_to_attacker { in_cap } else { new_total as u64 };

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(anchor_bin);
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let attacker_lock = ctx.build_script(&as_op, Bytes::from(b"attacker".to_vec())).unwrap();

    // pool_type_hash = the REAL anchor type script hash (empty-args legacy pool).
    let pool_type_hash = type_script.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();
    let mut largs = Vec::with_capacity(72);
    largs.extend_from_slice(pool_type_hash.as_slice());
    largs.extend_from_slice(refund_lock_hash.as_slice());
    largs.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(largs)).unwrap();

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
        .output_type(Some(Bytes::from(da)).pack())
        .build()
        .as_bytes();

    // The deposit cell, guarded by the REAL deposit lock.
    let deposit_in = ctx.create_cell(
        CellOutput::new_builder().capacity((amount as u64).pack()).lock(deposit_lock).build(),
        Bytes::from(to_key),
    );

    let mut b = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(anchor_in)
                .since(abs_epoch(cur_epoch).pack())
                .build(),
        )
        .input(CellInput::new_builder().previous_output(deposit_in).build())
        .output(
            CellOutput::new_builder()
                .capacity(out_cap.pack())
                .lock(lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    if divert_to_attacker {
        // The diverted deposit capacity goes to the attacker.
        b = b
            .output(
                CellOutput::new_builder()
                    .capacity((amount as u64).pack())
                    .lock(attacker_lock)
                    .build(),
            )
            .output_data(Bytes::new().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn e2e_legit_sweep_into_anchor_verifies() {
    let (ctx, tx) = build(false);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("E2E legit sweep result: {:?}", res);
    res.expect("a legit sweep (deposit absorbed by anchor) must verify");
}

#[test]
fn e2e_sweep_diverted_to_attacker_must_reject() {
    let (ctx, tx) = build(true);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("E2E diverted-to-attacker result: {:?}", res);
    assert!(
        res.is_err(),
        "THEFT: deposit lock unlocked AND anchor solvency failed to stop diversion to attacker"
    );
}
