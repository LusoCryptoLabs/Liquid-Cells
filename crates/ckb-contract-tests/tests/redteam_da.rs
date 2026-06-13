//! VECTOR 5: DA binding. The checkpoint must publish da_blob in the anchor witness
//! output_type, and keccak(blob) must equal the proven da_commitment (code 59). Try to
//! advance the root while WITHHOLDING / ALTERING the blob.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{abs_epoch, anchor, rd_u128, rd_u64};

const MAX_CYCLES: u64 = 5_000_000_000;
const ANCHOR_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
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

#[derive(Clone, Copy)]
enum Da {
    Correct,
    Withheld,   // output_type = None (claims keccak(&[]))
    Empty,      // output_type = Some(empty bytes)
    Truncated,  // output_type = blob[..len-1]
    Extended,   // output_type = blob ++ 0x00
}

fn build(da_mode: Da) -> (Context, TransactionView) {
    let anchor_bin: Bytes = std::fs::read(ANCHOR_BIN).expect("build anchor").into();
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
    let out_cap = new_total as u64;

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(anchor_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let dep_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();

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

    let wb = WitnessArgs::new_builder().input_type(Some(Bytes::from(witness)).pack());
    let w0 = match da_mode {
        Da::Correct => wb.output_type(Some(Bytes::from(da.clone())).pack()),
        Da::Withheld => wb, // no output_type
        Da::Empty => wb.output_type(Some(Bytes::new()).pack()),
        Da::Truncated => {
            let t = da[..da.len() - 1].to_vec();
            wb.output_type(Some(Bytes::from(t)).pack())
        }
        Da::Extended => {
            let mut e = da.clone();
            e.push(0);
            wb.output_type(Some(Bytes::from(e)).pack())
        }
    }
    .build()
    .as_bytes();

    let deposit_in = ctx.create_cell(
        CellOutput::new_builder().capacity((amount as u64).pack()).lock(dep_lock).build(),
        Bytes::from(to_key),
    );

    let b = TransactionBuilder::default()
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
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn da_correct_blob_verifies() {
    let (ctx, tx) = build(Da::Correct);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("DA correct result: {:?}", res);
    res.expect("the correct DA blob must verify");
}

#[test]
fn da_withheld_blob_rejected() {
    let (ctx, tx) = build(Da::Withheld);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("DA withheld result: {:?}", res);
    assert!(res.is_err(), "advancing the root while withholding the DA blob must reject");
}

#[test]
fn da_empty_blob_rejected() {
    let (ctx, tx) = build(Da::Empty);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("DA empty result: {:?}", res);
    assert!(res.is_err(), "an empty blob (keccak(&[]) != commitment) must reject");
}

#[test]
fn da_truncated_blob_rejected() {
    let (ctx, tx) = build(Da::Truncated);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("DA truncated result: {:?}", res);
    assert!(res.is_err(), "a truncated blob must reject");
}

#[test]
fn da_extended_blob_rejected() {
    let (ctx, tx) = build(Da::Extended);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("DA extended result: {:?}", res);
    assert!(res.is_err(), "a length-extended blob must reject");
}
