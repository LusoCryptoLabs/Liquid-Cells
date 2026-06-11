//! Withdrawal-binding (+ combined deposit) integration tests, Phase 2b-4.
//!
//! Uses `fixtures/wd/`, whose checkpoint has both a real deposit and a real withdrawal.
//! The tx carries the deposit as a non-anchor input and the withdrawal as a non-anchor
//! output whose lock hash equals the one the proof committed (built identically to the
//! `wd_target` helper). The type script recomputes both commitments from the cells and
//! checks conservation. Tampering the withdrawal lock / amount, or dropping the output,
//! must be rejected.
//!
//! Requires: `cargo run --bin wd_target`, then the contract built and `fixtures/wd/`
//! generated (`scripts/groth16.sh ... wd`).

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 5_000_000_000;
use liquid_cells_ckb_tests::{withdraw_lock, withdraw_lock_with};

const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const DIR: &str = "../../fixtures/wd";

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
    bad_wd_lock: bool,   // withdrawal output lock != the committed target
    bad_wd_amount: bool, // withdrawal output capacity != the proven amount
    drop_wd: bool,       // omit the withdrawal output
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let proof = std::fs::read(format!("{DIR}/groth16_proof.bin")).expect("fixtures/wd proof");
    let pv = std::fs::read(format!("{DIR}/public_values.bin")).expect("fixtures/wd pv");
    let dep = std::fs::read(format!("{DIR}/deposit.bin")).expect("fixtures/wd deposit.bin");
    let wdr = std::fs::read(format!("{DIR}/withdrawal.bin")).expect("fixtures/wd withdrawal.bin");

    let dep_key = dep[0..32].to_vec();
    let dep_amount = rd_u128(&dep, 32) as u64;
    let wd_target = wdr[0..32].to_vec();
    let wd_amount = rd_u128(&wdr, 32) as u64;

    let prev_root = pv[PV_PREV_ROOT..PV_PREV_ROOT + 32].to_vec();
    let new_root = pv[PV_NEW_ROOT..PV_NEW_ROOT + 32].to_vec();
    let prev_seq = rd_u64(&pv, PV_PREV_SEQ);
    let new_seq = rd_u64(&pv, PV_NEW_SEQ);
    let prev_total = rd_u128(&pv, PV_PREV_TOTAL);
    let new_total = rd_u128(&pv, PV_NEW_TOTAL);
    let fee_delta = rd_u128(&pv, PV_FEE_DELTA);

    let prev_anchor = anchor(&prev_root, prev_seq, prev_total, 0);
    let new_anchor = anchor(&new_root, new_seq, new_total, fee_delta);
    let in_cap = prev_total as u64; // anchor capacity == pool total
    let out_cap = new_total as u64;

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let dep_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();

    // Withdrawal output lock — the shared deterministic lock (== wd_target helper), so
    // its hash equals the proven target (sanity-checked here).
    let wlock = if cfg.bad_wd_lock { withdraw_lock_with(b"wrong-target") } else { withdraw_lock() };
    if !cfg.bad_wd_lock {
        let h: [u8; 32] = wlock.calc_script_hash().unpack();
        assert_eq!(h.to_vec(), wd_target, "test withdrawal lock must match the proven target");
    }

    let anchor_in = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(in_cap.pack())
            .lock(lock.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        Bytes::from(prev_anchor),
    );
    let deposit_in = ctx.create_cell(
        CellOutput::new_builder().capacity(dep_amount.pack()).lock(dep_lock).build(),
        Bytes::from(dep_key),
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

    if !cfg.drop_wd {
        let cap = if cfg.bad_wd_amount { wd_amount + 1 } else { wd_amount };
        b = b
            .output(CellOutput::new_builder().capacity(cap.pack()).lock(wlock).build())
            .output_data(Bytes::new().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn deposit_and_withdrawal_checkpoint_verifies() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a checkpoint with matching deposit + withdrawal cells must verify");
}

#[test]
fn wrong_withdrawal_lock_rejected() {
    let (ctx, tx) = build(Cfg { bad_wd_lock: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "withdrawal lock != proven target must reject");
}

#[test]
fn wrong_withdrawal_amount_rejected() {
    let (ctx, tx) = build(Cfg { bad_wd_amount: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "withdrawal amount != proof must reject");
}

#[test]
fn missing_withdrawal_output_rejected() {
    let (ctx, tx) = build(Cfg { drop_wd: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a proof debiting a withdrawal with no matching output must reject"
    );
}
