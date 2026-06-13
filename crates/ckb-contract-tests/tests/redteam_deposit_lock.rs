//! ADVERSARIAL red-team tests against the deposit lock (sweep/refund) and pool isolation.
//! Mirrors deposit_lock.rs but tries to BREAK the invariants.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::abs_epoch;

const MAX_CYCLES: u64 = 100_000_000;
const LOCK_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-deposit-lock";

const TIMEOUT: u64 = 1000;
const DEP_CAP: u64 = 100_00000000; // 100 CKB

// ---------------------------------------------------------------------------
// VECTOR 1: SWEEP — borrowed/forged type-hash cell to steal funds to attacker.
//
// The deposit lock sweep path returns 0 if ANY input bears `pool_type_hash`.
// It NEVER inspects the output destination on the sweep path. So if an attacker
// can place a cell bearing the pool anchor type-script hash as an input — WITHOUT
// it being a real, validated checkpoint — the deposit funds can be routed to the
// attacker. This test creates an attacker-owned cell carrying the pool type script
// (an always-success type stand-in, exactly as the existing positive test does),
// then routes ALL the deposit capacity to an attacker lock.
// ---------------------------------------------------------------------------
#[test]
fn sweep_borrowed_pooltype_cell_routes_funds_to_attacker() {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let pool_type = ctx.build_script(&as_op, Bytes::from(b"pool-anchor".to_vec())).unwrap();
    let attacker_lock = ctx.build_script(&as_op, Bytes::from(b"attacker".to_vec())).unwrap();
    let any_lock = ctx.build_script(&as_op, Bytes::from(b"any".to_vec())).unwrap();

    let pool_type_hash = pool_type.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();

    let mut args = Vec::with_capacity(72);
    args.extend_from_slice(pool_type_hash.as_slice());
    args.extend_from_slice(refund_lock_hash.as_slice());
    args.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    let to_key = [0x11u8; 32];
    let deposit_out = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock).build(),
        Bytes::from(to_key.to_vec()),
    );

    // Attacker fabricates a cell carrying the pool anchor type script. In v1 (empty-args
    // pools) the anchor type script is an ordinary type script; an attacker can deploy a
    // *fresh* anchor cell of the same contract (genesis, which "confers no power") and use
    // it as the borrowed input. Here we model it the same way the positive sweep test does:
    // an always-success cell carrying the very same `pool_type` script.
    let pool_cell = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(1_00000000u64.pack())
            .lock(any_lock)
            .type_(Some(pool_type).pack())
            .build(),
        Bytes::new(),
    );

    let b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .input(CellInput::new_builder().previous_output(pool_cell).build())
        .input(CellInput::new_builder().previous_output(deposit_out).build())
        // ALL deposit capacity goes to the ATTACKER, not the depositor or a real pool sweep.
        .output(
            CellOutput::new_builder()
                .capacity((DEP_CAP + 1_00000000).pack())
                .lock(attacker_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::default().as_bytes().pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    let tx = ctx.complete_tx(b.build());
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR1 borrowed-pooltype sweep-to-attacker result: {:?}", res);
    // If this PASSES, the deposit lock alone lets a borrowed/forged pool-type cell steal the
    // deposit. Whether that is a real theft depends on whether the anchor type script would
    // reject this tx as a checkpoint — but the DEPOSIT LOCK ITSELF does not enforce that.
    assert!(res.is_ok(), "demonstration: deposit lock unlocks on ANY input bearing pool_type_hash");
}

// ---------------------------------------------------------------------------
// VECTOR 2a: REFUND — relative-epoch since (no 0x20 absolute flag) should be rejected.
// abs_epoch requires top byte 0x20. A relative-epoch since (0xA0...) for the same number
// must NOT satisfy the timeout.
// ---------------------------------------------------------------------------
#[test]
fn refund_with_relative_epoch_since_rejected() {
    let (ctx, tx) = build_refund(0xA0u64 << 56 | TIMEOUT, true, DEP_CAP);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR2a relative-epoch since result: {:?}", res);
    assert!(res.is_err(), "a relative-epoch since must not satisfy the absolute-epoch timeout");
}

// VECTOR 2b: REFUND — block-number since (0x00 flag) must be rejected.
#[test]
fn refund_with_block_number_since_rejected() {
    // since = absolute block number TIMEOUT (top byte 0x00). abs_epoch returns None.
    let (ctx, tx) = build_refund(TIMEOUT, true, DEP_CAP);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR2b block-number since result: {:?}", res);
    assert!(res.is_err(), "a block-number since must not satisfy the epoch timeout");
}

// VECTOR 2c: REFUND — epoch fraction games. abs_epoch ignores the index/length fraction
// (low bits above 24). Encode timeout-1 in the epoch number but stuff a high fraction.
// CKB since absolute-epoch layout: 0x20 | (length<<40) | (index<<24) | number.
// We set number = TIMEOUT-1 but a big index/length — must still be rejected (e < timeout).
#[test]
fn refund_epoch_fraction_cannot_round_up() {
    // number = TIMEOUT-1, index=0xFFFF, length=0xFFFF (max fraction). e = TIMEOUT-1 < TIMEOUT.
    let since = (0x20u64 << 56) | (0xFFFFu64 << 40) | (0xFFFFu64 << 24) | (TIMEOUT - 1);
    let (ctx, tx) = build_refund(since, true, DEP_CAP);
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR2c fraction round-up result: {:?}", res);
    assert!(res.is_err(), "epoch fraction must not push a sub-timeout epoch over the timeout");
}

// VECTOR 2d: REFUND — split refund across attacker + depositor: pay depositor full but
// is there any way to ALSO siphon? The lock sums outputs to refund_lock_hash >= owed.
// Try: pay depositor exactly owed, but the tx ALSO has another deposit-lock input whose
// since is NOT mature, riding on the first's maturity. (group-wide since check)
#[test]
fn refund_second_immature_group_input_rejected() {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let pool_type = ctx.build_script(&as_op, Bytes::from(b"pool-anchor".to_vec())).unwrap();
    let pool_type_hash = pool_type.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();

    let mut args = Vec::with_capacity(72);
    args.extend_from_slice(pool_type_hash.as_slice());
    args.extend_from_slice(refund_lock_hash.as_slice());
    args.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    let to_key = [0x11u8; 32];
    // two deposit cells under the SAME lock => same lock group.
    let dep1 = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock.clone()).build(),
        Bytes::from(to_key.to_vec()),
    );
    let dep2 = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock).build(),
        Bytes::from(to_key.to_vec()),
    );

    let b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        // dep1 mature, dep2 immature.
        .input(
            CellInput::new_builder()
                .previous_output(dep1)
                .since(abs_epoch(TIMEOUT).pack())
                .build(),
        )
        .input(
            CellInput::new_builder()
                .previous_output(dep2)
                .since(abs_epoch(0).pack())
                .build(),
        )
        // pay BOTH back to depositor (full).
        .output(
            CellOutput::new_builder()
                .capacity((DEP_CAP * 2).pack())
                .lock(depositor_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::default().as_bytes().pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    let tx = ctx.complete_tx(b.build());
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR2d immature second group input result: {:?}", res);
    assert!(res.is_err(), "every group input's since must be mature; one immature must reject");
}

// VECTOR 3: THIRD-PARTY THEFT via refund-lock-hash collision is keccak/blake-hard; instead
// try: after timeout, pay depositor the FULL amount but in a tx that also has a separate
// (non-group) input the attacker controls, and an extra output to attacker funded by that
// input. This is legitimate (attacker funds their own output), NOT a break — skip.
// Real third-party attempt: refund output to refund_lock_hash but with LESS than owed while
// the rest goes to attacker. Covered by insufficient-capacity test. Here test the boundary:
// pay depositor exactly owed-1 with the deposit, rest to attacker.
#[test]
fn refund_underpay_by_one_routes_rest_to_attacker_rejected() {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let attacker_lock = ctx.build_script(&as_op, Bytes::from(b"attacker".to_vec())).unwrap();
    let pool_type = ctx.build_script(&as_op, Bytes::from(b"pool-anchor".to_vec())).unwrap();
    let pool_type_hash = pool_type.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();

    let mut args = Vec::with_capacity(72);
    args.extend_from_slice(pool_type_hash.as_slice());
    args.extend_from_slice(refund_lock_hash.as_slice());
    args.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    let to_key = [0x11u8; 32];
    let deposit_out = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock).build(),
        Bytes::from(to_key.to_vec()),
    );

    let b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .input(
            CellInput::new_builder()
                .previous_output(deposit_out)
                .since(abs_epoch(TIMEOUT).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity((DEP_CAP - 1).pack())
                .lock(depositor_lock)
                .build(),
        )
        .output_data(Bytes::new().pack())
        .output(CellOutput::new_builder().capacity(1u64.pack()).lock(attacker_lock).build())
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    let tx = ctx.complete_tx(b.build());
    let res = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("VECTOR3 underpay-by-one + attacker output result: {:?}", res);
    assert!(res.is_err(), "underpaying the depositor (rest to attacker) must reject");
}

// ---------------------------------------------------------------------------
// shared refund builder (single deposit cell, configurable since/dest/cap).
// ---------------------------------------------------------------------------
fn build_refund(since: u64, refund_to_depositor: bool, refund_cap: u64) -> (Context, TransactionView) {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let attacker_lock = ctx.build_script(&as_op, Bytes::from(b"attacker".to_vec())).unwrap();
    let pool_type = ctx.build_script(&as_op, Bytes::from(b"pool-anchor".to_vec())).unwrap();
    let pool_type_hash = pool_type.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();

    let mut args = Vec::with_capacity(72);
    args.extend_from_slice(pool_type_hash.as_slice());
    args.extend_from_slice(refund_lock_hash.as_slice());
    args.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    let to_key = [0x11u8; 32];
    let deposit_out = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock).build(),
        Bytes::from(to_key.to_vec()),
    );

    let out_lock = if refund_to_depositor { depositor_lock } else { attacker_lock };
    let b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .input(
            CellInput::new_builder()
                .previous_output(deposit_out)
                .since(since.pack())
                .build(),
        )
        .output(CellOutput::new_builder().capacity(refund_cap.pack()).lock(out_lock).build())
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::default().as_bytes().pack());

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}
