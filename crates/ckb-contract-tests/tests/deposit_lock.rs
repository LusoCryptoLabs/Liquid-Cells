//! Deposit-lock tests: a deposit cell's CKB can move ONLY into a pool checkpoint (sweep) or,
//! after a timeout, back to the depositor (refund). It can never be taken by a third party,
//! which is the always-success window this lock closes.
//!
//! The lock is isolated from the real anchor here: the "pool anchor" input is an always-success
//! stand-in whose script hash is bound as `pool_type_hash`, so these tests exercise the lock's
//! own logic (the anchor type script's deposit-crediting is covered by `deposit.rs`). Requires
//! the contract built: `cargo build --release` in crates/ckb-contract.
//!
//! Cross-pool isolation: the sweep path matches the deposit against ONE specific
//! `pool_type_hash`, so a deposit bound to pool A cannot be swept into a different pool B.
//! Two type-id'd anchors have distinct type-script hashes by construction (their type-id args
//! differ), so binding a deposit to a type-id'd anchor isolates it to that exact pool. A second
//! always-success stand-in with different args models pool B (a distinct hash), exercising that
//! the lock refuses a foreign-pool checkpoint.

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::TransactionView;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{abs_epoch};

const MAX_CYCLES: u64 = 100_000_000;
const LOCK_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-deposit-lock";

const TIMEOUT: u64 = 1000;
const DEP_CAP: u64 = 100_00000000; // 100 CKB


#[derive(Clone)]
enum Spend {
    /// Spent alongside an input carrying the pool anchor type script (a checkpoint).
    SweepWithPoolInput,
    /// Spent alongside a checkpoint of a DIFFERENT pool (a distinct anchor type hash). Models a
    /// type-id'd pool B trying to sweep a deposit bound to pool A: the lock must refuse.
    SweepWithForeignPool,
    /// Spent without any pool input. `since` epoch, and where the (single) output's capacity goes.
    NoPool { since_epoch: u64, refund_to_depositor: bool, refund_cap: u64 },
}

fn build(spend: Spend) -> (Context, TransactionView) {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();

    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // Precompute every script up front (avoids overlapping &mut ctx borrows in the builders).
    let depositor_lock = ctx.build_script(&as_op, Bytes::from(b"depositor".to_vec())).unwrap();
    let pool_type = ctx.build_script(&as_op, Bytes::from(b"pool-anchor".to_vec())).unwrap();
    // A different pool's anchor type script: same code, different args => a distinct type hash,
    // exactly as two type-id'd anchors differ. A deposit bound to `pool_type` must not be
    // sweepable into this one.
    let foreign_pool_type =
        ctx.build_script(&as_op, Bytes::from(b"foreign-pool-anchor".to_vec())).unwrap();
    let attacker_lock = ctx.build_script(&as_op, Bytes::from(b"attacker".to_vec())).unwrap();
    let pool_lock = ctx.build_script(&as_op, Bytes::from(b"pool-lock".to_vec())).unwrap();
    let sink_lock = ctx.build_script(&as_op, Bytes::from(b"sink".to_vec())).unwrap();

    let pool_type_hash = pool_type.calc_script_hash();
    let refund_lock_hash = depositor_lock.calc_script_hash();

    // deposit-lock args: pool_type_hash(32) ‖ refund_lock_hash(32) ‖ timeout(8 BE)
    let mut args = Vec::with_capacity(72);
    args.extend_from_slice(pool_type_hash.as_slice());
    args.extend_from_slice(refund_lock_hash.as_slice());
    args.extend_from_slice(&TIMEOUT.to_be_bytes());
    let deposit_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    // The deposit cell: capacity = amount, data = to_key, lock = deposit-lock.
    let to_key = [0x11u8; 32];
    let deposit_out = ctx.create_cell(
        CellOutput::new_builder().capacity(DEP_CAP.pack()).lock(deposit_lock).build(),
        Bytes::from(to_key.to_vec()),
    );

    let mut b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build());

    match spend {
        Spend::SweepWithPoolInput => {
            // input[0] = a cell carrying the pool anchor type script (the checkpoint).
            let pool_cell = ctx.create_cell(
                CellOutput::new_builder()
                    .capacity(50_00000000u64.pack())
                    .lock(pool_lock)
                    .type_(Some(pool_type).pack())
                    .build(),
                Bytes::new(),
            );
            b = b
                .input(CellInput::new_builder().previous_output(pool_cell).build())
                .input(CellInput::new_builder().previous_output(deposit_out).build())
                // one output: the swept funds (lock irrelevant to the deposit lock on the sweep path).
                .output(
                    CellOutput::new_builder()
                        .capacity((DEP_CAP + 50_00000000).pack())
                        .lock(sink_lock)
                        .build(),
                )
                .output_data(Bytes::new().pack())
                .witness(WitnessArgs::default().as_bytes().pack())
                .witness(WitnessArgs::default().as_bytes().pack());
        }
        Spend::SweepWithForeignPool => {
            // input[0] = a checkpoint of a DIFFERENT pool (foreign_pool_type, a distinct hash).
            // The deposit is bound to `pool_type`, so the sweep path must not match.
            let foreign_cell = ctx.create_cell(
                CellOutput::new_builder()
                    .capacity(50_00000000u64.pack())
                    .lock(pool_lock)
                    .type_(Some(foreign_pool_type).pack())
                    .build(),
                Bytes::new(),
            );
            b = b
                .input(CellInput::new_builder().previous_output(foreign_cell).build())
                .input(CellInput::new_builder().previous_output(deposit_out).build())
                .output(
                    CellOutput::new_builder()
                        .capacity((DEP_CAP + 50_00000000).pack())
                        .lock(sink_lock)
                        .build(),
                )
                .output_data(Bytes::new().pack())
                .witness(WitnessArgs::default().as_bytes().pack())
                .witness(WitnessArgs::default().as_bytes().pack());
        }
        Spend::NoPool { since_epoch, refund_to_depositor, refund_cap } => {
            let out_lock = if refund_to_depositor { depositor_lock } else { attacker_lock };
            b = b
                .input(
                    CellInput::new_builder()
                        .previous_output(deposit_out)
                        .since(abs_epoch(since_epoch).pack())
                        .build(),
                )
                .output(CellOutput::new_builder().capacity(refund_cap.pack()).lock(out_lock).build())
                .output_data(Bytes::new().pack())
                .witness(WitnessArgs::default().as_bytes().pack());
        }
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn sweep_into_a_pool_checkpoint_verifies() {
    let (ctx, tx) = build(Spend::SweepWithPoolInput);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a deposit consumed by a pool checkpoint must unlock");
}

#[test]
fn sweep_into_a_foreign_pool_rejected() {
    // Cross-pool isolation: a deposit bound to pool A's anchor type hash must not be sweepable by
    // a checkpoint of a different pool B (a distinct type hash, as every type-id'd pool has). This
    // is what binding a deposit to a type-id'd anchor buys: the sweep credit can only ever land in
    // the one pool the depositor chose.
    let (ctx, tx) = build(Spend::SweepWithForeignPool);
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a deposit bound to one pool must not be swept into a different pool"
    );
}

#[test]
fn refund_to_depositor_after_timeout_verifies() {
    let (ctx, tx) =
        build(Spend::NoPool { since_epoch: TIMEOUT, refund_to_depositor: true, refund_cap: DEP_CAP });
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a timed-out deposit refunding to the depositor must unlock");
}

#[test]
fn refund_before_timeout_rejected() {
    let (ctx, tx) = build(Spend::NoPool {
        since_epoch: TIMEOUT - 1,
        refund_to_depositor: true,
        refund_cap: DEP_CAP,
    });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a deposit must not be refundable before its timeout epoch"
    );
}

#[test]
fn theft_to_a_third_party_after_timeout_rejected() {
    // The whole point: even after the timeout, the deposit can only go to the depositor, never to
    // an attacker's lock. This is the always-success window that is now closed.
    let (ctx, tx) = build(Spend::NoPool {
        since_epoch: TIMEOUT + 5,
        refund_to_depositor: false,
        refund_cap: DEP_CAP,
    });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a deposit must never be spendable to a third party"
    );
}

#[test]
fn theft_to_a_third_party_before_timeout_rejected() {
    let (ctx, tx) = build(Spend::NoPool {
        since_epoch: 0,
        refund_to_depositor: false,
        refund_cap: DEP_CAP,
    });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no third-party spend, ever");
}

#[test]
fn refund_with_insufficient_capacity_rejected() {
    // Refund output goes to the depositor but underpays: the lock must reject (can't skim the
    // deposit by routing only part of it back).
    let (ctx, tx) = build(Spend::NoPool {
        since_epoch: TIMEOUT,
        refund_to_depositor: true,
        refund_cap: DEP_CAP - 1_00000000,
    });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a refund must return at least the full deposit to the depositor"
    );
}
