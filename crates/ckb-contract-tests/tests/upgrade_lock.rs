//! Timelocked upgrade lock: an upgrade of the (type-id'd) code cell may proceed only with a
//! governance-locked announcement that committed to the new code's data hash and has matured
//! `delay` epochs (relative-epoch `since`). Tampering any of those must reject.
//!
//! Requires the lock built first: (cd crates/ckb-contract && cargo build --release).
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;

const MAX_CYCLES: u64 = 100_000_000;
const LOCK_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-upgrade-lock";
const DELAY: u64 = 100;

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = ckb_testtool::ckb_hash::new_blake2b();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}
/// relative-epoch since: top byte 0xA0, value = epoch count.
fn rel_epoch(n: u64) -> u64 {
    (0xA0u64 << 56) | n
}
/// absolute-epoch since (for the negative test).
fn abs_epoch(n: u64) -> u64 {
    (0x20u64 << 56) | n
}

#[derive(Default, Clone)]
struct Cfg {
    since: Option<u64>,    // override the announcement input's since (default: rel_epoch(DELAY))
    wrong_commitment: bool, // announcement commits to other-than-the-new-code's data hash
    non_gov_announcement: bool, // announcement not locked by governance
    no_new_code: bool,     // no output carries the code cell's type
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let lock_bin: Bytes = std::fs::read(LOCK_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let lock_op = ctx.deploy_cell(lock_bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());

    // governance lock, the code cell's type-id, and the upgrade lock (args = gov_hash ‖ delay).
    let gov = ctx.build_script(&as_op, Bytes::from(b"governance".to_vec())).unwrap();
    let gov_hash = gov.calc_script_hash();
    let type_id = ctx.build_script(&as_op, Bytes::from(b"type-id".to_vec())).unwrap();
    let mut args = gov_hash.as_slice().to_vec();
    args.extend_from_slice(&DELAY.to_be_bytes());
    let upgrade_lock = ctx.build_script(&lock_op, Bytes::from(args)).unwrap();

    // the NEW code cell (output) and its data hash (what an honest announcement commits to).
    let new_code = Bytes::from(b"the new anchor verifier bytes v2".to_vec());
    let new_code_hash = blake2b256(&new_code);
    let commitment = if cfg.wrong_commitment { blake2b256(b"a different upgrade") } else { new_code_hash };

    // old code cell (this lock) + a governance-locked announcement committing to the new code.
    let old_code = ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(upgrade_lock).type_(Some(type_id.clone()).pack()).build(),
        Bytes::from(b"old verifier bytes v1".to_vec()),
    );
    let ann_lock = if cfg.non_gov_announcement {
        ctx.build_script(&as_op, Bytes::from(b"not-governance".to_vec())).unwrap()
    } else {
        gov.clone()
    };
    let announce = ctx.create_cell(
        CellOutput::new_builder().capacity(200u64.pack()).lock(ann_lock).build(),
        Bytes::from(commitment.to_vec()),
    );

    let new_code_type = if cfg.no_new_code { ctx.build_script(&as_op, Bytes::from(b"other-type".to_vec())).unwrap() } else { type_id };
    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(old_code).build())
        .input(
            CellInput::new_builder()
                .previous_output(announce)
                .since(cfg.since.unwrap_or_else(|| rel_epoch(DELAY)).pack())
                .build(),
        )
        .output(CellOutput::new_builder().capacity(1100u64.pack()).lock(ctx.build_script(&as_op, Bytes::new()).unwrap()).type_(Some(new_code_type).pack()).build())
        .output_data(new_code.pack())
        .cell_dep(CellDep::new_builder().out_point(lock_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(Bytes::new().pack())
        .witness(Bytes::new().pack());
    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn matured_governance_announcement_authorizes_upgrade() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("an announced, matured, governance upgrade must verify");
}

#[test]
fn upgrade_before_delay_rejected() {
    let (ctx, tx) = build(Cfg { since: Some(rel_epoch(DELAY - 1)), ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "an announcement younger than `delay` must reject");
}

#[test]
fn absolute_since_announcement_rejected() {
    // the delay must be a *relative*-epoch since (measured from the announcement's own block);
    // an absolute-epoch since can't prove the cell aged `delay` and must reject.
    let (ctx, tx) = build(Cfg { since: Some(abs_epoch(DELAY)), ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "absolute-epoch since must reject");
}

#[test]
fn upgrade_to_uncommitted_code_rejected() {
    // the announcement committed to a different upgrade than the one in the outputs.
    let (ctx, tx) = build(Cfg { wrong_commitment: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "new code not matching the announced commitment must reject");
}

#[test]
fn non_governance_announcement_rejected() {
    let (ctx, tx) = build(Cfg { non_gov_announcement: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "announcement not locked by governance must reject");
}

#[test]
fn upgrade_without_replacement_code_cell_rejected() {
    let (ctx, tx) = build(Cfg { no_new_code: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no replacement code cell of the type-id must reject");
}
