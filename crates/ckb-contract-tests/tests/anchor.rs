//! Real CKB-VM integration tests for the Liquid Cells anchor type script.
//!
//! Builds a checkpoint transaction, one input anchor cell (state n), one output
//! anchor cell (state n+1), and a witness carrying `proof ‖ public_values`, from the
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
use liquid_cells_ckb_tests::{abs_epoch,anchor,rd_u128,rd_u64};

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


/// anchor data = root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE) ‖ last_epoch(8 BE)

/// A CKB `since` flagged absolute-epoch with epoch number `e` (whole epoch).

#[derive(Clone, Default)]
struct Cfg {
    tamper_out_root: bool,
    bad_new_seq: bool,
    fee_mismatch: bool,
    tamper_pv: bool,
    ignore_fee_cap: bool, // output capacity ignores the L1 fee draw (breaks solvency)
    tamper_da: bool,      // published DA blob != the committed diff
    drop_da: bool,        // no DA blob published at all
    change_lock: bool,    // output anchor lock != input anchor lock (capture attempt)
    reward: bool,         // add a marked sequencer-reward output of exactly fee_withdrawal (valid)
    reward_over: bool,    // add a reward output of fee_withdrawal + 1 (must reject)
    type_id_args: Option<Vec<u8>>, // anchor type-script args: None/empty = legacy baked POOL_ID;
                                   // Some(32 bytes) = a type-id'd pool whose pool_id IS those bytes
}

/// A non-anchor output whose data starts with this marker is a sequencer reward cell (must match
/// the contract's REWARD_MARKER).
const REWARD_MARKER: &[u8] = b"LIQUIDCELLS/v1/fee-reward";

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
    let ts_args = cfg.type_id_args.clone().unwrap_or_default();
    let type_script = ctx.build_script(&contract_op, Bytes::from(ts_args)).unwrap();
    // The anchor lock here is always-success (different args ⇒ different hash), i.e. these
    // checkpoints are *permissionless*: no signature gates them, only the type script. The
    // output anchor must keep the SAME lock (continuity); `change_lock` swaps it to model a
    // capture attempt that re-locks the pool.
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let other_lock = ctx.build_script(&as_op, Bytes::from(b"capture-lock".to_vec())).unwrap();
    let out_lock = if cfg.change_lock { other_lock } else { lock.clone() };

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
                .lock(out_lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op.clone()).build())
        .witness(w0.pack());

    if cfg.reward || cfg.reward_over {
        // A sequencer reward cell: a non-anchor output, data marked, paid out of fee_withdrawal.
        // Exactly fee_withdrawal is valid (miner fee then 0); one over must reject (code 47).
        let reward_cap = if cfg.reward_over { fee_wd as u64 + 1 } else { fee_wd as u64 };
        let reward_lock = ctx.build_script(&as_op, Bytes::from(b"seq-reward".to_vec())).unwrap();
        b = b
            .output(CellOutput::new_builder().capacity(reward_cap.pack()).lock(reward_lock).build())
            .output_data(Bytes::from(REWARD_MARKER.to_vec()).pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn valid_checkpoint_verifies() {
    let (ctx, tx) = build(Cfg::default());
    let cyc = ctx.verify_tx(&tx, MAX_CYCLES).expect("a valid checkpoint must verify");
    // Regression guard. The ark-bn254 verifier does the plain 4-pairing Groth16 check at ~80M
    // cycles with the size-optimized (opt-z) build, ~2.3% of CKB's ~3.50B block limit (the
    // opt-level=3 build was ~53M). The old substrate-bn verifier needed a 3-pairing e(alpha,beta)
    // precompute just to fit at ~3.47B (99.3%); ark removed that need.
    assert!(cyc < 150_000_000, "checkpoint cycles {cyc} regressed (ark verifier should be ~80M)");
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
    // bind() passes (anchor rebuilt to match), so only the Groth16 proof can reject, 
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

#[test]
fn anchor_lock_change_rejected() {
    // Anchor lock continuity: an otherwise-valid checkpoint that re-locks the output anchor to a
    // different lock is a capture attempt (it would seize sequencing of a permissionless pool).
    // It must reject regardless of the proof being valid.
    let (ctx, tx) = build(Cfg { change_lock: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "changing the anchor lock across a checkpoint must reject (capture-proof)"
    );
}

#[test]
fn sequencer_reward_accepted() {
    // Phase 6b: a marked reward cell paying exactly the proven fee_withdrawal to the sequencer is
    // accepted (excluded from withdrawals, the L1 miner fee then being fee_withdrawal - reward).
    let (ctx, tx) = build(Cfg { reward: true, ..Default::default() });
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a reward within fee_withdrawal must verify");
}

#[test]
fn reward_exceeds_fee_withdrawal_rejected() {
    // A reward larger than the proven fee_withdrawal would have to come from a user balance, so
    // it must reject (code 47).
    let (ctx, tx) = build(Cfg { reward_over: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a reward exceeding fee_withdrawal must reject"
    );
}

/// The pool_id baked into the fixture's public values (= the legacy baked POOL_ID).
fn fixture_pool_id() -> Vec<u8> {
    std::fs::read(PV_PATH).expect("fixtures/public_values.bin")[0..32].to_vec()
}

#[test]
fn checkpoint_for_a_type_id_pool_verifies() {
    // A type-id'd pool carries its pool_id as 32-byte type-script args; the contract derives
    // pool_id from the args, not the baked constant. The fixture's pool_id is the baked value, so
    // set the args to it, the proof must still verify against the args-derived pool_id.
    let (ctx, tx) = build(Cfg { type_id_args: Some(fixture_pool_id()), ..Default::default() });
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a checkpoint for a type-id'd pool must verify");
}

#[test]
fn checkpoint_with_wrong_pool_args_rejected() {
    // Anchor args (the claimed pool_id) that don't match the proof's pool_id must reject (code 31),
    // before the pairing. This is what makes a type-id'd pool bound to exactly its own proofs.
    let mut wrong = fixture_pool_id();
    wrong[0] ^= 0xff;
    let (ctx, tx) = build(Cfg { type_id_args: Some(wrong), ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a checkpoint whose anchor args mismatch the proof's pool_id must reject"
    );
}
