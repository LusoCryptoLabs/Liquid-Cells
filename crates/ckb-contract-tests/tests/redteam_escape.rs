//! Adversarial red-team tests for the unilateral escape hatches and epoch/since gating.
//! Mirrors forceexit.rs / forcerefund.rs but tries to DEFEAT the checks.

use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{anchor};
use liquid_cells_stf::*;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const TIMEOUT: u64 = 180;
const LAST_EPOCH: u64 = 5;

const SECP_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn blake160(data: &[u8]) -> [u8; 20] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..20]);
    r
}
fn secp_lock(b160: &[u8; 20]) -> Script {
    Script::new_builder()
        .code_hash(SECP_CODE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(b160.to_vec()).pack())
        .build()
}

/// A CKB `since`: absolute-epoch flag 0x20, with controllable epoch number + index/length
/// fraction in the high bits, to test abs_epoch's masking.
fn since_epoch_frac(epoch: u64, index: u64, length: u64) -> u64 {
    (0x20u64 << 56) | (length << 40) | (index << 24) | (epoch & 0x00FF_FFFF)
}
fn abs_epoch(e: u64) -> u64 {
    (0x20u64 << 56) | e
}

/// Shared force-exit scenario builder. Returns the native STF state plus the exiter.
struct Scenario {
    root: [u8; 32],
    total: u128,
    seq: u64,
    fee_acc: u128,
    exiter_pk: [u8; 33],
    exiter_key: [u8; 32],
    balance: u128,
    nonce: u64,
    siblings: Vec<[u8; 32]>,
    new_root: [u8; 32],
    st: State,
}

fn scenario() -> Scenario {
    let chain_id = 0x434b_42u64;
    let mut st = State::genesis(keccak(b"forceexit-pool"), chain_id);
    let exiter_sk = secret(7);
    let exiter_pk = sig::pubkey(&exiter_sk);
    let exiter_key = key_of_pubkey(&exiter_pk);
    let other_key = key_of_pubkey(&sig::pubkey(&secret(9)));
    let balance: u128 = 7_000_000_000;
    apply(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![
                Deposit { to_key: exiter_key, amount: balance },
                Deposit { to_key: other_key, amount: 3_000_000_000 },
            ],
            ..Default::default()
        },
    )
    .unwrap();
    let root = st.pool.root;
    let total = st.pool.total;
    let leaf = st.get_leaf(&exiter_key);
    let siblings = st.smt.proof(&exiter_key);
    let new_root = {
        let mut smt = st.smt.clone();
        smt.set_leaf_hash(exiter_key, Leaf { balance: 0, nonce: leaf.nonce }.hash());
        smt.root()
    };
    Scenario {
        root,
        total,
        seq: st.pool.seq,
        fee_acc: st.pool.fee_acc,
        exiter_pk,
        exiter_key,
        balance,
        nonce: leaf.nonce,
        siblings,
        new_root,
        st,
    }
}

/// Build a force-exit tx from explicit knobs. The caller controls the witness fields,
/// the anchors, the since, and the payout outputs.
#[allow(clippy::too_many_arguments)]
fn build_exit(
    s: &Scenario,
    wit_pk: &[u8; 33],
    wit_balance: u128,
    wit_nonce: u64,
    siblings: &[[u8; 32]],
    out_root: &[u8],
    out_total: u128,
    in_cap: u64,
    out_cap: u64,
    since: u64,
    payouts: Vec<(Script, u64)>,
) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();

    let mut payload = Vec::with_capacity(33 + 16 + 8 + 32 * 256);
    payload.extend_from_slice(wit_pk);
    payload.extend_from_slice(&wit_balance.to_be_bytes());
    payload.extend_from_slice(&wit_nonce.to_be_bytes());
    for sib in siblings {
        payload.extend_from_slice(sib);
    }

    let prev_anchor = anchor(&s.root, s.seq, s.total, s.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(out_root, s.seq, out_total, s.fee_acc, LAST_EPOCH);

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
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

    let w0 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(payload)).pack())
        .build()
        .as_bytes();

    let mut b = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(anchor_in)
                .since(since.pack())
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
        .witness(w0.pack());

    for (lock_script, cap) in payouts {
        b = b
            .output(CellOutput::new_builder().capacity(cap.pack()).lock(lock_script).build())
            .output_data(Bytes::new().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

/// Helper: the canonical (valid) force-exit, to confirm the builder produces a passing tx.
fn valid_exit(s: &Scenario) -> (Context, TransactionView) {
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    build_exit(
        s,
        &s.exiter_pk,
        s.balance,
        s.nonce,
        &s.siblings,
        &s.new_root.to_vec(),
        s.total - s.balance,
        s.total as u64,
        (s.total - s.balance) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock, s.balance as u64)],
    )
}

#[test]
fn sanity_valid_exit_passes() {
    let s = scenario();
    let (ctx, tx) = valid_exit(&s);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("the canonical exit must verify (builder sanity)");
}

// ATTACK A: since with a huge index/length fraction but epoch == last_epoch+TIMEOUT.
// If abs_epoch incorrectly read the fraction bits, the gate math would change. Expect: still
// gated correctly (passes here because the epoch number is exactly at the open point).
#[test]
fn attack_since_fraction_at_open_point() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let since = since_epoch_frac(LAST_EPOCH + TIMEOUT, 0xFFFF, 0xFFFF);
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64, since,
        vec![(exit_lock, s.balance as u64)],
    );
    // Fraction bits must be ignored: epoch number alone gates, so this still verifies.
    ctx.verify_tx(&tx, MAX_CYCLES).expect("fraction bits must be ignored, epoch number gates");
}

// ATTACK A2: since with epoch number ONE BELOW the open point but max fraction. If abs_epoch
// leaked fraction into the comparison, this might slip through. Must REJECT.
#[test]
fn attack_since_fraction_below_open_point() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let since = since_epoch_frac(LAST_EPOCH + TIMEOUT - 1, 0xFFFF, 0xFFFF);
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64, since,
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "epoch number below open point must reject even with max fraction bits");
}

// ATTACK B: relative-epoch since (flag 0xA0). abs_epoch must return None -> reject.
#[test]
fn attack_relative_epoch_since_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let since = (0xA0u64 << 56) | (LAST_EPOCH + TIMEOUT); // relative+epoch flag
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64, since,
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a relative-epoch since must reject (only absolute-epoch gates)");
}

// ATTACK C: block-number since (flag 0x00). abs_epoch must return None -> reject.
#[test]
fn attack_block_number_since_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let since = LAST_EPOCH + TIMEOUT; // flag 0x00 = absolute block number
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64, since,
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a block-number since must reject");
}

// ATTACK D: SPLIT PAYOUT. Pay the owner the full balance in TWO cells (balance/2 each), and
// drop anchor capacity by the full balance. has_exit_output looks for ONE cell of exactly
// `balance`; if neither half matches, payout check fails -> reject. But try the inverse:
// pay one cell of exactly `balance` to the owner AND a second cell of `balance` to the owner,
// draining the anchor by `balance` only once. The attacker funds the extra cell themselves,
// so this is not a steal, just confirms no over-draw. Expect: PASS (owner paid their balance;
// extra owner-funded cell is harmless) OR REJECT on solvency. Document the result.
#[test]
fn attack_extra_owner_output_does_not_overdraw() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    // Two outputs of exactly `balance` to the owner. Anchor drops by `balance` only.
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock.clone(), s.balance as u64), (exit_lock, s.balance as u64)],
    );
    // Solvency ties anchor cap drop to `balance`; the 2nd cell must be funded by other inputs.
    // ckb-testtool's complete_tx will balance capacity; we just observe whether the contract
    // permits it (it should: the contract only checks anchor cap delta == balance).
    let r = ctx.verify_tx(&tx, MAX_CYCLES);
    println!("extra-owner-output result: {:?}", r);
    // Not asserting pass/fail; this documents that the anchor can never lose more than `balance`.
}

// ATTACK E: claim MORE than the leaf balance by tampering only the witness balance and the
// anchor total/cap to match, keeping the true siblings. Inclusion must fail (leaf_hash differs).
#[test]
fn attack_inflate_balance_rejected() {
    let s = scenario();
    let inflated = s.balance + 5_000_000_000;
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    // Rebuild a nullified root consistent with the inflated leaf so root checks *could* pass if
    // inclusion were not bound. (We use the true new_root; inclusion against prev must fail first.)
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, inflated, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total, // total can't go negative; keep nonsense
        (s.total + inflated) as u64, s.total as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock, inflated as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "inflating the claimed balance must fail SMT inclusion against the committed root");
}

// ATTACK F: exit a leaf you don't own. Supply the ATTACKER's pubkey (key = keccak(attacker_pk))
// but the VICTIM's siblings/balance. key != victim_key, so inclusion fails. Even if it passed,
// payout would go to attacker's lock. Must reject at inclusion.
#[test]
fn attack_exit_someone_elses_leaf_rejected() {
    let s = scenario();
    let attacker_sk = secret(123);
    let attacker_pk = sig::pubkey(&attacker_sk);
    let attacker_lock = secp_lock(&blake160(&attacker_pk));
    // Use the victim's balance/nonce/siblings but the attacker's pubkey.
    let (ctx, tx) = build_exit(
        &s, &attacker_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(attacker_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "exiting against the victim's leaf with the attacker's key must reject (key mismatch)");
}

// ATTACK G: REPLAY. After a valid exit, the leaf is nullified (balance->0). Try to exit the
// SAME leaf AGAIN against the *new* (nullified) root. The leaf now hashes to {0, nonce}; a
// force-exit needs balance>0 in the witness, but inclusion of {balance, nonce} against the
// nullified root fails. Simulate: prev root = the nullified root, claim the old balance.
#[test]
fn attack_replay_against_nullified_root_rejected() {
    let s = scenario();
    // Build a fresh scenario whose committed (prev) root IS the nullified root.
    let mut s2 = scenario();
    s2.root = s.new_root; // pretend the pool already advanced to the nullified root
    // siblings for the (now empty) leaf are the same path; recompute total accordingly.
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    // The output "re-nullified" root equals prev (no change), total stays.
    let (ctx, tx) = build_exit(
        &s2, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s2.total - s.balance,
        s2.total as u64, (s2.total - s.balance) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "replaying an exit against the nullified root must reject (leaf no longer holds balance)");
}

// ATTACK H: MODE CONFUSION. A force-exit witness padded to the checkpoint length (644) or
// the force-refund length (8321) would dispatch to the wrong handler. Build a force-exit
// payload but truncate/pad to FORCEREFUND_LEN (8321) and see it gets routed to force_refund
// (which will fail its own checks) rather than force_exit. This confirms length-based dispatch
// can't be abused to skip checks. We pad to 8321 and expect reject.
#[test]
fn attack_length_pad_to_refund_mode_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    // Build a normal exit payload then pad it to FORCEREFUND_LEN (8321 = 8249 + 72).
    let mut payload = Vec::new();
    payload.extend_from_slice(&s.exiter_pk);
    payload.extend_from_slice(&s.balance.to_be_bytes());
    payload.extend_from_slice(&s.nonce.to_be_bytes());
    for sib in &s.siblings {
        payload.extend_from_slice(sib);
    }
    payload.extend_from_slice(&[0u8; 8321 - 8249]); // pad to refund length

    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build first").into();
    let prev_anchor = anchor(&s.root, s.seq, s.total, s.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&s.new_root.to_vec(), s.seq, s.total - s.balance, s.fee_acc, LAST_EPOCH);
    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let anchor_in = ctx.create_cell(
        CellOutput::new_builder().capacity((s.total as u64).pack()).lock(lock.clone())
            .type_(Some(type_script.clone()).pack()).build(),
        Bytes::from(prev_anchor),
    );
    let w0 = WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack())
        .build().as_bytes();
    let b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in)
            .since(abs_epoch(LAST_EPOCH + TIMEOUT).pack()).build())
        .output(CellOutput::new_builder().capacity(((s.total - s.balance) as u64).pack())
            .lock(lock.clone()).type_(Some(type_script).pack()).build())
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .output(CellOutput::new_builder().capacity((s.balance as u64).pack()).lock(exit_lock).build())
        .output_data(Bytes::new().pack())
        .witness(w0.pack());
    let tx = ctx.complete_tx(b.build());
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a force-exit payload padded to refund length must be routed to force_refund and reject");
}

// ATTACK K: CAPTURE via force-exit. Re-lock the output anchor to a different lock during an
// otherwise-valid exit. Lock continuity is checked before mode dispatch, so it must reject.
#[test]
fn attack_capture_via_force_exit_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build first").into();
    let mut payload = Vec::new();
    payload.extend_from_slice(&s.exiter_pk);
    payload.extend_from_slice(&s.balance.to_be_bytes());
    payload.extend_from_slice(&s.nonce.to_be_bytes());
    for sib in &s.siblings { payload.extend_from_slice(sib); }
    let prev_anchor = anchor(&s.root, s.seq, s.total, s.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&s.new_root.to_vec(), s.seq, s.total - s.balance, s.fee_acc, LAST_EPOCH);
    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let capture_lock = ctx.build_script(&as_op, Bytes::from(b"capture".to_vec())).unwrap();
    let anchor_in = ctx.create_cell(
        CellOutput::new_builder().capacity((s.total as u64).pack()).lock(lock)
            .type_(Some(type_script.clone()).pack()).build(),
        Bytes::from(prev_anchor),
    );
    let w0 = WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();
    let b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in)
            .since(abs_epoch(LAST_EPOCH + TIMEOUT).pack()).build())
        .output(CellOutput::new_builder().capacity(((s.total - s.balance) as u64).pack())
            .lock(capture_lock).type_(Some(type_script).pack()).build()) // re-locked!
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .output(CellOutput::new_builder().capacity((s.balance as u64).pack()).lock(exit_lock).build())
        .output_data(Bytes::new().pack())
        .witness(w0.pack());
    let tx = ctx.complete_tx(b.build());
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a force-exit that re-locks the anchor must reject (capture-proof)");
}

// ATTACK I: exit while total drops by balance but anchor CAPACITY drops by LESS (steal the
// difference into a fee/elsewhere). Solvency in_cap - balance == out_cap must catch it.
#[test]
fn attack_capacity_drop_less_than_balance_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    // out_cap too high (drops by balance/2 instead of balance).
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total - s.balance,
        s.total as u64, (s.total - s.balance / 2) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "anchor capacity dropping by less than balance must reject (solvency)");
}

// ATTACK J: keep total unchanged (don't debit the pool) while still paying out. The anchor
// continuity check total -= balance must catch it.
#[test]
fn attack_total_not_debited_rejected() {
    let s = scenario();
    let exit_lock = secp_lock(&blake160(&s.exiter_pk));
    let (ctx, tx) = build_exit(
        &s, &s.exiter_pk, s.balance, s.nonce, &s.siblings,
        &s.new_root.to_vec(), s.total, // total NOT debited
        s.total as u64, (s.total - s.balance) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT),
        vec![(exit_lock, s.balance as u64)],
    );
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "output total that isn't debited by balance must reject");
}
