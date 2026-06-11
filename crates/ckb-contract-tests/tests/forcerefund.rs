//! Force-refund (HTLC escape hatch) integration tests — Phase 5 follow-up.
//!
//! A pending HTLC escrow is keyed by `htlc_id` (not `keccak(pubkey)`), so the account-leaf
//! force-exit cannot reach it. Force-refund is the *sender's* unilateral escape: once the
//! HTLC `timeout` has passed (so the receiver can no longer claim) AND the operator-silence
//! window has elapsed, the sender reclaims the timed-out escrow to her own secp lock, against
//! the last committed root, by supplying every lock term. The script re-derives the escrow's
//! `htlc_id`, proves the `{balance = amount, nonce = 0}` escrow leaf is included under the
//! committed root, nullifies it, drops `total` by `amount`, and forces the payout to the
//! sender's canonical secp256k1_blake160 lock. Tampering any binding must reject.
//!
//! These build the whole scenario *natively* with `liquid-cells-stf` (force-refund carries no
//! SP1 proof), under the contract's BAKED pool id (`keccak("sp1-pool")`) and chain id, because
//! the on-chain `htlc_id` recompute uses them. The escrow amount is ≥ 61 CKB so the L1 payout
//! cell is valid — like force-exit, force-refund pays out to L1 and so inherits the 61-CKB
//! cell floor; sub-61-CKB escrows under operator silence are the architectural residual that
//! Phase 6 (permissionless sequencing) resolves. See docs/EGRESS.md.
//!
//! Requires the contract built first:
//!   (cd crates/ckb-contract && cargo build --release)

use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_stf::*;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";

/// Must match the contract's `FORCE_EXIT_TIMEOUT_EPOCHS`.
const TIMEOUT: u64 = 180;
/// The epoch the last checkpoint recorded (anchor `last_epoch`).
const LAST_EPOCH: u64 = 5;
/// Must match the contract's baked `CHAIN_ID`.
const CHAIN_ID: u64 = 0x0043_4b42;

/// CKB system secp256k1_blake160_sighash_all lock code hash (must match the contract).
const SECP_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn abs_epoch(e: u64) -> u64 {
    (0x20u64 << 56) | e
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
/// anchor data = root(32) ‖ seq(8) ‖ total(16) ‖ fee_acc(16) ‖ last_epoch(8)
fn anchor(root: &[u8], seq: u64, total: u128, fee: u128, last_epoch: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(80);
    a.extend_from_slice(root);
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(&total.to_be_bytes());
    a.extend_from_slice(&fee.to_be_bytes());
    a.extend_from_slice(&last_epoch.to_be_bytes());
    a
}

#[derive(Clone, Default)]
struct Cfg {
    too_early_silence: bool,   // since < last_epoch + TIMEOUT (operator-silence gate)
    before_htlc_timeout: bool, // timeout pushed past `since` — silence passes, htlc gate fails
    wrong_receiver: bool,      // witness names a receiver_key the escrow wasn't locked to
    tamper_amount: bool,       // witness claims a different amount than the escrow holds
    wrong_payout: bool,        // pay a lock that isn't the sender's secp lock
    drop_payout: bool,         // no payout output at all
    bad_new_root: bool,        // output anchor root not the nullified root
    bad_total: bool,           // output anchor total doesn't drop by the amount
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();

    // The escrow MUST be built under the contract's baked pool id, because the on-chain
    // `htlc_id` recompute uses it.
    let pool_id = keccak(b"sp1-pool");
    let mut st = State::genesis(pool_id, CHAIN_ID);

    let alice_sk = secret(1);
    let alice_pk = sig::pubkey(&alice_sk);
    let alice_key = key_of_pubkey(&alice_pk);
    let bob_key = key_of_pubkey(&sig::pubkey(&secret(2)));
    let carol_key = key_of_pubkey(&sig::pubkey(&secret(3)));

    // ≥ 61 CKB so the L1 payout cell is valid (force-refund pays out to L1, like force-exit).
    let amount: u128 = 7_000_000_000;
    let fee: u128 = 1_000;
    // Fund Alice with extra, so `total` strictly exceeds the escrow and the anchor stays solvent.
    let funding = amount + fee + 3_000_000_000;
    apply(
        &mut st,
        &Batch {
            current_epoch: 0,
            deposits: vec![Deposit { to_key: alice_key, amount: funding }],
            ..Default::default()
        },
    )
    .unwrap();

    // HTLC `timeout` (in epochs). Short by default. For `before_htlc_timeout`, push it past the
    // silence window so the silence gate passes but the HTLC-timeout gate is the one that fails.
    let htlc_timeout: u64 =
        if cfg.before_htlc_timeout { LAST_EPOCH + TIMEOUT + 50 } else { 8 };
    let hashlock = keccak(b"liquid-cells/force-refund/preimage");
    let lock_nonce = 0u64; // Alice's account nonce at lock time (deposits don't bump nonce)

    let msg = htlc_lock_msg(
        CHAIN_ID, &pool_id, &alice_key, &bob_key, amount, fee, &hashlock, htlc_timeout, lock_nonce,
    );
    let (_pk, sig) = sig::sign(&alice_sk, &msg);
    let lock = HtlcLock {
        sender_pubkey: alice_pk,
        receiver_key: bob_key,
        amount,
        fee,
        hashlock,
        timeout: htlc_timeout,
        nonce: lock_nonce,
        sig,
    };
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() })
        .unwrap();

    let id = htlc_id(&pool_id, &alice_key, &bob_key, amount, &hashlock, htlc_timeout, lock_nonce);
    let escrow = st.get_leaf(&id);
    assert_eq!(escrow.balance, amount, "escrow must hold the locked amount");
    assert_eq!(escrow.nonce, 0, "escrow leaf has nonce 0");

    let root = st.pool.root;
    let total = st.pool.total; // unchanged by the lock — value stayed in the pool
    let fee_acc = st.pool.fee_acc;
    let seq = st.pool.seq;
    let siblings = st.smt.proof(&id); // 256 sibling hashes, top-down

    // Nullified root: the escrow leaf emptied to {0, 0}.
    let new_root = {
        let mut smt = st.smt.clone();
        smt.set_leaf_hash(id, Leaf { balance: 0, nonce: 0 }.hash());
        smt.root()
    };

    // Force-refund payload: sender_pubkey(33) ‖ receiver_key(32) ‖ amount(16) ‖ hashlock(32)
    // ‖ timeout(8) ‖ lock_nonce(8) ‖ siblings(256·32).
    let wit_receiver = if cfg.wrong_receiver { carol_key } else { bob_key };
    let wit_amount = if cfg.tamper_amount { amount + 1 } else { amount };
    let mut payload = Vec::with_capacity(33 + 32 + 16 + 32 + 8 + 8 + 32 * 256);
    payload.extend_from_slice(&alice_pk);
    payload.extend_from_slice(&wit_receiver);
    payload.extend_from_slice(&wit_amount.to_be_bytes());
    payload.extend_from_slice(&hashlock);
    payload.extend_from_slice(&htlc_timeout.to_be_bytes());
    payload.extend_from_slice(&lock_nonce.to_be_bytes());
    for s in &siblings {
        payload.extend_from_slice(s);
    }

    let out_root = if cfg.bad_new_root { root.to_vec() } else { new_root.to_vec() };
    let out_total = if cfg.bad_total { total } else { total - amount };
    let prev_anchor = anchor(&root, seq, total, fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&out_root, seq, out_total, fee_acc, LAST_EPOCH);

    let in_cap = total as u64; // anchor capacity == pool total
    let out_cap = (total - amount) as u64;

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock_script = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();

    let anchor_in = ctx.create_cell(
        CellOutput::new_builder()
            .capacity(in_cap.pack())
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        Bytes::from(prev_anchor),
    );

    let w0 = WitnessArgs::new_builder()
        .input_type(Some(Bytes::from(payload)).pack())
        .build()
        .as_bytes();

    // Operator-silence gate: the input `since` (absolute epoch) opens the hatch at
    // last_epoch + TIMEOUT.
    let since_epoch =
        if cfg.too_early_silence { LAST_EPOCH + TIMEOUT - 1 } else { LAST_EPOCH + TIMEOUT };

    let mut b = TransactionBuilder::default()
        .input(
            CellInput::new_builder()
                .previous_output(anchor_in)
                .since(abs_epoch(since_epoch).pack())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(out_cap.pack())
                .lock(lock_script)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack());

    if !cfg.drop_payout {
        // Payout to the *sender's* canonical secp lock (or, for the negative, a wrong one).
        let pk = if cfg.wrong_payout { sig::pubkey(&secret(99)) } else { alice_pk };
        let exit_lock = secp_lock(&blake160(&pk));
        b = b
            .output(CellOutput::new_builder().capacity((amount as u64).pack()).lock(exit_lock).build())
            .output_data(Bytes::new().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn force_refund_after_timeout_verifies() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES)
        .expect("a timed-out HTLC escrow, refunded to the sender's lock after silence, must verify");
}

#[test]
fn force_refund_before_silence_rejected() {
    // Even after the HTLC timeout, the escape hatch only opens after operator silence.
    let (ctx, tx) = build(Cfg { too_early_silence: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "refund before the silence window must reject");
}

#[test]
fn force_refund_before_htlc_timeout_rejected() {
    // The HTLC's own timeout gates the refund: while a valid claim window is still open (the
    // timeout is in the future), refunding to the sender could rob the receiver.
    let (ctx, tx) = build(Cfg { before_htlc_timeout: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "refund before the HTLC timeout must reject (receiver may still hold a valid claim)"
    );
}

#[test]
fn force_refund_wrong_receiver_rejected() {
    // The escrow's htlc_id binds the receiver; naming a different one addresses a different
    // (empty) key, so the inclusion proof against the committed root fails.
    let (ctx, tx) = build(Cfg { wrong_receiver: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "wrong receiver_key must reject");
}

#[test]
fn force_refund_tampered_amount_rejected() {
    // Amount is part of htlc_id *and* the escrow leaf, so a tampered amount fails inclusion.
    let (ctx, tx) = build(Cfg { tamper_amount: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "tampered amount must reject");
}

#[test]
fn force_refund_wrong_payout_lock_rejected() {
    // The refund may only pay the sender's own secp lock.
    let (ctx, tx) = build(Cfg { wrong_payout: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "payout to a non-sender lock must reject");
}

#[test]
fn force_refund_missing_payout_rejected() {
    let (ctx, tx) = build(Cfg { drop_payout: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no payout output must reject");
}

#[test]
fn force_refund_unnullified_root_rejected() {
    // The output anchor must carry the nullified root (escrow emptied), preventing double-refund.
    let (ctx, tx) = build(Cfg { bad_new_root: true, ..Default::default() });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "output root that doesn't nullify the escrow must reject"
    );
}

#[test]
fn force_refund_bad_total_rejected() {
    let (ctx, tx) = build(Cfg { bad_total: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "total must drop by exactly the refunded amount");
}
