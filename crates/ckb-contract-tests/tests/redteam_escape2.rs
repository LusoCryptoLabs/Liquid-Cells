//! Adversarial red-team tests, part 2: force-refund double-resolution, capture via lock
//! change in escape modes, and HTLC-timeout fraction tricks.

use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::anchor;
use liquid_cells_stf::*;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const TIMEOUT: u64 = 180;
const LAST_EPOCH: u64 = 5;
const CHAIN_ID: u64 = 0x0043_4b42;

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
fn abs_epoch(e: u64) -> u64 {
    (0x20u64 << 56) | e
}

struct RScenario {
    root: [u8; 32],
    new_root: [u8; 32],
    total: u128,
    seq: u64,
    fee_acc: u128,
    alice_pk: [u8; 33],
    bob_key: [u8; 32],
    amount: u128,
    hashlock: [u8; 32],
    htlc_timeout: u64,
    lock_nonce: u64,
    siblings: Vec<[u8; 32]>,
}

fn refund_scenario(htlc_timeout: u64) -> RScenario {
    let pool_id = keccak(b"sp1-pool");
    let mut st = State::genesis(pool_id, CHAIN_ID);
    let alice_sk = secret(1);
    let alice_pk = sig::pubkey(&alice_sk);
    let alice_key = key_of_pubkey(&alice_pk);
    let bob_key = key_of_pubkey(&sig::pubkey(&secret(2)));
    let amount: u128 = 7_000_000_000;
    let fee: u128 = 1_000;
    let funding = amount + fee + 3_000_000_000;
    apply(&mut st, &Batch {
        current_epoch: 0,
        deposits: vec![Deposit { to_key: alice_key, amount: funding }],
        ..Default::default()
    }).unwrap();
    let hashlock = keccak(b"liquid-cells/force-refund/preimage");
    let lock_nonce = 0u64;
    let msg = htlc_lock_msg(CHAIN_ID, &pool_id, &alice_key, &bob_key, amount, fee, &hashlock, htlc_timeout, lock_nonce);
    let (_pk, sig) = sig::sign(&alice_sk, &msg);
    let lock = HtlcLock { sender_pubkey: alice_pk, receiver_key: bob_key, amount, fee, hashlock, timeout: htlc_timeout, nonce: lock_nonce, sig };
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();
    let id = htlc_id(&pool_id, &alice_key, &bob_key, amount, &hashlock, htlc_timeout, lock_nonce);
    let siblings = st.smt.proof(&id);
    let new_root = {
        let mut smt = st.smt.clone();
        smt.set_leaf_hash(id, Leaf { balance: 0, nonce: 0 }.hash());
        smt.root()
    };
    RScenario {
        root: st.pool.root, new_root, total: st.pool.total, seq: st.pool.seq,
        fee_acc: st.pool.fee_acc, alice_pk, bob_key, amount, hashlock, htlc_timeout, lock_nonce, siblings,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_refund(
    s: &RScenario, prev_root: &[u8], out_root: &[u8], out_total: u128,
    in_cap: u64, out_cap: u64, since: u64, change_lock: bool, payout: Option<(Script, u64)>,
) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build first").into();
    let mut payload = Vec::new();
    #[cfg(feature = "compact_smt")]
    payload.push(0x02u8); // FORCE_REFUND_TAG
    payload.extend_from_slice(&s.alice_pk);
    payload.extend_from_slice(&s.bob_key);
    payload.extend_from_slice(&s.amount.to_be_bytes());
    payload.extend_from_slice(&s.hashlock);
    payload.extend_from_slice(&s.htlc_timeout.to_be_bytes());
    payload.extend_from_slice(&s.lock_nonce.to_be_bytes());
    #[cfg(not(feature = "compact_smt"))]
    for sib in &s.siblings { payload.extend_from_slice(sib); }
    #[cfg(feature = "compact_smt")]
    payload.extend_from_slice(&liquid_cells_stf::smt_compact::sparse_encode_proof(&s.siblings));

    let prev_anchor = anchor(prev_root, s.seq, s.total, s.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(out_root, s.seq, out_total, s.fee_acc, LAST_EPOCH);

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let other = ctx.build_script(&as_op, Bytes::from(b"capture".to_vec())).unwrap();
    let out_lock = if change_lock { other } else { lock.clone() };

    let anchor_in = ctx.create_cell(
        CellOutput::new_builder().capacity(in_cap.pack()).lock(lock)
            .type_(Some(type_script.clone()).pack()).build(),
        Bytes::from(prev_anchor),
    );
    let w0 = WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();
    let mut b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in).since(since.pack()).build())
        .output(CellOutput::new_builder().capacity(out_cap.pack()).lock(out_lock)
            .type_(Some(type_script).pack()).build())
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack());
    if let Some((l, c)) = payout {
        b = b.output(CellOutput::new_builder().capacity(c.pack()).lock(l).build())
            .output_data(Bytes::new().pack());
    }
    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

fn valid_refund(s: &RScenario) -> (Context, TransactionView) {
    let payout = secp_lock(&blake160(&s.alice_pk));
    build_refund(s, &s.root.to_vec(), &s.new_root.to_vec(), s.total - s.amount,
        s.total as u64, (s.total - s.amount) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT), false, Some((payout, s.amount as u64)))
}

#[test]
fn sanity_valid_refund_passes() {
    let s = refund_scenario(8);
    let (ctx, tx) = valid_refund(&s);
    ctx.verify_tx(&tx, MAX_CYCLES).expect("canonical refund must verify (builder sanity)");
}

// ATTACK: force-refund DOUBLE-RESOLUTION. Replay a refund against the already-nullified root.
// prev_root = the nullified root; the escrow leaf is now empty, so inclusion of {amount,0} fails.
#[test]
fn attack_refund_replay_rejected() {
    let s = refund_scenario(8);
    let payout = secp_lock(&blake160(&s.alice_pk));
    let (ctx, tx) = build_refund(&s, &s.new_root.to_vec(), &s.new_root.to_vec(), s.total - s.amount,
        s.total as u64, (s.total - s.amount) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT), false, Some((payout, s.amount as u64)));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "replaying a refund against the nullified root must reject (escrow already consumed)");
}

// ATTACK: CAPTURE via force-refund. An otherwise-valid refund that re-locks the output anchor
// to a different lock must reject (lock continuity is checked before mode dispatch).
#[test]
fn attack_capture_via_refund_rejected() {
    let s = refund_scenario(8);
    let payout = secp_lock(&blake160(&s.alice_pk));
    let (ctx, tx) = build_refund(&s, &s.root.to_vec(), &s.new_root.to_vec(), s.total - s.amount,
        s.total as u64, (s.total - s.amount) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT), true /* change lock */, Some((payout, s.amount as u64)));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a refund that re-locks the anchor must reject (capture-proof, lock continuity)");
}

// ATTACK: refund BEFORE the HTLC timeout using a since whose epoch number is past silence but
// below the htlc timeout. Here htlc_timeout is huge; silence gate passes at last+TIMEOUT, but
// since_epoch < timeout must reject. (Mirrors the existing before_htlc_timeout test but via the
// explicit builder, ensuring no fraction trick helps.)
#[test]
fn attack_refund_before_htlc_timeout_rejected() {
    let big_timeout = LAST_EPOCH + TIMEOUT + 50;
    let s = refund_scenario(big_timeout);
    let payout = secp_lock(&blake160(&s.alice_pk));
    // since at the silence open point (passes silence) but below htlc timeout.
    let (ctx, tx) = build_refund(&s, &s.root.to_vec(), &s.new_root.to_vec(), s.total - s.amount,
        s.total as u64, (s.total - s.amount) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT), false, Some((payout, s.amount as u64)));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "refund before the HTLC timeout must reject even when silence has elapsed");
}

// ATTACK: refund to the WRONG key (receiver pays themselves). Payout forced to sender's secp
// lock; pay bob instead of alice -> reject.
#[test]
fn attack_refund_to_receiver_rejected() {
    let s = refund_scenario(8);
    let bob_pk = sig::pubkey(&secret(2));
    let bob_lock = secp_lock(&blake160(&bob_pk));
    let (ctx, tx) = build_refund(&s, &s.root.to_vec(), &s.new_root.to_vec(), s.total - s.amount,
        s.total as u64, (s.total - s.amount) as u64,
        abs_epoch(LAST_EPOCH + TIMEOUT), false, Some((bob_lock, s.amount as u64)));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "refund paid to the receiver instead of the sender must reject");
}

// ATTACK: cross-pool refund. The escrow was built under pool_id=keccak("sp1-pool") (the baked
// legacy POOL_ID). If the contract used 32-byte args naming a DIFFERENT pool, htlc_id recompute
// would differ. Here we keep empty args (legacy), so it matches; to test the mismatch we set a
// type-id arg that differs -> htlc_id recompute uses the arg pool_id, inclusion fails.
#[test]
fn attack_refund_wrong_pool_args_rejected() {
    let s = refund_scenario(8);
    let payout = secp_lock(&blake160(&s.alice_pk));
    // Rebuild with 32-byte type args != keccak("sp1-pool"); contract derives pool_id from args.
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build first").into();
    let mut payload = Vec::new();
    #[cfg(feature = "compact_smt")]
    payload.push(0x02u8); // FORCE_REFUND_TAG
    payload.extend_from_slice(&s.alice_pk);
    payload.extend_from_slice(&s.bob_key);
    payload.extend_from_slice(&s.amount.to_be_bytes());
    payload.extend_from_slice(&s.hashlock);
    payload.extend_from_slice(&s.htlc_timeout.to_be_bytes());
    payload.extend_from_slice(&s.lock_nonce.to_be_bytes());
    #[cfg(not(feature = "compact_smt"))]
    for sib in &s.siblings { payload.extend_from_slice(sib); }
    #[cfg(feature = "compact_smt")]
    payload.extend_from_slice(&liquid_cells_stf::smt_compact::sparse_encode_proof(&s.siblings));

    let prev_anchor = anchor(&s.root.to_vec(), s.seq, s.total, s.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&s.new_root.to_vec(), s.seq, s.total - s.amount, s.fee_acc, LAST_EPOCH);
    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let wrong_args = vec![0xABu8; 32];
    let type_script = ctx.build_script(&contract_op, Bytes::from(wrong_args)).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let anchor_in = ctx.create_cell(
        CellOutput::new_builder().capacity((s.total as u64).pack()).lock(lock.clone())
            .type_(Some(type_script.clone()).pack()).build(),
        Bytes::from(prev_anchor),
    );
    let w0 = WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();
    let (pl, pc) = (payout, s.amount as u64);
    let b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in)
            .since(abs_epoch(LAST_EPOCH + TIMEOUT).pack()).build())
        .output(CellOutput::new_builder().capacity(((s.total - s.amount) as u64).pack())
            .lock(lock).type_(Some(type_script).pack()).build())
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .output(CellOutput::new_builder().capacity(pc.pack()).lock(pl).build())
        .output_data(Bytes::new().pack())
        .witness(w0.pack());
    let tx = ctx.complete_tx(b.build());
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a refund whose anchor args name a different pool must reject (htlc_id binds pool_id)");
}
