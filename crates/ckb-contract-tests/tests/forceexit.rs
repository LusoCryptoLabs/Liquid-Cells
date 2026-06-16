//! Force-exit (escape hatch) integration tests, Phase 3.
//!
//! Force-exit has no SP1 proof, so these build the whole scenario *natively* with
//! `liquid-cells-stf`: fund a couple of leaves, take the committed root and one leaf's SMT
//! inclusion proof, then drive the anchor type script's force-exit mode. The payout is
//! forced to the owner's canonical secp256k1_blake160 lock (`args = blake160(pubkey)`), the
//! leaf is nullified (balance→0), and the anchor capacity/total drop by exactly the exited
//! balance, only after the operator-silence timeout. Tampering any of these must reject.
//!
//! Requires the contract built first:
//!   (cd crates/ckb-contract && cargo build --release)

use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_stf::*;
use liquid_cells_ckb_tests::{abs_epoch,anchor};

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";

/// Must match the contract's `FORCE_EXIT_TIMEOUT_EPOCHS`.
const TIMEOUT: u64 = 180;
/// The epoch the last checkpoint recorded (anchor `last_epoch`).
const LAST_EPOCH: u64 = 5;

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

#[derive(Clone, Default)]
struct Cfg {
    too_early: bool,     // since < last_epoch + TIMEOUT
    tamper_balance: bool, // claim a different balance than the leaf holds
    wrong_exit_lock: bool, // pay a lock that isn't the owner's secp lock
    drop_exit: bool,     // no payout output
    bad_new_root: bool,  // output anchor root not the nullified root
    bad_total: bool,     // output anchor total doesn't drop by the balance
}

fn build(cfg: Cfg) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();

    // Native STF: fund the exiter (key 7) and one other leaf, so the tree is non-trivial.
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
    let leaf = st.get_leaf(&exiter_key); // { balance, nonce: 0 }
    let siblings = st.smt.proof(&exiter_key); // 256 sibling hashes, top-down

    // Nullified root: the same tree with the exiter's leaf emptied (balance→0, nonce kept).
    let new_root = {
        let mut smt = st.smt.clone();
        smt.set_leaf_hash(exiter_key, Leaf { balance: 0, nonce: leaf.nonce }.hash());
        smt.root()
    };

    // Force-exit payload. Deployed: pubkey(33) ‖ balance(16 BE) ‖ nonce(8 BE) ‖ siblings(256·32).
    // Under compact_smt: a 1-byte mode tag, then the fixed fields, then the SPARSE proof (bitmap + the
    // non-empty siblings only), exactly what the client emits and the anchor's compact arm decodes.
    let claimed_balance = if cfg.tamper_balance { balance + 1 } else { balance };
    let mut payload = Vec::new();
    #[cfg(feature = "compact_smt")]
    payload.push(0x01u8); // FORCE_EXIT_TAG
    payload.extend_from_slice(&exiter_pk);
    payload.extend_from_slice(&claimed_balance.to_be_bytes());
    payload.extend_from_slice(&leaf.nonce.to_be_bytes());
    #[cfg(not(feature = "compact_smt"))]
    for s in &siblings {
        payload.extend_from_slice(s);
    }
    #[cfg(feature = "compact_smt")]
    payload.extend_from_slice(&liquid_cells_stf::smt_compact::sparse_encode_proof(&siblings));

    let out_root = if cfg.bad_new_root { root.to_vec() } else { new_root.to_vec() };
    let out_total = if cfg.bad_total { total } else { total - balance };
    let prev_anchor = anchor(&root, st.pool.seq, total, st.pool.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&out_root, st.pool.seq, out_total, st.pool.fee_acc, LAST_EPOCH);

    let in_cap = total as u64; // anchor capacity == pool total
    let out_cap = (total - balance) as u64;

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

    // Timeout: the input `since` is an absolute epoch; the hatch opens at last_epoch+TIMEOUT.
    let since_epoch = if cfg.too_early { LAST_EPOCH + TIMEOUT - 1 } else { LAST_EPOCH + TIMEOUT };

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
                .lock(lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack());

    if !cfg.drop_exit {
        // Payout to the owner's canonical secp lock (or, for the negative, a wrong one).
        let pk = if cfg.wrong_exit_lock { sig::pubkey(&secret(99)) } else { exiter_pk };
        let exit_lock = secp_lock(&blake160(&pk));
        b = b
            .output(CellOutput::new_builder().capacity((balance as u64).pack()).lock(exit_lock).build())
            .output_data(Bytes::new().pack());
    }

    let tx = ctx.complete_tx(b.build());
    (ctx, tx)
}

#[test]
fn force_exit_after_timeout_verifies() {
    let (ctx, tx) = build(Cfg::default());
    ctx.verify_tx(&tx, MAX_CYCLES).expect("a timed-out force-exit to the owner's lock must verify");
}

#[test]
fn force_exit_before_timeout_rejected() {
    let (ctx, tx) = build(Cfg { too_early: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "exit before the silence timeout must reject");
}

#[test]
fn force_exit_wrong_balance_rejected() {
    // A claimed balance the leaf doesn't hold fails the SMT inclusion against the root.
    let (ctx, tx) = build(Cfg { tamper_balance: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "wrong claimed balance must reject");
}

#[test]
fn force_exit_wrong_payout_lock_rejected() {
    // Funds may only go to the leaf owner's own secp lock.
    let (ctx, tx) = build(Cfg { wrong_exit_lock: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "payout to a non-owner lock must reject");
}

#[test]
fn force_exit_missing_payout_rejected() {
    let (ctx, tx) = build(Cfg { drop_exit: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "no payout output must reject");
}

#[test]
fn force_exit_unnullified_root_rejected() {
    // The output anchor must carry the nullified root (leaf emptied), preventing double-exit.
    let (ctx, tx) = build(Cfg { bad_new_root: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "output root that doesn't nullify the leaf must reject");
}

#[test]
fn force_exit_bad_total_rejected() {
    let (ctx, tx) = build(Cfg { bad_total: true, ..Default::default() });
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "total must drop by exactly the exited balance");
}
