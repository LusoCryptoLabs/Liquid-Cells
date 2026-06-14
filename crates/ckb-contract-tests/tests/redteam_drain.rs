//! Full-drain / anchor-capacity-floor proof (ROADMAP B2).
//!
//! Concern raised by the red-team: `force_exit` enforces `out_cap == in_cap − balance` with no
//! explicit floor, so could a draining pool push the output anchor below the ~minimum a CKB cell
//! needs to exist and strand the last exiter? Answer: **no**, and this test demonstrates why.
//!
//! Define `slack = anchor_capacity − pool_total`. The anchor type script's GENESIS branch forces
//! `total == 0`, so a real pool starts with `slack = genesis_capacity`, which must already satisfy
//! CKB's occupied-capacity rule for the cell to exist (`slack ≥ ANCHOR_OCCUPIED`). Every mode
//! preserves slack exactly — force-exit drops `capacity` and `total` by the same `balance`;
//! checkpoints change both by the same `Σdep − Σwd − fee_wd`. So `slack` is invariant, and the
//! anchor capacity `= total + slack ≥ slack ≥ ANCHOR_OCCUPIED` at all times. Draining `total` to 0
//! therefore leaves a valid anchor holding exactly the (operator-seeded) genesis slack.
//!
//! (The existing `forceexit.rs` tests use the shortcut `in_cap = total`, i.e. slack 0, which the
//! test VM accepts but a real chain never produces — genesis-total-0 guarantees slack ≥ occupied.)

use ckb_testtool::ckb_types::core::{ScriptHashType, TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{abs_epoch, anchor};
use liquid_cells_stf::*;

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";
const TIMEOUT: u64 = 180;
const LAST_EPOCH: u64 = 5;
/// A conservative lower bound on a real anchor cell's occupied capacity (capacity(8) + an
/// always-success/secp lock + the anchor type script + the 80-byte data ≈ 150–190 CKB). The
/// genesis slack — seeded once, never withdrawable below this — must clear it.
const ANCHOR_OCCUPIED: u64 = 18_600_000_000; // ~186 CKB
/// Realistic genesis slack (matches the live pools' 250 CKB genesis anchor over total 0).
const GENESIS_SLACK: u64 = 25_000_000_000; // 250 CKB

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

/// Build a force-exit of the pool's ONLY leaf (so it drains `total` to 0), with a realistic
/// genesis slack baked into the anchor capacity.
fn build_full_drain() -> (Context, TransactionView, u64, u128) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let chain_id = 0x434b_42u64;
    let mut st = State::genesis(keccak(b"drain-pool"), chain_id);
    let sk = secret(7);
    let pk = sig::pubkey(&sk);
    let key = key_of_pubkey(&pk);
    let balance: u128 = 7_000_000_000;
    // single leaf => total == balance; exiting it drains the pool to 0.
    apply(&mut st, &Batch { current_epoch: 0, deposits: vec![Deposit { to_key: key, amount: balance }], ..Default::default() }).unwrap();

    let root = st.pool.root;
    let total = st.pool.total;
    assert_eq!(total, balance, "single-leaf pool: total == the only balance");
    let leaf = st.get_leaf(&key);
    let siblings = st.smt.proof(&key);
    let new_root = {
        let mut smt = st.smt.clone();
        smt.set_leaf_hash(key, Leaf { balance: 0, nonce: leaf.nonce }.hash());
        smt.root()
    };

    let mut payload = Vec::with_capacity(33 + 16 + 8 + 32 * 256);
    payload.extend_from_slice(&pk);
    payload.extend_from_slice(&balance.to_be_bytes());
    payload.extend_from_slice(&leaf.nonce.to_be_bytes());
    for s in &siblings {
        payload.extend_from_slice(s);
    }

    // Realistic capacities: anchor holds total + the genesis slack; draining leaves the slack.
    let in_cap = total as u64 + GENESIS_SLACK;
    let out_cap = in_cap - balance as u64; // == GENESIS_SLACK (total drained to 0)
    let prev_anchor = anchor(&root, st.pool.seq, total, st.pool.fee_acc, LAST_EPOCH);
    let new_anchor = anchor(&new_root, st.pool.seq, 0, st.pool.fee_acc, LAST_EPOCH);

    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ckb_testtool::builtin::ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();

    let anchor_in = ctx.create_cell(
        CellOutput::new_builder().capacity(in_cap.pack()).lock(lock.clone()).type_(Some(type_script.clone()).pack()).build(),
        Bytes::from(prev_anchor),
    );
    let w0 = WitnessArgs::new_builder().input_type(Some(Bytes::from(payload)).pack()).build().as_bytes();

    let b = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(anchor_in).since(abs_epoch(LAST_EPOCH + TIMEOUT).pack()).build())
        .output(CellOutput::new_builder().capacity(out_cap.pack()).lock(lock).type_(Some(type_script).pack()).build())
        .output_data(Bytes::from(new_anchor).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .witness(w0.pack())
        .output(CellOutput::new_builder().capacity((balance as u64).pack()).lock(secp_lock(&blake160(&pk))).build())
        .output_data(Bytes::new().pack());

    let tx = ctx.complete_tx(b.build());
    (ctx, tx, out_cap, total)
}

#[test]
fn full_drain_leaves_a_valid_anchor_no_stranding() {
    let (ctx, tx, out_cap, total) = build_full_drain();
    // 1. the script accepts draining the pool's last leaf to total = 0.
    ctx.verify_tx(&tx, MAX_CYCLES).expect("draining the final leaf must verify");
    // 2. slack invariant: the drained anchor retains exactly the genesis slack...
    assert_eq!(out_cap, GENESIS_SLACK, "slack preserved through a full drain");
    assert_eq!(out_cap, (total as u64 + GENESIS_SLACK) - total as u64, "out_cap == in_cap - balance");
    // 3. ...which clears the cell occupied-capacity floor, so the anchor is still constructable.
    assert!(out_cap >= ANCHOR_OCCUPIED, "drained anchor stays above its occupied capacity -> no stranding");
}
