//! Genesis (pool creation) tests. Creating the anchor cell runs the type script on the
//! OUTPUT with no input anchor, so the contract's genesis branch must accept the canonical
//! empty state and reject anything else. (The other suites always have an input + output
//! anchor, so this path is only covered here.)

use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_types::core::{TransactionBuilder, TransactionView};
use ckb_testtool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_testtool::context::Context;
use liquid_cells_ckb_tests::{anchor};

const MAX_CYCLES: u64 = 5_000_000_000;
const CONTRACT_BIN: &str =
    "../ckb-contract/target/riscv64imac-unknown-none-elf/release/liquid-cells-anchor";

/// The empty SMT root (must match the contract's `EMPTY_ROOT` / stf genesis root). Under
/// `compact_smt` the STF empty tree roots to the zero constant, NOT the depth-256 keccak fold, so
/// this must track the feature or it would mirror a wrong contract constant and pass while a real
/// compact-pool genesis is rejected on-chain (the exact gap this cfg closes).
#[cfg(not(feature = "compact_smt"))]
const EMPTY_ROOT: [u8; 32] = [
    0xa7, 0xff, 0x9e, 0x28, 0xff, 0xd3, 0xde, 0xf4, 0x43, 0xd3, 0x24, 0x54, 0x76, 0x88, 0xc2, 0xc4,
    0xeb, 0x98, 0xed, 0xf7, 0xda, 0x75, 0x7d, 0x6b, 0xfa, 0x22, 0xbf, 0xf5, 0x5b, 0x9c, 0xe2, 0x4a,
];
#[cfg(feature = "compact_smt")]
const EMPTY_ROOT: [u8; 32] = [0u8; 32];


fn build(data: Vec<u8>) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let type_script = ctx.build_script(&contract_op, Bytes::new()).unwrap();
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();

    // A plain funding input (no anchor type), so the anchor type group has no input.
    let funding = ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(lock.clone()).build(),
        Bytes::new(),
    );

    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(funding).build())
        .output(
            CellOutput::new_builder()
                .capacity(1000u64.pack())
                .lock(lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(data).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn genesis_canonical_empty_state_accepts() {
    let (ctx, tx) = build(anchor(&EMPTY_ROOT, 0, 0, 0, 0));
    ctx.verify_tx(&tx, MAX_CYCLES).expect("the canonical empty genesis must verify");
}

#[test]
fn genesis_non_empty_root_rejected() {
    let mut r = EMPTY_ROOT;
    r[0] ^= 0xff;
    let (ctx, tx) = build(anchor(&r, 0, 0, 0, 0));
    assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "a non-empty genesis root must reject");
}

#[test]
fn genesis_nonzero_counters_rejected() {
    for data in [
        anchor(&EMPTY_ROOT, 1, 0, 0, 0),
        anchor(&EMPTY_ROOT, 0, 5, 0, 0),
        anchor(&EMPTY_ROOT, 0, 0, 5, 0),
        anchor(&EMPTY_ROOT, 0, 0, 0, 9),
    ] {
        let (ctx, tx) = build(data);
        assert!(ctx.verify_tx(&tx, MAX_CYCLES).is_err(), "non-zero genesis counters must reject");
    }
}

// ---- type-id'd pools (32-byte anchor args bound to the genesis input) ----

/// The type-id a type-id'd anchor must carry: blake2b256("ckb-default-hash", first input).
fn type_id_of(first_input: &CellInput) -> [u8; 32] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(first_input.as_slice());
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Build a canonical-empty genesis whose anchor type script carries `make_args(first_input)`.
fn build_with_args(make_args: impl FnOnce(&CellInput) -> Vec<u8>) -> (Context, TransactionView) {
    let bin: Bytes = std::fs::read(CONTRACT_BIN).expect("build crates/ckb-contract first").into();
    let mut ctx = Context::default();
    let contract_op = ctx.deploy_cell(bin);
    let as_op = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let lock = ctx.build_script(&as_op, Bytes::from(b"lock".to_vec())).unwrap();
    let funding = ctx.create_cell(
        CellOutput::new_builder().capacity(1000u64.pack()).lock(lock.clone()).build(),
        Bytes::new(),
    );
    let first_input = CellInput::new_builder().previous_output(funding).build();
    let type_script = ctx.build_script(&contract_op, Bytes::from(make_args(&first_input))).unwrap();
    let tx = TransactionBuilder::default()
        .input(first_input)
        .output(
            CellOutput::new_builder()
                .capacity(1000u64.pack())
                .lock(lock)
                .type_(Some(type_script).pack())
                .build(),
        )
        .output_data(Bytes::from(anchor(&EMPTY_ROOT, 0, 0, 0, 0)).pack())
        .cell_dep(CellDep::new_builder().out_point(contract_op).build())
        .cell_dep(CellDep::new_builder().out_point(as_op).build())
        .build();
    let tx = ctx.complete_tx(tx);
    (ctx, tx)
}

#[test]
fn genesis_type_id_pool_accepts() {
    let (ctx, tx) = build_with_args(|inp| type_id_of(inp).to_vec());
    ctx.verify_tx(&tx, MAX_CYCLES)
        .expect("a type-id'd genesis (args == blake2b(first input)) must verify");
}

#[test]
fn genesis_type_id_mismatch_rejected() {
    let (ctx, tx) = build_with_args(|inp| {
        let mut id = type_id_of(inp);
        id[0] ^= 0xff; // not blake2b(first input)
        id.to_vec()
    });
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "a type-id'd genesis whose args != blake2b(first input) must reject (forged identity)"
    );
}

#[test]
fn genesis_malformed_args_rejected() {
    let (ctx, tx) = build_with_args(|_| vec![0u8; 16]); // neither empty (legacy) nor 32 bytes
    assert!(
        ctx.verify_tx(&tx, MAX_CYCLES).is_err(),
        "anchor args of a non-32 length must reject"
    );
}
