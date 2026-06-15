//! Liquid Cells anchor type script, guards the pool anchor cell in three modes,
//! selected by the input group's witness `input_type` length:
//!
//!   * **checkpoint** (`input_type` len 644): a sequencer state transition, verify its
//!     SP1 Groth16 proof inside CKB-VM and pin the public values to chain facts.
//!   * **force-exit** (`input_type` len 8249): a *unilateral* user withdrawal of an ordinary
//!     account leaf against the last committed root after operator silence, no proof, an SMT
//!     inclusion path. The escape hatch that makes the operator unable to freeze funds by
//!     going dark.
//!   * **force-refund** (`input_type` len 8321): the same escape hatch for a *timed-out HTLC
//!     escrow leaf*, the sender reclaims an escrow whose `timeout` has passed (so the
//!     receiver can no longer claim it) by proving the lock terms, against the committed root,
//!     after operator silence. Closes the dust-swap sender's exposure if the operator dies
//!     mid-swap. (The receiver's symmetric force-claim cannot be given under a single anchor, 
//!     see `force_refund`, so this is deliberately sender-only.)
//!
//! All modes have exactly one **input** anchor (state n) and one **output** anchor
//! (state n+1) carrying this type script, and all enforce **anchor lock continuity**
//! (output anchor lock == input anchor lock), so the genesis lock is a permanent policy
//! for *who may sequence*: a permissive (always-success) genesis lock ⇒ a permanently
//! **permissionless**, capture-proof pool; a specific lock ⇒ a pool pinned to it.
//!
//!   anchor cell data (80 bytes): root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE) ‖ last_epoch(8 BE)
//!   checkpoint witness input_type  : proof(356) ‖ public_values(288)
//!   checkpoint witness output_type : da_blob (the published state diff)
//!   force-exit witness input_type  : pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32)
//!   force-refund witness input_type: sender_pubkey(33) ‖ receiver_key(32) ‖ amount(16)
//!                                    ‖ hashlock(32) ‖ timeout(8) ‖ lock_nonce(8) ‖ siblings(256·32)
//!
//! The script, in order (cheap checks first so a tampered transaction is rejected
//! without paying for the BN254 pairing): (1) pins `prev_*`/`new_*` in the public
//! values to the input/output anchor cell data and checks sequence/fee continuity
//! (`new_fee_acc == prev_fee_acc + fee_delta − fee_withdrawal`); (2) recomputes the
//! deposits/withdrawals commitments from the real non-anchor cells and binds them to
//! the proof; (3) checks value conservation, accounting
//! (`prev_total + Σdep − Σwd − fee_withdrawal == new_total`) and solvency
//! (`out_cap − in_cap == Σdep − Σwd − fee_withdrawal`), which pins the L1 miner fee to
//! the proven `fee_withdrawal`; then (4) verifies the SP1 Groth16 proof of the public
//! values. Field elements are big-endian (matching SP1 / the g16ckb verifier this is
//! adapted from), with the soundness checks `exit_code == 0` and `vk_root == VK_ROOT`
//! added.
//!
//! The `fee_withdrawal` is the CKB the sequencer draws from accumulated pool fees to
//! fund the on-chain miner fee; the in-circuit STF caps it at fee revenue, so the
//! solvency check above makes "an L1 fee is never skimmed from a user balance" an
//! on-chain-verifiable fact.
//!
//! Data availability (Phase 4): the proof commits `da_commitment = keccak(da_blob)` over
//! the touched leaves' post-state, and the checkpoint tx must carry that exact blob in
//! the anchor witness `output_type`. The script recomputes `keccak(blob)` and binds it
//! (code 59), so the operator cannot advance the root while withholding the diff, any
//! user can replay the published blobs and force-exit.

#![no_std]
#![no_main]

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::WitnessArgs;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type_hash,
    load_input, load_input_since, load_script, load_script_hash, load_witness_args,
};
use liquid_cells_groth16::{verify_sp1_groth16, PROOF_LEN};
use sha3::{Digest, Keccak256};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

mod atomics;
mod cells; // checkpoint cell folding + public-value binding
mod escape; // force-exit / force-refund (the unilateral escape hatch)

// ---- baked policy ----
/// SP1 v6 Groth16 universal verifying key (identical to the g16ckb / bridge VK).
static GROTH16_VK: &[u8] = include_bytes!("../../../fixtures/reference/groth16_vk.bin");
/// Our program's SP1 vkey hash (`0x00213af5…c1e8`), binds the proof to *this* STF.
/// (Re-derived again in Phase 5 when the STF gained HTLC ops. History: `0x00add002…55ee9`
/// (P4 DA), `0x00cd19a7…521f5` (2b-5 fee), `0x00fda595…ace165` (2a). Any STF change ⇒
/// this must be re-baked.)
static VKEY_HASH: [u8; 32] = [
    0x00, 0x21, 0x3a, 0xf5, 0xb4, 0xcc, 0x89, 0x22, 0x75, 0x4e, 0x5b, 0x8e, 0xe7, 0xe6, 0x10, 0xde,
    0x70, 0x3d, 0x4c, 0xb1, 0x7f, 0xab, 0xb0, 0xa1, 0x87, 0xc9, 0x5c, 0x37, 0xfe, 0x67, 0xc1, 0xe8,
];
/// SP1 v6.1.0 recursion vk root.
static VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];
/// This pool's identity (= keccak("sp1-pool") in the current fixture).
static POOL_ID: [u8; 32] = [
    0x9e, 0xc3, 0xa1, 0x2f, 0xb4, 0xe1, 0xf5, 0x6b, 0x53, 0xa0, 0x2d, 0xfa, 0xcb, 0x20, 0x63, 0xd0,
    0x48, 0xc6, 0x14, 0x40, 0x8a, 0x01, 0x1d, 0xd3, 0x27, 0x92, 0x63, 0xa9, 0x12, 0x2c, 0x4e, 0x01,
];
const CHAIN_ID: u64 = 0x0043_4b42;

/// CKB system `secp256k1_blake160_sighash_all` lock code hash (hash_type = Type; the same
/// constant on mainnet and Pudge). Force-exit payouts are forced to this lock with
/// `args = blake160(pubkey)`, so a unilateral exit can only pay the leaf owner's own
/// address, no in-contract signature needed.
static SECP_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];
/// Operator-silence window: a leaf can only be force-exited once `last_epoch + TIMEOUT`
/// epochs have passed with no checkpoint (~30 days at ~4h/epoch). While the operator keeps
/// checkpointing, `last_epoch` advances and the window never opens.
const FORCE_EXIT_TIMEOUT_EPOCHS: u64 = 180;
const SMT_DEPTH: usize = 256;

/// The empty sparse-Merkle-tree root (depth-256, keccak), the genesis pool root. Must
/// equal `liquid_cells_stf::smt::Smt::new().root()` (pinned by `crates/stf/tests/genesis.rs`).
static EMPTY_ROOT: [u8; 32] = [
    0xa7, 0xff, 0x9e, 0x28, 0xff, 0xd3, 0xde, 0xf4, 0x43, 0xd3, 0x24, 0x54, 0x76, 0x88, 0xc2, 0xc4,
    0xeb, 0x98, 0xed, 0xf7, 0xda, 0x75, 0x7d, 0x6b, 0xfa, 0x22, 0xbf, 0xf5, 0x5b, 0x9c, 0xe2, 0x4a,
];

// ---- layouts ----
const ANCHOR_LEN: usize = 80; // root(32) seq(8) total(16) fee_acc(16) last_epoch(8)
const PV_LEN: usize = 288;
// PROOF_LEN (356) is imported from liquid-cells-groth16 (the SP1 proof format), the single source
// of truth for the verifier.
const WITNESS_LEN: usize = PROOF_LEN + PV_LEN; // 644, checkpoint witness input_type
/// Force-exit witness input_type: pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32).
const FORCEEXIT_LEN: usize = 33 + 16 + 8 + 32 * SMT_DEPTH; // 8249
/// Force-refund witness input_type: sender_pubkey(33) ‖ receiver_key(32) ‖ amount(16) ‖
/// hashlock(32) ‖ timeout(8) ‖ lock_nonce(8) ‖ siblings(256·32). Distinct length from
/// checkpoint (644) and force-exit (8249), so the mode is selected unambiguously.
#[cfg(not(feature = "htlc_keyspace"))]
const FORCEREFUND_LEN: usize = 33 + 32 + 16 + 32 + 8 + 8 + 32 * SMT_DEPTH; // 8321
// Under `htlc_keyspace` (audit H-1): the witness also carries the actual committed escrow balance
// (16 bytes after lock_nonce) so force-refund can reconstruct/sweep a balance-altered escrow.
#[cfg(feature = "htlc_keyspace")]
const FORCEREFUND_LEN: usize = 33 + 32 + 16 + 32 + 8 + 8 + 16 + 32 * SMT_DEPTH; // 8337

// anchor data offsets
const A_ROOT: usize = 0;
const A_SEQ: usize = 32;
const A_TOTAL: usize = 40;
const A_FEE: usize = 56;
const A_LAST_EPOCH: usize = 72;

// PublicValues offsets (liquid_cells_stf::PublicValues::encode)
const PV_POOL_ID: usize = 0;
const PV_CHAIN_ID: usize = 32;
const PV_PREV_ROOT: usize = 40;
const PV_PREV_SEQ: usize = 72;
const PV_NEW_ROOT: usize = 80;
const PV_NEW_SEQ: usize = 112;
const PV_DEP_COMMIT: usize = 120;
const PV_WD_COMMIT: usize = 152;
const PV_PREV_TOTAL: usize = 184;
const PV_NEW_TOTAL: usize = 200;
const PV_FEE_DELTA: usize = 216;
// (current_epoch occupies 232..240)
const PV_FEE_WD: usize = 240;
const PV_CURRENT_EPOCH: usize = 232;
const PV_DA_COMMIT: usize = 256;

fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_be_bytes(a)
}
fn rd_u128(b: &[u8], off: usize) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[off..off + 16]);
    u128::from_be_bytes(a)
}
fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&Keccak256::digest(bytes));
    o
}

/// Extract the epoch number from a CKB `since` flagged **absolute epoch** (`0x20` top byte).
/// Low 24 bits are the epoch number; the index/length fraction is ignored (whole-epoch
/// granularity). `None` if not absolute-epoch. Shared by `checkpoint` and the `escape` modes.
fn abs_epoch(since: u64) -> Option<u64> {
    if (since >> 56) != 0x20 {
        return None;
    }
    Some(since & 0x00FF_FFFF)
}

/// The pool's identity, the single source of truth for `pool_id`.
///   * **empty type-script args** => the baked [`POOL_ID`] (the originally-deployed pool;
///     backward-compatible, so the live pool keeps working under this upgrade).
///   * **32-byte args** => a *type-id'd* pool whose identity IS that 32-byte value, made unique
///     and unforgeable by binding it to a spent UTXO at genesis (see [`anchor_type_id`]). Each
///     such pool has a distinct anchor type-script hash, which is what lets a deposit lock bind
///     to one specific pool.
/// `None` if the args are a malformed length.
fn pool_id() -> Option<[u8; 32]> {
    let script = load_script().ok()?;
    let args = script.args().raw_data();
    if args.is_empty() {
        Some(POOL_ID)
    } else if args.len() == 32 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&args);
        Some(id)
    } else {
        None
    }
}

/// The type-id a 32-byte-args anchor must carry: `blake2b256("ckb-default-hash", first_input)`.
/// The tx's first input is a UTXO consumed at genesis, so it can never recur, the pool's
/// identity is therefore globally unique and unforgeable (the standard CKB type-id binding).
fn anchor_type_id() -> Option<[u8; 32]> {
    let first_input = load_input(0, Source::Input).ok()?;
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(first_input.as_slice());
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    Some(out)
}


/// Genesis (pool creation): an OUTPUT anchor with **no input anchor**, which must hold the
/// canonical empty state (empty SMT root, all counters zero). The type script runs when the
/// anchor cell is first created, so this branch is required, otherwise creating the pool is
/// rejected for lack of an input group. Anyone may create such a pool; it always starts
/// empty, so genesis confers no power. (A production singleton would seal it with a type-id
/// in the anchor args; v1 keeps empty args + baked policy.)
fn genesis() -> i8 {
    let new = match load_cell_data(0, Source::GroupOutput) {
        Ok(d) => d,
        Err(_) => return 41,
    };
    if load_cell_data(1, Source::GroupOutput).is_ok() {
        return 40;
    }
    if new.len() != ANCHOR_LEN {
        return 30;
    }
    if new[A_ROOT..A_ROOT + 32] != EMPTY_ROOT {
        return 70;
    }
    if rd_u64(&new, A_SEQ) != 0
        || rd_u128(&new, A_TOTAL) != 0
        || rd_u128(&new, A_FEE) != 0
        || rd_u64(&new, A_LAST_EPOCH) != 0
    {
        return 71;
    }
    // Type-id binding: a type-id'd pool (32-byte args) must set its args to blake2b(first input),
    // pinning its identity to a consumed UTXO so it is unique and unforgeable. A legacy pool
    // (empty args) skips this, it keeps the baked POOL_ID. Malformed args are rejected.
    let pid = match pool_id() {
        Some(p) => p,
        None => return 72,
    };
    let args_present = load_script().map(|s| !s.args().raw_data().is_empty()).unwrap_or(false);
    if args_present {
        match anchor_type_id() {
            Some(tid) if tid == pid => {}
            _ => return 73,
        }
    }
    0
}

fn program_entry() -> i8 {
    // The anchor type script runs whenever an anchor cell is consumed or created. Genesis
    // (pool creation) has an output anchor but no input anchor, handle it first, else the
    // `GroupInput` load below would reject the creation (code 41).
    let prev = match load_cell_data(0, Source::GroupInput) {
        Ok(d) => d,
        Err(SysError::IndexOutOfBound) => return genesis(),
        Err(_) => return 41,
    };
    if load_cell_data(1, Source::GroupInput).is_ok() {
        return 40;
    }
    let new = match load_cell_data(0, Source::GroupOutput) {
        Ok(d) => d,
        Err(_) => return 41,
    };
    if load_cell_data(1, Source::GroupOutput).is_ok() {
        return 40;
    }
    if prev.len() != ANCHOR_LEN || new.len() != ANCHOR_LEN {
        return 30;
    }

    // Anchor lock continuity (permissionless-safety). The anchor's lock may never change across
    // a transition: the output anchor's lock hash must equal the input anchor's. This turns the
    // **genesis** lock into a permanent, unforgeable policy for *who may sequence*:
    //   * a pool created with a permissive (e.g. always-success) lock is permanently
    //     PERMISSIONLESS, anyone who can produce a valid proof may advance the root, and
    //     **capture-proof**: no checkpoint can re-lock the anchor to seize sequencing;
    //   * a pool created with a specific lock (multisig, governance, a single operator) stays
    //     pinned to exactly that lock forever.
    // Checked before mode dispatch, so it binds checkpoint, force-exit, and force-refund alike.
    // (Genesis has no input anchor, so it returns above and never reaches here, the pool
    // creator's initial lock choice is what gets locked in.)
    let in_lock = match load_cell_lock_hash(0, Source::GroupInput) {
        Ok(h) => h,
        Err(_) => return 46,
    };
    let out_lock = match load_cell_lock_hash(0, Source::GroupOutput) {
        Ok(h) => h,
        Err(_) => return 46,
    };
    if in_lock != out_lock {
        return 46;
    }

    // The input group's witness `input_type` selects the mode by length:
    //   WITNESS_LEN (644)      => checkpoint (SP1 proof + pinned public values)
    //   FORCEEXIT_LEN (8249)   => force-exit (account-leaf SMT inclusion vs the committed root)
    //   FORCEREFUND_LEN (8321) => force-refund (timed-out HTLC escrow leaf, sender reclaims)
    let wa = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w,
        Err(_) => return 42,
    };
    let wb = match wa.input_type().to_opt() {
        Some(b) => b.raw_data(),
        None => return 42,
    };
    match wb.len() {
        WITNESS_LEN => checkpoint(&prev, &new, &wa, &wb),
        FORCEEXIT_LEN => escape::force_exit(&prev, &new, &wb),
        FORCEREFUND_LEN => escape::force_refund(&prev, &new, &wb),
        _ => 42,
    }
}

/// A sequencer checkpoint: verify the SP1 Groth16 proof of the transition and pin its
/// public values to the anchor cells, the real deposit/withdrawal cells, value
/// conservation, the L1 fee draw, the DA blob, and the epoch clock.
fn checkpoint(prev: &[u8], new: &[u8], wa: &WitnessArgs, wb: &[u8]) -> i8 {
    let proof = &wb[0..PROOF_LEN];
    let pv = &wb[PROOF_LEN..WITNESS_LEN];

    // The pool this checkpoint must be for (baked POOL_ID for a legacy pool; the type-id for a
    // type-id'd pool). Cheap pins first, expensive pairing last.
    let pid = match pool_id() {
        Some(p) => p,
        None => return 31,
    };
    let b = cells::bind(prev, new, pv, &pid);
    if b != 0 {
        return b;
    }

    // The recorded epoch must not be in the future: the anchor input's `since` (absolute
    // epoch) must be ≥ current_epoch, so CKB only mines the checkpoint at/after that epoch.
    // This caps `last_epoch` at real chain time, so the force-exit timeout can't be pushed
    // out by lying about the epoch.
    let since = match load_input_since(0, Source::GroupInput) {
        Ok(s) => s,
        Err(_) => return 45,
    };
    match abs_epoch(since) {
        Some(e) if e >= rd_u64(pv, PV_CURRENT_EPOCH) => {}
        _ => return 45,
    }

    // Recompute deposits/withdrawals commitments from the real cells, bind them to the
    // proof, and check value conservation (accounting + real capacity). Still cheap.
    let self_hash = match load_script_hash() {
        Ok(h) => h,
        Err(_) => return 54,
    };
    let (dep_c, wd_c, sum_dep, sum_wd, sum_reward) = match cells::fold_cells(&self_hash) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if dep_c[..] != pv[PV_DEP_COMMIT..PV_DEP_COMMIT + 32] {
        return 55;
    }
    if wd_c[..] != pv[PV_WD_COMMIT..PV_WD_COMMIT + 32] {
        return 56;
    }
    // Data availability: the checkpoint must publish the state diff. keccak of the blob
    // carried in the anchor witness output_type must equal the proven da_commitment, so
    // the operator cannot advance the root while withholding it (code 59).
    let da_ok = match wa.output_type().to_opt() {
        Some(b) => keccak(&b.raw_data())[..] == pv[PV_DA_COMMIT..PV_DA_COMMIT + 32],
        None => keccak(&[])[..] == pv[PV_DA_COMMIT..PV_DA_COMMIT + 32],
    };
    if !da_ok {
        return 59;
    }
    // accounting: prev_total + Σdeposits − Σwithdrawals − fee_withdrawal == new_total
    let prev_total = rd_u128(pv, PV_PREV_TOTAL) as i128;
    let new_total = rd_u128(pv, PV_NEW_TOTAL) as i128;
    let fee_wd = rd_u128(pv, PV_FEE_WD) as i128;
    if prev_total + sum_dep - sum_wd - fee_wd != new_total {
        return 57;
    }
    // Sequencer reward (Phase 6b): the operator may pay itself reward cells out of the proven
    // fee_withdrawal (the remainder is the L1 miner fee). Bounded by fee_withdrawal, which the
    // STF caps at accrued fee revenue, so a reward can never be drawn from a user balance. This
    // is what makes permissionless sequencing profitable, hence self-sustaining.
    if sum_reward > fee_wd {
        return 47;
    }
    // solvency: the anchor's real capacity delta must equal Σdep − Σwd − fee_withdrawal.
    // Inputs are the anchor + deposits; outputs are the anchor + withdrawals + reward cells.
    // The reward cells (capacity sum_reward) are not in this equation, so the tx's miner fee
    // (Σin − Σout) works out to exactly fee_withdrawal − sum_reward, all of it drawn from
    // accumulated fees, never from a user balance.
    let in_cap = match load_cell_capacity(0, Source::GroupInput) {
        Ok(c) => c as i128,
        Err(_) => return 58,
    };
    let out_cap = match load_cell_capacity(0, Source::GroupOutput) {
        Ok(c) => c as i128,
        Err(_) => return 58,
    };
    if out_cap - in_cap != sum_dep - sum_wd - fee_wd {
        return 58;
    }

    verify_sp1_groth16(proof, pv, GROTH16_VK, &VKEY_HASH, &VK_ROOT)
}
