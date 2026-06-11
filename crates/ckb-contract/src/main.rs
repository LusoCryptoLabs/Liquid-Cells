//! Liquid Cells anchor type script — guards the pool anchor cell in two modes,
//! selected by the input group's witness `input_type` length:
//!
//!   * **checkpoint** (`input_type` len 644): a sequencer state transition — verify its
//!     SP1 Groth16 proof inside CKB-VM and pin the public values to chain facts.
//!   * **force-exit** (`input_type` len 8249): a *unilateral* user withdrawal against the
//!     last committed root after operator silence — no proof, an SMT inclusion path. The
//!     escape hatch that makes the operator unable to freeze funds by going dark.
//!
//! Both modes have exactly one **input** anchor (state n) and one **output** anchor
//! (state n+1) carrying this type script.
//!
//!   anchor cell data (80 bytes): root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE) ‖ last_epoch(8 BE)
//!   checkpoint witness input_type : proof(356) ‖ public_values(288)
//!   checkpoint witness output_type: da_blob (the published state diff)
//!   force-exit witness input_type : pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32)
//!
//! The script, in order (cheap checks first so a tampered transaction is rejected
//! without paying for the BN254 pairing): (1) pins `prev_*`/`new_*` in the public
//! values to the input/output anchor cell data and checks sequence/fee continuity
//! (`new_fee_acc == prev_fee_acc + fee_delta − fee_withdrawal`); (2) recomputes the
//! deposits/withdrawals commitments from the real non-anchor cells and binds them to
//! the proof; (3) checks value conservation — accounting
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
//! (code 59), so the operator cannot advance the root while withholding the diff — any
//! user can replay the published blobs and force-exit.

#![no_std]
#![no_main]

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::WitnessArgs;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type_hash,
    load_input_since, load_script_hash, load_witness_args,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

mod atomics;

// ---- baked policy ----
/// SP1 v6 Groth16 universal verifying key (identical to the g16ckb / bridge VK).
static GROTH16_VK: &[u8] = include_bytes!("../../../fixtures/reference/groth16_vk.bin");
/// Our program's SP1 vkey hash (`0x00213af5…c1e8`) — binds the proof to *this* STF.
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
/// address — no in-contract signature needed.
static SECP_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];
/// Operator-silence window: a leaf can only be force-exited once `last_epoch + TIMEOUT`
/// epochs have passed with no checkpoint (~30 days at ~4h/epoch). While the operator keeps
/// checkpointing, `last_epoch` advances and the window never opens.
const FORCE_EXIT_TIMEOUT_EPOCHS: u64 = 180;
const SMT_DEPTH: usize = 256;

/// The empty sparse-Merkle-tree root (depth-256, keccak) — the genesis pool root. Must
/// equal `liquid_cells_stf::smt::Smt::new().root()` (pinned by `crates/stf/tests/genesis.rs`).
static EMPTY_ROOT: [u8; 32] = [
    0xa7, 0xff, 0x9e, 0x28, 0xff, 0xd3, 0xde, 0xf4, 0x43, 0xd3, 0x24, 0x54, 0x76, 0x88, 0xc2, 0xc4,
    0xeb, 0x98, 0xed, 0xf7, 0xda, 0x75, 0x7d, 0x6b, 0xfa, 0x22, 0xbf, 0xf5, 0x5b, 0x9c, 0xe2, 0x4a,
];

// ---- layouts ----
const ANCHOR_LEN: usize = 80; // root(32) seq(8) total(16) fee_acc(16) last_epoch(8)
const PV_LEN: usize = 288;
const PROOF_LEN: usize = 356;
const WITNESS_LEN: usize = PROOF_LEN + PV_LEN; // 644 — checkpoint witness input_type
/// Force-exit witness input_type: pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32).
const FORCEEXIT_LEN: usize = 33 + 16 + 8 + 32 * SMT_DEPTH; // 8249

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

const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(PartialEq)]
enum Flag {
    Positive,
    Negative,
    Infinity,
}

fn deserialize_with_flags(buf: &[u8]) -> Option<(Fq, Flag)> {
    if buf.len() != 32 {
        return None;
    }
    let m = buf[0] & MASK;
    if m == 0 {
        return None;
    }
    if m == COMPRESSED_INFINITY {
        if buf[0] & !MASK == 0 && buf[1..].iter().all(|&b| b == 0) {
            return Some((Fq::zero(), Flag::Infinity));
        }
        return None;
    }
    let mut xb = [0u8; 32];
    xb.copy_from_slice(buf);
    xb[0] &= !MASK;
    let x = Fq::from_be_bytes_mod_order(&xb).ok()?;
    let flag = if m == COMPRESSED_POSITIVE { Flag::Positive } else { Flag::Negative };
    Some((x, flag))
}

fn comp_x_to_g1(buf: &[u8]) -> Option<AffineG1> {
    let (x, m) = deserialize_with_flags(buf)?;
    let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)?;
    let mut fy = y;
    if y.cmp(&neg_y) == core::cmp::Ordering::Greater {
        if m == Flag::Positive {
            fy = -y;
        }
    } else if m == Flag::Negative {
        fy = -y;
    }
    Some(AffineG1::new_unchecked(x, fy))
}

fn uncomp_g1(buf: &[u8]) -> Option<AffineG1> {
    if buf.len() != 64 {
        return None;
    }
    let x = Fq::from_slice(&buf[..32]).ok()?;
    let y = Fq::from_slice(&buf[32..]).ok()?;
    AffineG1::new(x, y).ok()
}

fn comp_x_to_g2(buf: &[u8]) -> Option<AffineG2> {
    if buf.len() != 64 {
        return None;
    }
    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]).ok()?;
    let x = Fq2::new(x0, x1);
    if flag == Flag::Infinity {
        return Some(AffineG2::zero());
    }
    let (y, neg_y) = AffineG2::get_ys_from_x_unchecked(x)?;
    match flag {
        Flag::Positive => Some(AffineG2::new_unchecked(x, y)),
        Flag::Negative => Some(AffineG2::new_unchecked(x, neg_y)),
        _ => None,
    }
}

fn uncomp_g2(buf: &[u8]) -> Option<AffineG2> {
    if buf.len() != 128 {
        return None;
    }
    let x1 = Fq::from_slice(&buf[0..32]).ok()?;
    let x0 = Fq::from_slice(&buf[32..64]).ok()?;
    let y1 = Fq::from_slice(&buf[64..96]).ok()?;
    let y0 = Fq::from_slice(&buf[96..128]).ok()?;
    AffineG2::new(Fq2::new(x0, x1), Fq2::new(y0, y1)).ok()
}

struct Vk {
    alpha: AffineG1,
    k: Vec<AffineG1>,
    beta: AffineG2,
    gamma: AffineG2,
    delta: AffineG2,
}

fn load_vk(buf: &[u8]) -> Option<Vk> {
    if buf.len() < 292 {
        return None;
    }
    let alpha = comp_x_to_g1(&buf[..32])?;
    let beta = comp_x_to_g2(&buf[64..128])?;
    let gamma = comp_x_to_g2(&buf[128..192])?;
    let delta = comp_x_to_g2(&buf[224..288])?;
    let num_k = u32::from_be_bytes([buf[288], buf[289], buf[290], buf[291]]);
    let mut k = Vec::new();
    let mut off = 292usize;
    if (buf.len() as u64) < (num_k as u64) * 32 + off as u64 {
        return None;
    }
    for _ in 0..num_k {
        k.push(comp_x_to_g1(&buf[off..off + 32])?);
        off += 32;
    }
    Some(Vk { alpha, k, beta: -beta, gamma, delta })
}

struct Pf {
    ar: AffineG1,
    krs: AffineG1,
    bs: AffineG2,
}

fn load_proof(buf: &[u8]) -> Option<Pf> {
    if buf.len() != 256 {
        return None;
    }
    let ar = uncomp_g1(&buf[..64])?;
    let bs = uncomp_g2(&buf[64..192])?;
    let krs = uncomp_g1(&buf[192..256])?;
    Some(Pf { ar, krs, bs })
}

fn prepare_inputs(vk: &Vk, public_inputs: &[Fr]) -> Option<G1> {
    if (public_inputs.len() + 1) != vk.k.len() {
        return None;
    }
    Some(
        public_inputs
            .iter()
            .zip(vk.k.iter().skip(1))
            .fold(vk.k[0], |acc, (i, b)| if *i != Fr::zero() { acc + (*b * *i) } else { acc })
            .into(),
    )
}

fn verify_alg(vk: &Vk, p: &Pf, public_inputs: &[Fr]) -> bool {
    let prepared = match prepare_inputs(vk, public_inputs) {
        Some(x) => x,
        None => return false,
    };
    // NOTE: this 4-pairing batch costs ~3.81B cycles, which EXCEEDS the CKB block cycle
    // limit (~3.50B) — confirmed by the live Pudge checkpoint rejection (see DEPLOY.md). The
    // fix is to precompute the constant e(alpha, beta) and verify 3 pairings instead of 4
    // (measured ~3.47B, under the limit), which needs a `bn`-crate patch to (de)serialize
    // the Gt constant. Tracked in DEPLOY.md.
    pairing_batch(&[
        (-Into::<G1>::into(p.ar), p.bs.into()),
        (prepared, vk.gamma.into()),
        (p.krs.into(), vk.delta.into()),
        (vk.alpha.into(), -Into::<G2>::into(vk.beta)),
    ]) == Gt::one()
}

fn slice32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}
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
/// Must match liquid_cells_stf::transition::fold_commit: keccak(acc ‖ key ‖ amount_be).
fn fold_commit(acc: &[u8; 32], key: &[u8; 32], amount: u128) -> [u8; 32] {
    let mut b = [0u8; 80];
    b[..32].copy_from_slice(acc);
    b[32..64].copy_from_slice(key);
    b[64..].copy_from_slice(&amount.to_be_bytes());
    keccak(&b)
}

/// Recompute the deposits/withdrawals commitments from the real cells, and sum their
/// amounts. Implicit format: a **deposit** is any non-anchor INPUT (credits
/// `data[0..32]` = to_key by its capacity); a **withdrawal** is any non-anchor OUTPUT
/// (pays its `lock_hash` its capacity). The anchor is the cell whose type script is
/// this one.
fn fold_cells(self_hash: &[u8; 32]) -> Result<([u8; 32], [u8; 32], i128, i128), i8> {
    let mut dep = keccak(b"LIQUIDCELLS/v1/deposits-commitment");
    let mut sum_dep: i128 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_capacity(i, Source::Input) {
            Ok(cap) => {
                let th = load_cell_type_hash(i, Source::Input).map_err(|_| 50i8)?;
                if th.as_ref() != Some(self_hash) {
                    let data = load_cell_data(i, Source::Input).map_err(|_| 50i8)?;
                    if data.len() < 32 {
                        return Err(51);
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&data[..32]);
                    dep = fold_commit(&dep, &key, cap as u128);
                    sum_dep += cap as i128;
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(50),
        }
    }
    let mut wd = keccak(b"LIQUIDCELLS/v1/withdrawals-commitment");
    let mut sum_wd: i128 = 0;
    let mut j = 0usize;
    loop {
        match load_cell_capacity(j, Source::Output) {
            Ok(cap) => {
                let th = load_cell_type_hash(j, Source::Output).map_err(|_| 52i8)?;
                if th.as_ref() != Some(self_hash) {
                    let lh = load_cell_lock_hash(j, Source::Output).map_err(|_| 52i8)?;
                    wd = fold_commit(&wd, &lh, cap as u128);
                    sum_wd += cap as i128;
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(52),
        }
    }
    Ok((dep, wd, sum_dep, sum_wd))
}

/// Pin the public values to the anchor cells. Cheap; runs before the proof verify so
/// a tampered transaction is rejected without paying for the BN254 pairing.
fn bind(prev: &[u8], new: &[u8], pv: &[u8]) -> i8 {
    if pv.len() != PV_LEN || prev.len() != ANCHOR_LEN || new.len() != ANCHOR_LEN {
        return 30;
    }
    if pv[PV_POOL_ID..PV_POOL_ID + 32] != POOL_ID {
        return 31;
    }
    if rd_u64(pv, PV_CHAIN_ID) != CHAIN_ID {
        return 32;
    }
    let prev_seq = rd_u64(pv, PV_PREV_SEQ);
    let new_seq = rd_u64(pv, PV_NEW_SEQ);
    if prev_seq.checked_add(1) != Some(new_seq) {
        return 33;
    }
    // input anchor == prev_*
    if prev[A_ROOT..A_ROOT + 32] != pv[PV_PREV_ROOT..PV_PREV_ROOT + 32] {
        return 34;
    }
    if rd_u64(prev, A_SEQ) != prev_seq {
        return 35;
    }
    if rd_u128(prev, A_TOTAL) != rd_u128(pv, PV_PREV_TOTAL) {
        return 36;
    }
    // output anchor == new_*
    if new[A_ROOT..A_ROOT + 32] != pv[PV_NEW_ROOT..PV_NEW_ROOT + 32] {
        return 37;
    }
    if rd_u64(new, A_SEQ) != new_seq {
        return 38;
    }
    if rd_u128(new, A_TOTAL) != rd_u128(pv, PV_NEW_TOTAL) {
        return 39;
    }
    // fee accumulator continuity with the L1 fee draw:
    //   new_fee_acc == prev_fee_acc + fee_delta − fee_withdrawal,
    // and fee_withdrawal ≤ prev_fee_acc + fee_delta (no drawing from user balances).
    let fee_avail = match rd_u128(prev, A_FEE).checked_add(rd_u128(pv, PV_FEE_DELTA)) {
        Some(a) => a,
        None => return 43,
    };
    let fee_wd = rd_u128(pv, PV_FEE_WD);
    if fee_wd > fee_avail || fee_avail - fee_wd != rd_u128(new, A_FEE) {
        return 43;
    }
    // epoch continuity: the checkpoint records its epoch into the output anchor — this is
    // the clock the force-exit timeout reads. `new.last_epoch == current_epoch`, and
    // epochs never go backward. (The `since` check in `checkpoint` proves the recorded
    // epoch is not in the future.)
    let cur_epoch = rd_u64(pv, PV_CURRENT_EPOCH);
    if rd_u64(new, A_LAST_EPOCH) != cur_epoch || cur_epoch < rd_u64(prev, A_LAST_EPOCH) {
        return 44;
    }
    0
}

// ---- force-exit primitives ----

/// Bit `i` of a 32-byte key, MSB-first (matches `liquid_cells_stf::smt::bit`).
#[inline]
fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

/// Leaf-content hash, matching `liquid_cells_stf::types::Leaf::hash`: empty `{0,0}` hashes
/// to the all-zero `EMPTY_LEAF`; otherwise keccak(balance(16 BE) ‖ nonce(8 BE)).
fn leaf_hash(balance: u128, nonce: u64) -> [u8; 32] {
    if balance == 0 && nonce == 0 {
        return [0u8; 32];
    }
    let mut enc = [0u8; 24];
    enc[..16].copy_from_slice(&balance.to_be_bytes());
    enc[16..].copy_from_slice(&nonce.to_be_bytes());
    keccak(&enc)
}

/// Reconstruct the SMT root from a single-leaf inclusion path, bottom-up — the exact walk
/// `liquid_cells_stf::smt::verify_proof` performs. `siblings` is 256 × 32 bytes top-down.
fn smt_root(key: &[u8; 32], leaf: &[u8; 32], siblings: &[u8]) -> [u8; 32] {
    let mut cur = *leaf;
    let mut depth = SMT_DEPTH;
    while depth > 0 {
        depth -= 1;
        let sib = &siblings[depth * 32..depth * 32 + 32];
        let mut buf = [0u8; 64];
        if bit(key, depth) == 0 {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sib);
        } else {
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&cur);
        }
        cur = keccak(&buf);
    }
    cur
}

/// blake160(data) = first 20 bytes of CKB's default blake2b-256 — the secp lock's args.
fn blake160(data: &[u8]) -> [u8; 20] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..20]);
    r
}

/// Extract the epoch number from a CKB `since` that is flagged **absolute epoch**
/// (`0x20` in the top byte). The low 24 bits are the epoch number; the index/length
/// fraction is ignored (whole-epoch granularity). `None` if not absolute-epoch.
fn abs_epoch(since: u64) -> Option<u64> {
    if (since >> 56) != 0x20 {
        return None;
    }
    Some(since & 0x00FF_FFFF)
}

/// Is there an output paying exactly `amount` to the owner's canonical secp lock
/// (`code_hash == SECP_CODE_HASH`, hash_type == Type, `args == b160`)?
fn has_exit_output(b160: &[u8; 20], amount: u64) -> bool {
    let mut i = 0usize;
    loop {
        match load_cell_lock(i, Source::Output) {
            Ok(lock) => {
                if lock.code_hash().as_slice() == &SECP_CODE_HASH[..]
                    && lock.hash_type().as_slice()[0] == 1
                    && lock.args().raw_data().as_ref() == &b160[..]
                {
                    if let Ok(cap) = load_cell_capacity(i, Source::Output) {
                        if cap == amount {
                            return true;
                        }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

/// Force-exit (escape hatch): a user unilaterally withdraws their leaf against the last
/// committed root after the operator has been silent for `FORCE_EXIT_TIMEOUT_EPOCHS`. No
/// SP1 proof; the witness carries `pubkey ‖ balance ‖ nonce ‖ siblings`. The payout is
/// forced to the owner's own secp lock, the leaf is nullified (balance→0, nonce kept), and
/// the anchor capacity/total drop by exactly the exited balance.
fn force_exit(prev: &[u8], new: &[u8], wb: &[u8]) -> i8 {
    let pubkey = &wb[0..33];
    let balance = rd_u128(wb, 33);
    let nonce = rd_u64(wb, 49);
    let siblings = &wb[57..57 + 32 * SMT_DEPTH];
    if balance == 0 {
        return 60; // nothing to exit
    }
    if balance > u64::MAX as u128 {
        return 61; // cannot be paid out as a single capacity
    }

    let key = keccak(pubkey);
    // Inclusion of {balance, nonce} against the committed (input) root.
    let leaf = leaf_hash(balance, nonce);
    if smt_root(&key, &leaf, siblings)[..] != prev[A_ROOT..A_ROOT + 32] {
        return 62;
    }
    // Nullified root: balance→0, nonce kept (replay-safe), same siblings ⇒ output root.
    let new_leaf = leaf_hash(0, nonce);
    if smt_root(&key, &new_leaf, siblings)[..] != new[A_ROOT..A_ROOT + 32] {
        return 63;
    }

    // Anchor continuity: seq / fee_acc / last_epoch unchanged; total -= balance.
    if rd_u64(prev, A_SEQ) != rd_u64(new, A_SEQ)
        || rd_u128(prev, A_FEE) != rd_u128(new, A_FEE)
        || rd_u64(prev, A_LAST_EPOCH) != rd_u64(new, A_LAST_EPOCH)
        || rd_u128(prev, A_TOTAL).checked_sub(balance) != Some(rd_u128(new, A_TOTAL))
    {
        return 64;
    }

    // Solvency: the anchor's real capacity drops by exactly the exited balance.
    let in_cap = match load_cell_capacity(0, Source::GroupInput) {
        Ok(c) => c,
        Err(_) => return 65,
    };
    let out_cap = match load_cell_capacity(0, Source::GroupOutput) {
        Ok(c) => c,
        Err(_) => return 65,
    };
    if in_cap.checked_sub(balance as u64) != Some(out_cap) {
        return 65;
    }

    // Timeout: only after operator silence. Input `since` (absolute epoch) must be at least
    // `last_epoch + TIMEOUT`; CKB consensus refuses to mine the tx any earlier.
    let since = match load_input_since(0, Source::GroupInput) {
        Ok(s) => s,
        Err(_) => return 66,
    };
    let since_epoch = match abs_epoch(since) {
        Some(e) => e,
        None => return 66,
    };
    let open_at = match rd_u64(prev, A_LAST_EPOCH).checked_add(FORCE_EXIT_TIMEOUT_EPOCHS) {
        Some(e) => e,
        None => return 66,
    };
    if since_epoch < open_at {
        return 66;
    }

    // Payout: an output paying exactly `balance` to the owner's canonical secp lock.
    if !has_exit_output(&blake160(pubkey), balance as u64) {
        return 67;
    }
    0
}

/// Verify an SP1 Groth16 proof of `public_values`. 0 = ok, else a stage code.
fn verify_sp1_groth16(proof: &[u8], public_values: &[u8]) -> i8 {
    if proof.len() != PROOF_LEN {
        return 10;
    }
    let vkh = Sha256::digest(GROTH16_VK);
    if vkh[..4] != proof[..4] {
        return 10;
    }
    let exit_code = slice32(&proof[4..36]);
    let vk_root = slice32(&proof[36..68]);
    let proof_nonce = slice32(&proof[68..100]);
    let gnark = &proof[100..356];

    if exit_code != [0u8; 32] {
        return 20;
    }
    if vk_root != VK_ROOT {
        return 21;
    }

    let mut pd: [u8; 32] = Sha256::digest(public_values).into();
    pd[0] &= 0x1F; // sha256(pv) with top 3 bits cleared, to fit BN254 Fr

    let inputs_bytes: [[u8; 32]; 5] = [VKEY_HASH, pd, exit_code, vk_root, proof_nonce];
    let mut frs: Vec<Fr> = Vec::new();
    for ib in inputs_bytes.iter() {
        match Fr::from_slice(ib) {
            Ok(f) => frs.push(f),
            Err(_) => return 11,
        }
    }

    let vk = match load_vk(GROTH16_VK) {
        Some(v) => v,
        None => return 12,
    };
    let pf = match load_proof(gnark) {
        Some(p) => p,
        None => return 13,
    };
    if verify_alg(&vk, &pf, &frs) {
        0
    } else {
        1
    }
}

/// Genesis (pool creation): an OUTPUT anchor with **no input anchor**, which must hold the
/// canonical empty state (empty SMT root, all counters zero). The type script runs when the
/// anchor cell is first created, so this branch is required — otherwise creating the pool is
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
    0
}

fn program_entry() -> i8 {
    // The anchor type script runs whenever an anchor cell is consumed or created. Genesis
    // (pool creation) has an output anchor but no input anchor — handle it first, else the
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

    // The input group's witness `input_type` selects the mode by length:
    //   WITNESS_LEN (644)    => checkpoint (SP1 proof + pinned public values)
    //   FORCEEXIT_LEN (8249) => force-exit (SMT inclusion against the committed root)
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
        FORCEEXIT_LEN => force_exit(&prev, &new, &wb),
        _ => 42,
    }
}

/// A sequencer checkpoint: verify the SP1 Groth16 proof of the transition and pin its
/// public values to the anchor cells, the real deposit/withdrawal cells, value
/// conservation, the L1 fee draw, the DA blob, and the epoch clock.
fn checkpoint(prev: &[u8], new: &[u8], wa: &WitnessArgs, wb: &[u8]) -> i8 {
    let proof = &wb[0..PROOF_LEN];
    let pv = &wb[PROOF_LEN..WITNESS_LEN];

    // Cheap pins first, expensive pairing last.
    let b = bind(prev, new, pv);
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
    let (dep_c, wd_c, sum_dep, sum_wd) = match fold_cells(&self_hash) {
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
    // solvency: the anchor's real capacity delta must equal Σdep − Σwd − fee_withdrawal.
    // Since the only inputs are the anchor + deposits and the only outputs are the
    // anchor + withdrawals, the tx's miner fee (Σin − Σout) is then exactly the proven
    // fee_withdrawal — drawn from accumulated fees, never from a user balance.
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

    verify_sp1_groth16(proof, pv)
}
