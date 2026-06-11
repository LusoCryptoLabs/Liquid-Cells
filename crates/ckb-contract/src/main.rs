//! Liquid Cells anchor type script — verifies the SP1 Groth16 proof of a state
//! transition inside CKB-VM and pins its public values to the on-chain anchor cell.
//!
//! Transaction shape (one checkpoint): exactly one **input** anchor cell (state n)
//! and one **output** anchor cell (state n+1) carry this type script. The witness
//! for the input group carries `proof ‖ public_values`.
//!
//!   anchor cell data (72 bytes): root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE)
//!   witness input_type        : proof(356) ‖ public_values(256)
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
//! on-chain-verifiable fact. Not yet bound here: the DA blob (Phase 4).

#![no_std]
#![no_main]

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};
use ckb_std::ckb_constants::Source;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script_hash,
    load_witness_args,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

mod atomics;

// ---- baked policy ----
/// SP1 v6 Groth16 universal verifying key (identical to the g16ckb / bridge VK).
static GROTH16_VK: &[u8] = include_bytes!("../../../fixtures/reference/groth16_vk.bin");
/// Our program's SP1 vkey hash (`0x00cd19a7…521f5`) — binds the proof to *this* STF.
/// (Changed from the Phase-2a `0x00fda595…ace165` when the STF gained `fee_withdrawal`:
/// the guest ELF — which compiles in the STF — changed, so its program vkey changed.)
static VKEY_HASH: [u8; 32] = [
    0x00, 0xcd, 0x19, 0xa7, 0x49, 0x78, 0x2b, 0x8e, 0xa1, 0x85, 0x7b, 0xb0, 0x8c, 0x16, 0x85, 0xda,
    0x88, 0xa2, 0x26, 0x16, 0x99, 0x28, 0x92, 0xda, 0xff, 0x0e, 0x1a, 0xea, 0x6f, 0xf5, 0x21, 0xf5,
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

// ---- layouts ----
const ANCHOR_LEN: usize = 72; // root(32) seq(8) total(16) fee_acc(16)
const PV_LEN: usize = 256;
const PROOF_LEN: usize = 356;
const WITNESS_LEN: usize = PROOF_LEN + PV_LEN; // 612

// anchor data offsets
const A_ROOT: usize = 0;
const A_SEQ: usize = 32;
const A_TOTAL: usize = 40;
const A_FEE: usize = 56;

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

fn program_entry() -> i8 {
    // Exactly one input anchor and one output anchor (this type-script group).
    let prev = match load_cell_data(0, Source::GroupInput) {
        Ok(d) => d,
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

    // proof ‖ public_values from the input group's witness.
    let wa = match load_witness_args(0, Source::GroupInput) {
        Ok(w) => w,
        Err(_) => return 42,
    };
    let wb = match wa.input_type().to_opt() {
        Some(b) => b.raw_data(),
        None => return 42,
    };
    if wb.len() != WITNESS_LEN {
        return 42;
    }
    let proof = &wb[0..PROOF_LEN];
    let pv = &wb[PROOF_LEN..WITNESS_LEN];

    // Cheap pins first, expensive pairing last.
    let b = bind(&prev, &new, pv);
    if b != 0 {
        return b;
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
