//! Liquid Cells anchor type script — verifies the SP1 Groth16 proof of a state
//! transition inside CKB-VM and pins its public values to chain facts.
//!
//! The BN254 Groth16 verifier is adapted from the project's `g16-ckbvm` verifier
//! (itself vendored from SP1's `sp1-verifier`, Groth16 path), with two soundness
//! checks the Solidity reference makes that g16ckb omitted: `exit_code == 0` and
//! `vk_root == VK_ROOT`. Field elements are big-endian, matching SP1's encoding.
//!
//! **Phase 2b-1 (this file):** verifies a real proof + public values (baked in as
//! fixtures) and enforces the *baked* pins (program vkey, pool identity, monotonic
//! sequence). Run standalone in ckb-debugger → exit 0.
//!
//! **Phase 2b-2 (next):** read `proof` / `public_values` from the witness and pin
//! `prev_*` / `new_*` to the input/output anchor cell data, the deposits/withdrawals
//! commitments to the real deposit cells / withdrawal outputs, and the DA blob —
//! using ckb-std cell/witness syscalls. The verify + decode functions below are
//! written to be reused unchanged.

#![no_std]
#![no_main]

use alloc::vec::Vec;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};
use sha2::{Digest, Sha256};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

mod atomics;

// ---- baked policy ----
/// SP1 v6 Groth16 universal verifying key (identical to the one g16ckb/bridge use).
static GROTH16_VK: &[u8] = include_bytes!("../../../fixtures/reference/groth16_vk.bin");
/// Our program's SP1 vkey hash (`0x00fda595…ace165`) — binds the proof to *this* STF.
static VKEY_HASH: [u8; 32] = [
    0x00, 0xfd, 0xa5, 0x95, 0xb6, 0xc0, 0xb6, 0xe6, 0x4a, 0xf3, 0x34, 0xfb, 0xe7, 0xec, 0xfc, 0x02,
    0x9e, 0xc3, 0x14, 0xc0, 0x8c, 0xfc, 0x06, 0x26, 0x15, 0x33, 0xd2, 0x9b, 0x84, 0xac, 0xe1, 0x65,
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

// ---- Phase 2b-1 fixtures (2b-2 reads these from the witness instead) ----
static PROOF: &[u8] = include_bytes!("../../../fixtures/groth16_proof.bin"); // 356 bytes
static PUBVALS: &[u8] = include_bytes!("../../../fixtures/public_values.bin"); // 240 bytes

// PublicValues byte offsets (see liquid_cells_stf::PublicValues::encode).
const OFF_POOL_ID: usize = 0;
const OFF_CHAIN_ID: usize = 32;
const OFF_PREV_SEQ: usize = 72;
const OFF_NEW_SEQ: usize = 112;
const PV_LEN: usize = 240;

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
    beta: AffineG2, // stored negated, exactly as sp1-verifier
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

fn rd_u64(pv: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&pv[off..off + 8]);
    u64::from_be_bytes(a)
}

/// Verify an SP1 Groth16 proof of `public_values`. Returns 0 on success, or a
/// distinct nonzero stage code on failure. Reusable verbatim by the type-script
/// entrypoint in Phase 2b-2.
fn verify_sp1_groth16(proof: &[u8], public_values: &[u8]) -> i8 {
    if proof.len() != 356 {
        return 10;
    }
    // SP1 prepends the proof with the first 4 bytes of sha256(groth16_vk) as a selector.
    let vkh = Sha256::digest(GROTH16_VK);
    if vkh[..4] != proof[..4] {
        return 10;
    }
    let exit_code = slice32(&proof[4..36]);
    let vk_root = slice32(&proof[36..68]);
    let proof_nonce = slice32(&proof[68..100]);
    let gnark = &proof[100..356];

    // Soundness: the proof must attest a *successful* run of the *pinned* circuit.
    if exit_code != [0u8; 32] {
        return 20;
    }
    if vk_root != VK_ROOT {
        return 21;
    }

    // hash_public_inputs: sha256(public_values) with the top 3 bits cleared (fit BN254 Fr).
    let mut pd: [u8; 32] = Sha256::digest(public_values).into();
    pd[0] &= 0x1F;

    // 5 Groth16 public inputs, in sp1-verifier order.
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

/// Enforce the pins that depend only on baked policy + the public values themselves.
/// (The cell-data pins — prev/new roots & totals to the anchor cells, commitments to
/// deposit/withdrawal cells — are added in Phase 2b-2 where the tx is available.)
fn check_public_values(pv: &[u8]) -> i8 {
    if pv.len() != PV_LEN {
        return 30;
    }
    if pv[OFF_POOL_ID..OFF_POOL_ID + 32] != POOL_ID {
        return 31;
    }
    if rd_u64(pv, OFF_CHAIN_ID) != CHAIN_ID {
        return 32;
    }
    let prev_seq = rd_u64(pv, OFF_PREV_SEQ);
    let new_seq = rd_u64(pv, OFF_NEW_SEQ);
    if prev_seq.checked_add(1) != Some(new_seq) {
        return 33;
    }
    0
}

fn program_entry() -> i8 {
    let v = verify_sp1_groth16(PROOF, PUBVALS);
    if v != 0 {
        return v;
    }
    check_public_values(PUBVALS)
}
