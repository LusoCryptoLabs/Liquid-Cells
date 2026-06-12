//! SP1 Groth16 (BN254) verifier for the Liquid Cells anchor type script.
//!
//! `no_std`, pure-Rust ark-bn254: a plain 4-pairing Groth16 check measured at ~80M cycles on
//! CKB-VM (~2% of the ~3.50B block limit), with no `e(alpha,beta)` precompute. This crate is the
//! **single source of truth** for the verifier: the on-chain contract (`crates/ckb-contract`) and
//! the differential test (`crates/verifier-difftest`) both call [`verify_sp1_groth16`], so the
//! deployed bytes and the tested bytes are identical. (The differential test additionally checks
//! this against an independent substrate-bn implementation over a fuzzed corpus.)
//!
//! Field elements are big-endian (matching SP1 / the g16ckb verifier this is adapted from). The
//! soundness constants `exit_code == 0` and `vk_root == vk_root` are checked before the pairing.

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use sha2::{Digest, Sha256};

/// SP1 Groth16 proof length: `vkh(4) ‖ exit_code(32) ‖ vk_root(32) ‖ proof_nonce(32) ‖ gnark(256)`.
pub const PROOF_LEN: usize = 356;

const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
#[allow(dead_code)] // documents the bit pattern; deserialize takes the `else` branch for it
const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const COMPRESSED_INFINITY: u8 = 0b01 << 6;

#[derive(PartialEq)]
enum Flag {
    Positive,
    Negative,
    Infinity,
}

fn slice32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
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
    let x = Fq::from_be_bytes_mod_order(&xb);
    let flag = if m == COMPRESSED_POSITIVE { Flag::Positive } else { Flag::Negative };
    Some((x, flag))
}

// gnark compressed-point convention: a `Positive` flag selects the smaller y, `Negative` the
// larger. ark's `get_point_from_x_unchecked(x, greatest)` returns the larger y when greatest is
// true, so `greatest = (flag == Negative)`.
fn comp_x_to_g1(buf: &[u8]) -> Option<G1Affine> {
    let (x, m) = deserialize_with_flags(buf)?;
    if m == Flag::Infinity {
        return Some(G1Affine::zero());
    }
    G1Affine::get_point_from_x_unchecked(x, m == Flag::Negative)
}

fn uncomp_g1(buf: &[u8]) -> Option<G1Affine> {
    if buf.len() != 64 {
        return None;
    }
    let x = Fq::from_be_bytes_mod_order(&buf[..32]);
    let y = Fq::from_be_bytes_mod_order(&buf[32..]);
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(p)
}

fn comp_x_to_g2(buf: &[u8]) -> Option<G2Affine> {
    if buf.len() != 64 {
        return None;
    }
    let (x1, flag) = deserialize_with_flags(&buf[..32])?;
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let x = Fq2::new(x0, x1);
    if flag == Flag::Infinity {
        return Some(G2Affine::zero());
    }
    G2Affine::get_point_from_x_unchecked(x, flag == Flag::Negative)
}

fn uncomp_g2(buf: &[u8]) -> Option<G2Affine> {
    if buf.len() != 128 {
        return None;
    }
    let x1 = Fq::from_be_bytes_mod_order(&buf[0..32]);
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let y1 = Fq::from_be_bytes_mod_order(&buf[64..96]);
    let y0 = Fq::from_be_bytes_mod_order(&buf[96..128]);
    let p = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1));
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(p)
}

struct Vk {
    alpha: G1Affine,
    k: Vec<G1Affine>,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
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
    Some(Vk { alpha, k, beta, gamma, delta })
}

struct Pf {
    ar: G1Affine,
    krs: G1Affine,
    bs: G2Affine,
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

fn prepare_inputs(vk: &Vk, public_inputs: &[Fr]) -> Option<G1Affine> {
    if (public_inputs.len() + 1) != vk.k.len() {
        return None;
    }
    let mut acc = vk.k[0].into_group();
    for (i, b) in public_inputs.iter().zip(vk.k.iter().skip(1)) {
        if !i.is_zero() {
            acc += *b * *i;
        }
    }
    Some(acc.into_affine())
}

fn verify_alg(vk: &Vk, p: &Pf, public_inputs: &[Fr]) -> bool {
    let vk_x = match prepare_inputs(vk, public_inputs) {
        Some(x) => x,
        None => return false,
    };
    // Standard Groth16 check as one 4-pairing product == 1:
    //   e(A,B) · e(-alpha,beta) · e(-vk_x,gamma) · e(-C,delta) == 1
    let g1s = [p.ar, -vk.alpha, -vk_x, -p.krs];
    let g2s = [p.bs, vk.beta, vk.gamma, vk.delta];
    Bn254::multi_pairing(g1s, g2s).is_zero()
}

/// Verify an SP1 Groth16 proof of a Liquid Cells transition. Returns `0` on success, a non-zero
/// code otherwise. `vk` is the Groth16 verifying-key bytes; `vkey_hash` (the SP1 program vkey) and
/// `vk_root` (the SP1 recursion vk root) are the caller's baked soundness constants. Public inputs:
/// `[vkey_hash, sha256(public_values) with top 3 bits cleared, exit_code, vk_root, proof_nonce]`.
pub fn verify_sp1_groth16(
    proof: &[u8],
    public_values: &[u8],
    vk: &[u8],
    vkey_hash: &[u8; 32],
    vk_root: &[u8; 32],
) -> i8 {
    if proof.len() != PROOF_LEN {
        return 10;
    }
    let vkh = Sha256::digest(vk);
    if vkh[..4] != proof[..4] {
        return 10;
    }
    let exit_code = slice32(&proof[4..36]);
    let proof_vk_root = slice32(&proof[36..68]);
    let proof_nonce = slice32(&proof[68..100]);
    let gnark = &proof[100..356];

    if exit_code != [0u8; 32] {
        return 20;
    }
    if &proof_vk_root != vk_root {
        return 21;
    }

    let mut pd: [u8; 32] = Sha256::digest(public_values).into();
    pd[0] &= 0x1F; // sha256(pv) with top 3 bits cleared, to fit BN254 Fr

    let inputs_bytes: [[u8; 32]; 5] = [*vkey_hash, pd, exit_code, *vk_root, proof_nonce];
    let mut frs: Vec<Fr> = Vec::new();
    for ib in inputs_bytes.iter() {
        // 32-byte big-endian field element; the prover ensures each is < the BN254 scalar
        // modulus, so reduce-mod is exact (matches the previous Fr::from_slice behavior).
        frs.push(Fr::from_be_bytes_mod_order(ib));
    }

    let vk = match load_vk(vk) {
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
