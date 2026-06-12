//! The on-chain Groth16 verifier against an independent reference, side by side.
//!
//! * [`ark_verify`] is the **live** verifier: it calls `liquid_cells_groth16::verify_sp1_groth16`
//!   directly, the exact ark-bn254 implementation the deployed contract runs (no copy, so this
//!   test can never drift from the deployed code).
//! * [`bn_verify`] is the **pre-port** verifier (the vendored, CKB-patched substrate-bn
//!   fork), copied verbatim from git commit `3e1b425^`, the implementation the port
//!   replaced. It uses the 3-pairing form with the baked `e(alpha,beta)` constant.
//!
//! Both take the identical `(proof, public_values)` bytes the type script sees and return
//! the identical `i8` status code shape (`0` == valid, non-zero == rejected). The tests in
//! `tests/difftest.rs` assert the two never disagree on accept/reject. The rejection *codes*
//! may differ (the libraries reject malformed field elements at different points), so the
//! tested invariant is agreement on validity, which is the only thing the chain cares about.

// shared constants (identical to the contract's baked values)
pub const PROOF_LEN: usize = 356;
const GROTH16_VK: &[u8] = include_bytes!("../../../fixtures/reference/groth16_vk.bin");

static VKEY_HASH: [u8; 32] = [
    0x00, 0x21, 0x3a, 0xf5, 0xb4, 0xcc, 0x89, 0x22, 0x75, 0x4e, 0x5b, 0x8e, 0xe7, 0xe6, 0x10, 0xde,
    0x70, 0x3d, 0x4c, 0xb1, 0x7f, 0xab, 0xb0, 0xa1, 0x87, 0xc9, 0x5c, 0x37, 0xfe, 0x67, 0xc1, 0xe8,
];
static VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];

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

/// Run BOTH verifiers and return `(ark_code, bn_code)`. A convenience for the tests.
pub fn both(proof: &[u8], public_values: &[u8]) -> (i8, i8) {
    (ark_verify(proof, public_values), bn_verify(proof, public_values))
}

/// The live (ark-bn254) verifier path: the ACTUAL deployed implementation from the shared
/// `liquid-cells-groth16` crate (not a copy), so this test guards the real code path.
pub fn ark_verify(proof: &[u8], public_values: &[u8]) -> i8 {
    liquid_cells_groth16::verify_sp1_groth16(proof, public_values, GROTH16_VK, &VKEY_HASH, &VK_ROOT)
}

/// The pre-port (substrate-bn) verifier path.
pub fn bn_verify(proof: &[u8], public_values: &[u8]) -> i8 {
    bn_verifier::verify_sp1_groth16(proof, public_values)
}


// =====================================================================================
// PRE-PORT verifier: substrate-bn (vendored fork). Verbatim from git 3e1b425^.
// =====================================================================================
mod bn_verifier {
    use super::*;
    use bn::{miller_loop_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1};
    use sha2::{Digest, Sha256};

    static ALPHA_BETA: &[u8; 384] = include_bytes!("../../../fixtures/reference/alpha_beta.bin");

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

    // `alpha`/`beta` are folded into the baked `ALPHA_BETA` constant for the 3-pairing form, so
    // they are parsed (to validate the vk bytes) but not read in `verify_alg`.
    #[allow(dead_code)]
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
        let ab = match Gt::from_bytes(ALPHA_BETA) {
            Some(g) => g,
            None => return false,
        };
        let ml = match miller_loop_batch(&[
            (p.bs.into(), -Into::<G1>::into(p.ar)),
            (vk.gamma.into(), prepared),
            (vk.delta.into(), p.krs.into()),
        ]) {
            Ok(g) => g,
            Err(_) => return false,
        };
        match ml.final_exponentiation() {
            Some(lhs) => lhs == ab,
            None => false,
        }
    }

    pub fn verify_sp1_groth16(proof: &[u8], public_values: &[u8]) -> i8 {
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
        pd[0] &= 0x1F;

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
}
