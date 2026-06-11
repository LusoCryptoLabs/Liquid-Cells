//! One-shot generator: compute ALPHA_BETA = e(alpha, beta) for the baked Groth16 VK and
//! print its 384-byte Gt serialization, to paste into the contract's `ALPHA_BETA`.
//!   cargo test --release --test alphabeta -- --nocapture
//! (Uses the vendored+patched bn crate's `Gt::to_bytes`, identical to the contract's bn.)

use bn::{pairing, AffineG1, AffineG2, Fq, Fq2, G2};

const MASK: u8 = 0b11 << 6;
const COMPRESSED_POSITIVE: u8 = 0b10 << 6;
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

#[test]
fn print_alpha_beta() {
    let vk = std::fs::read("../../fixtures/reference/groth16_vk.bin").expect("groth16_vk.bin");
    let alpha = comp_x_to_g1(&vk[..32]).expect("alpha");
    let beta = comp_x_to_g2(&vk[64..128]).expect("beta");
    // The contract's load_vk stores beta as -beta; ALPHA_BETA = pairing(alpha, -beta).
    let ab = pairing(alpha.into(), -Into::<G2>::into(beta));
    let bytes = ab.to_bytes();

    // Round-trip check against from_bytes.
    assert_eq!(bn::Gt::from_bytes(&bytes).map(|g| g.to_bytes()), Some(bytes));

    // Write the constant for the contract to include_bytes! (no hand-transcription).
    std::fs::write("../../fixtures/reference/alpha_beta.bin", &bytes).expect("write alpha_beta.bin");

    print!("ALPHA_BETA bytes (384):");
    for (i, b) in bytes.iter().enumerate() {
        if i % 12 == 0 {
            print!("\n   ");
        }
        print!(" 0x{:02x},", b);
    }
    println!();
}
