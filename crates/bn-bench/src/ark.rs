// One BN254 pairing via ark-bn254 (modern pure-Rust), same operation as substrate.rs.
#![no_std]
#![no_main]

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_std::Zero;

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

fn program_entry() -> i8 {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let r = Bn254::pairing(g1, g2);
    // Use the result (defeat DCE); e(G1,G2) is not the identity, so this never returns 1.
    if r.is_zero() {
        return 1;
    }
    0
}
