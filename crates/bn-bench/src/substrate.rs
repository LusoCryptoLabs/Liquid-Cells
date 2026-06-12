// One BN254 pairing via substrate-bn (the library our anchor verifier currently uses).
#![no_std]
#![no_main]

use bn::Group;

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

fn program_entry() -> i8 {
    let r = bn::pairing(bn::G1::one(), bn::G2::one());
    // Use the result (defeat dead-code elimination); e(G1,G2) != 1, so this never returns 1.
    if r == bn::Gt::one() {
        return 1;
    }
    0
}
