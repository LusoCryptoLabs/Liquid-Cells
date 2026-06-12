//! Differential test: the live ark-bn254 verifier and the pre-port substrate-bn verifier must
//! agree on accept/reject for every real proof and every input in a fuzzed corpus.
//!
//! This is the safety net under a hand-ported curve-math implementation. If the port changed
//! behaviour on *any* input, a valid proof that one library accepts but the other rejects, or
//! a forged proof one accepts, this surfaces it. The hard invariant is `(ark==0) == (bn==0)`.

use verifier_difftest::{ark_verify, bn_verify, both, PROOF_LEN};

const PV_LEN: usize = 288;

/// Every real (proof, public_values) fixture in the tree, each a genuine SP1 Groth16 output.
fn corpus() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
    vec![
        ("demo/cp1", include_bytes!("../../../fixtures/demo/cp1/groth16_proof.bin"), include_bytes!("../../../fixtures/demo/cp1/public_values.bin")),
        ("demo/cp2", include_bytes!("../../../fixtures/demo/cp2/groth16_proof.bin"), include_bytes!("../../../fixtures/demo/cp2/public_values.bin")),
        ("genesis", include_bytes!("../../../fixtures/genesis/groth16_proof.bin"), include_bytes!("../../../fixtures/genesis/public_values.bin")),
        ("seq/cp2", include_bytes!("../../../fixtures/seq/cp2/groth16_proof.bin"), include_bytes!("../../../fixtures/seq/cp2/public_values.bin")),
        ("seq/cp3", include_bytes!("../../../fixtures/seq/cp3/groth16_proof.bin"), include_bytes!("../../../fixtures/seq/cp3/public_values.bin")),
        ("seq/cp4", include_bytes!("../../../fixtures/seq/cp4/groth16_proof.bin"), include_bytes!("../../../fixtures/seq/cp4/public_values.bin")),
        ("wd", include_bytes!("../../../fixtures/wd/groth16_proof.bin"), include_bytes!("../../../fixtures/wd/public_values.bin")),
        ("dw", include_bytes!("../../../fixtures/dw/groth16_proof.bin"), include_bytes!("../../../fixtures/dw/public_values.bin")),
        ("top", include_bytes!("../../../fixtures/groth16_proof.bin"), include_bytes!("../../../fixtures/public_values.bin")),
    ]
}

/// SplitMix64: reproducible, dependency-free.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

#[test]
fn the_live_cp1_proof_verifies_under_both_implementations() {
    // demo/cp1 is the proof the live ark verifier accepted on-chain on Pudge; both
    // implementations must accept it, anchoring the positive side of the differential.
    let (_, proof, pv) = corpus()[0];
    assert_eq!(ark_verify(proof, pv), 0, "ark must accept the live cp1 proof");
    assert_eq!(bn_verify(proof, pv), 0, "substrate-bn must accept the live cp1 proof");
}

#[test]
fn both_implementations_accept_exactly_the_same_real_fixtures() {
    let mut accepted = 0usize;
    for (name, proof, pv) in corpus() {
        let (a, b) = both(proof, pv);
        assert_eq!(a == 0, b == 0, "fixture {name}: ark={a} bn={b} disagree on validity");
        if a == 0 {
            accepted += 1;
        }
    }
    assert!(accepted >= 1, "the corpus must exercise the accepting path at least once");
}

#[test]
fn agree_under_single_bit_flips_in_the_proof() {
    // The dangerous class: a one-bit change in the gnark point bytes that one deserializer reads
    // as a different valid point than the other. Sweep every bit of a valid proof.
    let (_, base_proof, pv) = corpus()[0];
    let mut disagreements = 0;
    for byte in 0..PROOF_LEN {
        for bit in 0..8 {
            let mut p = base_proof.to_vec();
            p[byte] ^= 1 << bit;
            let (a, b) = both(&p, pv);
            if (a == 0) != (b == 0) {
                disagreements += 1;
                eprintln!("DISAGREE proof[{byte}] bit {bit}: ark={a} bn={b}");
            }
            // a tampered proof must never verify
            assert_ne!(a, 0, "ark accepted a single-bit-flipped proof at byte {byte} bit {bit}");
        }
    }
    assert_eq!(disagreements, 0, "verifiers disagreed on at least one single-bit proof flip");
}

#[test]
fn agree_under_single_bit_flips_in_the_public_values() {
    let (_, proof, base_pv) = corpus()[0];
    let mut disagreements = 0;
    for byte in 0..PV_LEN {
        for bit in 0..8 {
            let mut pv = base_pv.to_vec();
            pv[byte] ^= 1 << bit;
            let (a, b) = both(proof, &pv);
            if (a == 0) != (b == 0) {
                disagreements += 1;
                eprintln!("DISAGREE pv[{byte}] bit {bit}: ark={a} bn={b}");
            }
            assert_ne!(a, 0, "ark accepted a single-bit-flipped public_values at byte {byte} bit {bit}");
        }
    }
    assert_eq!(disagreements, 0, "verifiers disagreed on at least one single-bit pv flip");
}

#[test]
fn agree_under_random_multi_byte_mutations_across_the_corpus() {
    // Heavier random fuzz: multi-byte mutations, field zeroing, truncation, and cross-field
    // splicing, over every fixture. The only invariant that must hold is accept/reject agreement.
    let fixtures = corpus();
    let mut rng = Rng(0x1122_3344_5566_7788);
    let mut checked = 0usize;
    let mut accepted = 0usize;

    for _ in 0..2500 {
        let (_, base_proof, base_pv) = fixtures[rng.below(fixtures.len())];
        let mut proof = base_proof.to_vec();
        let mut pv = base_pv.to_vec();

        match rng.below(6) {
            0 => {
                // flip a handful of random proof bits
                for _ in 0..(1 + rng.below(6)) {
                    let i = rng.below(proof.len());
                    proof[i] ^= 1 << rng.below(8);
                }
            }
            1 => {
                // flip a handful of random pv bits
                for _ in 0..(1 + rng.below(6)) {
                    let i = rng.below(pv.len());
                    pv[i] ^= 1 << rng.below(8);
                }
            }
            2 => {
                // zero a random 32-byte aligned field of the proof
                let nfields = proof.len() / 32;
                let f = rng.below(nfields);
                for b in &mut proof[f * 32..f * 32 + 32] {
                    *b = 0;
                }
            }
            3 => {
                // set a random proof field to 0xFF (likely out of field / off curve)
                let nfields = proof.len() / 32;
                let f = rng.below(nfields);
                for b in &mut proof[f * 32..f * 32 + 32] {
                    *b = 0xFF;
                }
            }
            4 => {
                // truncate either input
                if rng.below(2) == 0 {
                    proof.truncate(rng.below(proof.len() + 1));
                } else {
                    pv.truncate(rng.below(pv.len() + 1));
                }
            }
            _ => {
                // splice a field from a different fixture's proof into this one
                let (_, other, _) = fixtures[rng.below(fixtures.len())];
                let nfields = proof.len() / 32;
                let f = rng.below(nfields);
                proof[f * 32..f * 32 + 32].copy_from_slice(&other[f * 32..f * 32 + 32]);
            }
        }

        let (a, b) = both(&proof, &pv);
        assert_eq!(
            a == 0,
            b == 0,
            "differential mismatch: ark={a} bn={b}\n proof={}\n pv={}",
            hex(&proof),
            hex(&pv)
        );
        if a == 0 {
            accepted += 1;
        }
        checked += 1;
    }
    eprintln!("fuzz: checked {checked} mutated inputs, {accepted} still verified on both");
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
