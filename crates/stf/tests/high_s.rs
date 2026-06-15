//! Validates the staged `reject_high_s` fix for THREAT-MODEL L3 (ECDSA signature-bytes
//! malleability). Runs under `--features reject_high_s`.
//!
//! For a valid low-S signature `(r, s)`, the malleated `(r, n - s)` is the *other* valid
//! encoding of the same signature over the same message. The deployed `sig::verify`
//! normalizes and accepts both; with `reject_high_s` only the canonical low-S form verifies.
#![cfg(feature = "reject_high_s")]

use liquid_cells_stf::{keccak, sig};

/// secp256k1 group order n (big-endian).
const N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `a - b` for 32-byte big-endian integers (caller guarantees `a >= b`).
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let mut diff = a[i] as i32 - b[i] as i32 - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = diff as u8;
    }
    out
}

/// The malleated (high-S) encoding of a low-S compact signature: keep `r`, replace `s` with
/// `n - s`. For a low-S input (`s < n/2`) this yields a distinct high-S signature valid over
/// the same message.
fn high_s_variant(sig64: &[u8; 64]) -> [u8; 64] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig64[32..]);
    let ns = sub_be(&N, &s);
    let mut out = *sig64;
    out[32..].copy_from_slice(&ns);
    out
}

#[test]
fn low_s_accepted_high_s_rejected() {
    for seed in 1u8..16 {
        let secret = [seed; 32];
        let pk = sig::pubkey(&secret);
        let msg = keccak(&[seed, 0xab, 0xcd, seed ^ 0x5a]);
        let (pk2, low) = sig::sign(&secret, &msg);
        assert_eq!(pk, pk2);

        // The canonical (low-S, as `sign` emits) signature still verifies.
        assert!(sig::verify(&pk, &msg, &low), "seed {seed}: canonical low-S must verify");

        // Its malleated high-S twin is a *distinct* 64-byte encoding...
        let high = high_s_variant(&low);
        assert_ne!(&high[32..], &low[32..], "seed {seed}: high-S must differ from low-S");
        // ...and under `reject_high_s` it is rejected (the deployed verifier would accept it).
        assert!(
            !sig::verify(&pk, &msg, &high),
            "seed {seed}: high-S (malleated) signature must be rejected"
        );
    }
}

#[test]
fn round_trip_of_a_low_s_through_high_then_back_is_identity() {
    // n - (n - s) = s, so the construction is the genuine malleation, not noise.
    let (_, low) = sig::sign(&[3u8; 32], &keccak(b"x"));
    let back = high_s_variant(&high_s_variant(&low));
    assert_eq!(back, low);
}
