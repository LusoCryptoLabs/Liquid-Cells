//! secp256k1 ECDSA over a pre-hashed (keccak) message.
//!
//! Native here; in the SP1 guest the `k256` crate is patched to the zkVM's
//! secp256k1 precompile, so the identical call is cheap to prove. Signatures are
//! normalized to low-S to remove malleability.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// Verify a 64-byte compact signature over `msg32` for the compressed `pubkey33`.
pub fn verify(pubkey33: &[u8; 33], msg32: &[u8; 32], sig64: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_sec1_bytes(pubkey33) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(sig64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Deployed behaviour: normalize a high-S signature to low-S and verify, so BOTH encodings
    // pass (the documented THREAT-MODEL L3 signature-bytes malleability: harmless because every
    // effect is keyed by the signed message + leaf nonce and the signature is never committed
    // on-chain). The staged `reject_high_s` feature rejects high-S outright so only the
    // canonical low-S encoding verifies; it changes the guest ELF, so it is OFF in the deployed
    // guest (vkey 0x00213af5… unchanged) and the `#[cfg]` below keeps the off path byte-identical.
    #[cfg(feature = "reject_high_s")]
    if sig.normalize_s().is_some() {
        return false; // `normalize_s` returns Some iff the input was high-S => reject it
    }
    #[cfg(not(feature = "reject_high_s"))]
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify_prehash(msg32, &sig).is_ok()
}

/// Compressed secp256k1 pubkey for a secret. Clients derive their SMT key as
/// `key_of_pubkey(&pubkey(secret))`.
pub fn pubkey(secret: &[u8; 32]) -> [u8; 33] {
    let sk = SigningKey::from_slice(secret).expect("valid 32-byte secret");
    let mut pub33 = [0u8; 33];
    pub33.copy_from_slice(sk.verifying_key().to_encoded_point(true).as_bytes());
    pub33
}

/// Deterministic (RFC-6979) signing helper. Used by clients/tests to produce
/// intents; returns the compressed pubkey and a low-S compact signature.
pub fn sign(secret: &[u8; 32], msg32: &[u8; 32]) -> ([u8; 33], [u8; 64]) {
    let sk = SigningKey::from_slice(secret).expect("valid 32-byte secret");
    let vk = sk.verifying_key();
    let mut pub33 = [0u8; 33];
    pub33.copy_from_slice(vk.to_encoded_point(true).as_bytes());
    let sig: Signature = sk.sign_prehash(msg32).expect("sign");
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut s = [0u8; 64];
    s.copy_from_slice(&sig.to_bytes());
    (pub33, s)
}
