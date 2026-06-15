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

// --- ecrecover (staged) ----------------------------------------------------------------------
// The staged `ecrecover` feature drops the 33-byte `from_pubkey` from each signed intent and
// recovers the signer's pubkey from the signature instead: the intent carries r||s||recovery_id
// (65 bytes) and the verifier recovers the pubkey, then derives the SMT key as keccak(pubkey).
// Net wire saving: (33 pubkey + 64 sig) -> 65 = 32 bytes per signed transfer/withdrawal/htlc_lock.
//
// Recovery requires the signed message to be INDEPENDENT of the pubkey (otherwise computing the
// digest to recover against needs the very key being recovered), so under `ecrecover` the `*_msg`
// digests must omit the sender key (it is re-derived from the recovered pubkey). That, plus the
// intent struct change, ripples through codec / touched_keys / apply / the client and every test
// fixture, so the integration is a coordinated re-bake-time change (docs/V2-REBAKE.md); these two
// primitives are the reusable crypto, staged + tested behind the feature so the deployed guest is
// untouched (vkey-neutral).

/// Recoverable RFC-6979 signature over `msg32`: `r(32) ‖ s(32) ‖ recovery_id(1)` (65 bytes). The
/// signer's pubkey is recoverable from this and the (pubkey-independent) message via [`recover`].
#[cfg(feature = "ecrecover")]
pub fn sign_recoverable(secret: &[u8; 32], msg32: &[u8; 32]) -> [u8; 65] {
    let sk = SigningKey::from_slice(secret).expect("valid 32-byte secret");
    // k256 returns a low-S signature with the matching recovery id, so no separate normalization.
    let (sig, recid) = sk.sign_prehash_recoverable(msg32).expect("sign");
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recid.to_byte();
    out
}

/// Recover the compressed signer pubkey from a 65-byte recoverable signature (`r‖s‖recovery_id`)
/// over `msg32`. `None` if the signature is malformed or recovery fails. A wrong message or a
/// tampered signature recovers a DIFFERENT key (never the signer's), so the caller authenticates by
/// deriving the SMT key from the result and looking up the funded account.
#[cfg(feature = "ecrecover")]
pub fn recover(msg32: &[u8; 32], sig65: &[u8; 65]) -> Option<[u8; 33]> {
    let sig = Signature::from_slice(&sig65[..64]).ok()?;
    let recid = k256::ecdsa::RecoveryId::from_byte(sig65[64])?;
    let vk = VerifyingKey::recover_from_prehash(msg32, &sig, recid).ok()?;
    let mut p = [0u8; 33];
    p.copy_from_slice(vk.to_encoded_point(true).as_bytes());
    Some(p)
}
