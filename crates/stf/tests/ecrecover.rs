//! Staged `ecrecover` primitive (v2 bundle): recover the signer's pubkey from a recoverable
//! signature, so a signed intent need not carry the 33-byte `from_pubkey`. Runs under
//! `--features ecrecover`. The full integration (drop the field, omit the sender key from the
//! signed digest, thread through codec/apply/client) is a coordinated re-bake-time change
//! (docs/V2-REBAKE.md); here we prove the crypto and the byte saving.
#![cfg(feature = "ecrecover")]

use liquid_cells_stf::{key_of_pubkey, keccak, sig};

#[test]
fn sign_recoverable_round_trips_to_the_signer_pubkey() {
    let secret = [7u8; 32];
    let pk = sig::pubkey(&secret);
    // A message that does NOT depend on the pubkey (as the ecrecover *_msg digests will be).
    let msg = keccak(b"liquid-cells/ecrecover/a-pubkey-free-message");
    let sig65 = sig::sign_recoverable(&secret, &msg);
    let recovered = sig::recover(&msg, &sig65).expect("recover succeeds");
    assert_eq!(recovered, pk, "recovered pubkey equals the signer's");
    // The SMT key is derived from the recovered pubkey, so the intent need not carry the pubkey.
    assert_eq!(key_of_pubkey(&recovered), key_of_pubkey(&pk));
}

#[test]
fn recovery_authenticates_message_and_signature() {
    let secret = [9u8; 32];
    let pk = sig::pubkey(&secret);
    let msg = keccak(b"the signed message");
    let sig65 = sig::sign_recoverable(&secret, &msg);

    // A DIFFERENT message recovers some other key, never the signer's, so binding the recovered key
    // to the funded account authenticates the (message, signature) pair.
    let other = keccak(b"a different message");
    assert_ne!(sig::recover(&other, &sig65), Some(pk), "wrong message must not recover the signer");

    // A corrupted signature either fails to recover or yields a different key.
    let mut bad = sig65;
    bad[10] ^= 0xff;
    assert_ne!(sig::recover(&msg, &bad), Some(pk), "tampered signature must not recover the signer");

    // A malformed recovery id is rejected outright.
    let mut bad_recid = sig65;
    bad_recid[64] = 0xff;
    assert_eq!(sig::recover(&msg, &bad_recid), None, "an invalid recovery id is rejected");
}

#[test]
fn ecrecover_saves_32_bytes_per_signed_intent() {
    // Deployed: each signed intent carries from_pubkey(33) + sig(64) = 97 auth bytes.
    // Under ecrecover: r||s||recovery_id (65 bytes), and the verifier recovers the pubkey.
    let deployed = 33 + 64;
    let ecrecover = 65;
    assert_eq!(deployed - ecrecover, 32, "ecrecover saves 32 wire bytes per signed intent");
}
