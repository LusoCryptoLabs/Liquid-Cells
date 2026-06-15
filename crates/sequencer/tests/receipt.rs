//! Soft-confirmation receipts: signing, verification, tamper-rejection, and binding to the
//! sequencer's live pool + committed seq. Receipts are liveness (a signed promise), not finality.

use liquid_cells_sequencer::{receipt, Sequencer};
use liquid_cells_stf::{keccak, sig, Deposit};

const SEQ_SECRET: [u8; 32] = [9u8; 32];

fn pool() -> Sequencer {
    Sequencer::genesis(keccak(b"receipt-pool"), 0x434b42)
}

#[test]
fn issue_and_verify_roundtrip() {
    let pool_id = keccak(b"p");
    let intent = keccak(b"transfer-msg-digest");
    let r = receipt::issue(&SEQ_SECRET, pool_id, intent, 3, 100);
    assert!(r.verify(), "a freshly issued receipt must verify");
    assert!(r.verify_from(&sig::pubkey(&SEQ_SECRET)), "and against the expected signer");
    assert_eq!(r.committed_seq, 3);
    assert_eq!(r.accepted_epoch, 100);
    assert_eq!(r.intent_msg, intent);
}

#[test]
fn wrong_signer_is_rejected() {
    let r = receipt::issue(&SEQ_SECRET, keccak(b"p"), keccak(b"i"), 1, 1);
    assert!(r.verify(), "self-consistent");
    assert!(!r.verify_from(&sig::pubkey(&[7u8; 32])), "but not from a different sequencer identity");
}

#[test]
fn tampering_any_field_breaks_verification() {
    let r = receipt::issue(&SEQ_SECRET, keccak(b"p"), keccak(b"i"), 5, 50);
    for tamper in 0..5 {
        let mut t = r;
        match tamper {
            0 => t.pool_id = keccak(b"other-pool"),
            1 => t.intent_msg = keccak(b"other-intent"),
            2 => t.committed_seq = 6,
            3 => t.accepted_epoch = 51,
            _ => t.sig[0] ^= 1,
        }
        assert!(!t.verify(), "tamper {tamper} must break the receipt");
    }
}

#[test]
fn sequencer_binds_live_pool_and_committed_seq() {
    let mut seq = pool();
    let intent = keccak(b"alice-transfer-digest");

    let r0 = seq.issue_receipt(&SEQ_SECRET, intent, 10);
    assert_eq!(r0.committed_seq, 0, "binds the current committed seq");
    assert_eq!(r0.pool_id, seq.pool().pool_id, "binds this pool");
    assert!(r0.verify_from(&sig::pubkey(&SEQ_SECRET)));

    // advance the chain: seal a deposit batch (deposits need no signature) => seq 0 -> 1
    seq.submit_deposit(Deposit { to_key: keccak(b"x"), amount: 1 });
    seq.seal_batch(10, 0).unwrap();
    assert_eq!(seq.seq(), 1);

    let r1 = seq.issue_receipt(&SEQ_SECRET, intent, 11);
    assert_eq!(r1.committed_seq, 1, "a later receipt binds the advanced seq");
    assert_ne!(r0, r1, "same intent at a different seq is a distinct receipt");
}
