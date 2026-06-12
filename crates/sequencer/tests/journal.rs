//! The durability journal: a recovered sequencer is byte-identical to the original.
//!
//! These prove the property the demo and any production deployment rely on, a restart
//! does not lose the committed root *or* the unsealed mempool, and recovery is exact
//! (same leaves, same counters), because it re-runs the same deterministic STF commands.

use liquid_cells_sequencer::{DurableSequencer, FileJournal, MemJournal, Sequencer};
use liquid_cells_stf::*;
use std::collections::BTreeMap;

const CHAIN_ID: u64 = 0x0043_4b42;
fn pool_id() -> Hash {
    keccak(b"sp1-pool")
}
fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn key_for(n: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}
fn signed_transfer(payer: u8, to: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key: to, amount, fee, nonce, expiry, sig }
}
fn signed_withdrawal(payer: u8, target: Hash, amount: u128, nonce: u64, expiry: u64) -> Withdrawal {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash: target, amount, nonce, expiry, sig }
}

/// Fingerprint of the committed state plus the unsealed mempool size, what recovery must
/// reproduce exactly.
#[derive(PartialEq, Debug)]
struct Fingerprint {
    root: Hash,
    seq: u64,
    total: u128,
    fee_acc: u128,
    last_epoch: u64,
    pending: usize,
    leaves: BTreeMap<Hash, (u128, u64)>,
}
fn fingerprint(s: &Sequencer) -> Fingerprint {
    Fingerprint {
        root: s.root(),
        seq: s.seq(),
        total: s.total(),
        fee_acc: s.fee_acc(),
        last_epoch: s.last_epoch(),
        pending: s.pending(),
        leaves: s.state().leaves.iter().map(|(k, l)| (*k, (l.balance, l.nonce))).collect(),
    }
}

/// Drive a representative mixed workload (deposits, fee'd transfers, a withdrawal, several
/// sealed checkpoints) and leave a couple of intents unsealed in the mempool.
fn run_workload<J: liquid_cells_sequencer::Journal>(ds: &mut DurableSequencer<J>) {
    let (alice, bob, carol) = (key_for(1), key_for(2), key_for(3));

    // cp1: fund Alice, she pays Bob with a fee, sequencer draws the fee for the L1 miner fee.
    ds.submit_deposit(Deposit { to_key: alice, amount: 10_000_000_000 }).unwrap();
    ds.submit_transfer(signed_transfer(1, bob, 1_000, 100_000, 0, 1_000_000)).unwrap();
    ds.seal_batch(0, 100_000).unwrap();

    // cp2: Bob pays Carol with a fee.
    ds.submit_transfer(signed_transfer(2, carol, 400, 100, 0, 1_000_000)).unwrap();
    ds.seal_batch(1, 100).unwrap();

    // cp3: Carol transfers and withdraws in one batch.
    ds.submit_transfer(signed_transfer(3, alice, 50, 50, 0, 1_000_000)).unwrap();
    ds.submit_withdrawal(signed_withdrawal(3, keccak(b"l1-target"), 200, 1, 1_000_000)).unwrap();
    ds.seal_batch(2, 50).unwrap();

    // two more intents submitted but NOT yet sealed (the crash window).
    ds.submit_transfer(signed_transfer(1, bob, 25, 0, 1, 1_000_000)).unwrap();
    ds.submit_deposit(Deposit { to_key: carol, amount: 7_000 }).unwrap();
}

#[test]
fn recovered_sequencer_is_byte_identical() {
    let mut original = DurableSequencer::genesis(pool_id(), CHAIN_ID, MemJournal::new());
    run_workload(&mut original);
    let before = fingerprint(original.inner());
    assert_eq!(before.seq, 3, "three checkpoints sealed");
    assert_eq!(before.pending, 2, "two intents left unsealed");

    // Recover from the very journal the live run wrote.
    let log = original.journal().clone();
    let recovered = DurableSequencer::recover(pool_id(), CHAIN_ID, log).expect("recover");
    let after = fingerprint(recovered.inner());

    assert_eq!(before, after, "recovered state and mempool must match the original exactly");
}

#[test]
fn sealing_after_recovery_continues_the_chain() {
    // Recovery is not just a snapshot read: the resumed sequencer can seal the recovered
    // mempool into a checkpoint that chains correctly onto the last committed anchor.
    let mut original = DurableSequencer::genesis(pool_id(), CHAIN_ID, MemJournal::new());
    run_workload(&mut original);
    let last_anchor = original.inner().anchor();

    let mut recovered =
        DurableSequencer::recover(pool_id(), CHAIN_ID, original.journal().clone()).unwrap();
    let job = recovered.seal_batch(3, 0).expect("seal the recovered mempool");

    assert_eq!(job.prev_anchor, last_anchor, "the post-recovery seal consumes the last anchor");
    assert_eq!(job.new_seq(), 4, "seq continues from where it left off");
    assert_eq!(recovered.inner().pending(), 0, "the recovered mempool drained");
}

#[test]
fn file_journal_survives_a_restart() {
    let path = std::env::temp_dir().join(format!("lc-journal-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // First process: run the workload against a file-backed journal, then drop it (== exit).
    let before = {
        let mut ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
        run_workload(&mut ds);
        fingerprint(ds.inner())
    };

    // Second process: reopen the same path, which replays the journal on the way up.
    let after = {
        let ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
        fingerprint(ds.inner())
    };
    assert_eq!(before, after, "a file-backed sequencer resumes exactly after a restart");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn torn_trailing_frame_is_tolerated() {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!("lc-journal-torn-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let before = {
        let mut ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
        run_workload(&mut ds);
        fingerprint(ds.inner())
    };

    // Simulate a power loss mid-append: garbage half-frame tacked onto the end.
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0x01, 0x00, 0x00, 0x10, 0xde, 0xad]).unwrap(); // tag + len=16 but only 2 body bytes
    }

    // Recovery drops the torn frame and reproduces the last intact state.
    let after = {
        let ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
        fingerprint(ds.inner())
    };
    assert_eq!(before, after, "a torn trailing frame must not corrupt recovery");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn unsealed_intents_survive_a_crash_without_a_seal() {
    // A crash before any seal must still recover the queued intents (they were write-ahead
    // logged on submit), so nothing a client handed the sequencer is silently dropped.
    let path = std::env::temp_dir().join(format!("lc-journal-nosseal-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);

    {
        let mut ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
        ds.submit_deposit(Deposit { to_key: key_for(1), amount: 5_000_000_000 }).unwrap();
        ds.submit_deposit(Deposit { to_key: key_for(2), amount: 3_000_000_000 }).unwrap();
        // no seal: process "crashes" here
        assert_eq!(ds.inner().pending(), 2);
    }

    let ds = DurableSequencer::open(pool_id(), CHAIN_ID, &path).unwrap();
    assert_eq!(ds.inner().pending(), 2, "queued-but-unsealed intents are recovered");
    assert_eq!(ds.inner().seq(), 0, "no checkpoint was committed");

    let _ = std::fs::remove_file(&path);
}
