//! DA snapshotting: a full-state snapshot + the tail checkpoints reconstructs the same state as
//! replaying all history (O(snapshot+tail) recovery), and a snapshot not matching the trusted
//! on-chain root is rejected. Keeps force-exit reconstruction cheap as a pool ages.
use liquid_cells_client::{reconstruct_from_snapshot, reconstruct_tree, Account};
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::*;

const CHAIN: u64 = 0x434b_42;
fn pool() -> Hash {
    keccak(b"snapshot-pool")
}
fn key(n: u8) -> Hash {
    let mut s = [0u8; 32];
    s[31] = n;
    key_of_pubkey(&sig::pubkey(&s))
}

#[test]
fn snapshot_plus_tail_equals_full_history_and_rejects_tampering() {
    let mut op = Sequencer::genesis(pool(), CHAIN);
    let mut a1 = Account::new(pool(), CHAIN, { let mut s = [0u8; 32]; s[31] = 1; s });
    let mut all = Vec::new();

    // cp1: deposits; cp2: a transfer
    op.submit_deposit(Deposit { to_key: key(1), amount: 1_000_000_000_000 });
    op.submit_deposit(Deposit { to_key: key(2), amount: 500_000_000_000 });
    all.push(op.seal_batch(0, 0).unwrap().da_blob);
    op.submit_transfer(a1.transfer(key(3), 1000, 0, 1_000_000));
    all.push(op.seal_batch(0, 0).unwrap().da_blob);

    // --- SNAPSHOT at this seq ---
    let snap = op.snapshot_blob();
    let snap_root = op.root();

    // tail: two more checkpoints
    op.submit_transfer(a1.transfer(key(4), 2000, 0, 1_000_000));
    let tail1 = op.seal_batch(0, 0).unwrap().da_blob;
    op.submit_deposit(Deposit { to_key: key(5), amount: 300_000_000_000 });
    let tail2 = op.seal_batch(0, 0).unwrap().da_blob;
    let tail = vec![tail1.clone(), tail2.clone()];
    all.push(tail1);
    all.push(tail2);

    // full-history reconstruct == current on-chain root
    assert_eq!(reconstruct_tree(&all).unwrap().root(), op.root());
    // snapshot + tail reconstructs the SAME current state (bounded by tail, not all history)
    let restored = reconstruct_from_snapshot(&snap, &snap_root, &tail).unwrap();
    assert_eq!(restored.root(), op.root(), "snapshot + tail == current state");
    // a snapshot not matching the trusted anchor root is rejected
    let mut bad = snap_root;
    bad[0] ^= 1;
    assert!(reconstruct_from_snapshot(&snap, &bad, &tail).is_none(), "untrusted-root snapshot rejected");
}
