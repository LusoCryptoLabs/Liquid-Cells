//! Anchor sharding: K independent pools advance in parallel, value conserved per shard.
//!
//! Sharding is the throughput answer: the anchor type script already supports any number of
//! independent pools, so K shards run with zero contention and throughput scales with K. This
//! checks the off-chain wrapper: K shards seal independently, each is a well-formed checkpoint
//! chain, and value is conserved within every shard and in aggregate.

use liquid_cells_sequencer::{shard_pool_id, ShardedSequencer};
use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x0043_4b42;

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn key_for(n: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}
fn signed_transfer(shard_pool: &Hash, payer: u8, to: Hash, amount: u128, fee: u128, nonce: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, shard_pool, &from_key, &to, amount, fee, nonce, 1_000_000);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key: to, amount, fee, nonce, expiry: 1_000_000, sig }
}

#[test]
fn k_shards_advance_independently_and_conserve_value() {
    let base = keccak(b"sharded-pool");
    let k = 3usize;
    let mut sharded = ShardedSequencer::new(base, CHAIN_ID, k);
    assert_eq!(sharded.k(), k);

    // Distinct accounts; each is assigned a home shard, and we fund + spend within that shard.
    let mut expected_total = 0u128;
    for n in 1..=6u8 {
        let payer = key_for(n);
        let i = sharded.shard_of(&payer);
        let pool = shard_pool_id(&base, i);
        let recipient = key_for(100 + n);
        let s = sharded.shard_mut(i);
        s.submit_deposit(Deposit { to_key: payer, amount: 1_000_000 });
        // payer pays a recipient within the same shard, with a fee.
        s.submit_transfer(signed_transfer(&pool, n, recipient, 1000, 10, 0));
        expected_total += 1_000_000;
    }

    // Seal every shard that has work. Each is an independent checkpoint (genesis-pinned, seq 1).
    let jobs = sharded.seal_all(0, 0);
    assert!(!jobs.is_empty(), "shards with intents must seal");
    for (i, res) in &jobs {
        let job = res.as_ref().expect("each shard seals");
        assert_eq!(job.new_seq(), 1, "shard {i} advances to seq 1 independently");
    }

    // Value is conserved in aggregate across all shards.
    assert_eq!(sharded.total(), expected_total, "total across shards conserved");
    assert_eq!(sharded.pending(), 0, "all sealed");

    // And conserved within each shard: Σ balances + fee_acc == total.
    for i in 0..k {
        let s = sharded.shard(i);
        let balances: u128 = s.state().leaves.values().map(|l| l.balance).sum();
        assert_eq!(balances + s.fee_acc(), s.total(), "shard {i} conserves value");
    }
}

#[test]
fn shard_pool_ids_are_distinct() {
    let base = keccak(b"sharded-pool");
    let ids: Vec<Hash> = (0..4).map(|i| shard_pool_id(&base, i)).collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "each shard has an independent pool id");
        }
    }
}
