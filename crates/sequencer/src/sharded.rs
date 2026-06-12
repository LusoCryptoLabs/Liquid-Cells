//! Anchor sharding (Phase 6b): K independent pools, advanced in parallel.
//!
//! A single pool has one anchor cell, so one checkpoint stream and a throughput ceiling. The
//! anchor type script already supports any number of independent pools (each its own anchor and
//! checkpoint chain), so the throughput fix needs no contract change: run K pools, and K
//! sequencers advance them with zero contention. Throughput scales with K.
//!
//! There is no cross-shard atomicity to get wrong. A user is simply present in whatever shard(s)
//! they have transacted in: paying someone is a transfer within one shard that credits their
//! leaf there, and a user's total balance is the sum of their leaves across shards (the client
//! aggregates). Moving liquidity between shards uses the same trustless exits as moving it
//! anywhere else (force-exit or an atomic swap), so it is not a new mechanism.

use crate::{CheckpointJob, Sequencer};
use liquid_cells_stf::{keccak, Hash, StfError};

/// Deterministic per-shard pool id: `keccak("LIQUIDCELLS/v1/shard" ‖ base ‖ index)`. Distinct per
/// shard, so each shard is a fully independent pool with its own signing domain.
pub fn shard_pool_id(base: &Hash, index: usize) -> Hash {
    let mut b = Vec::with_capacity(20 + 32 + 8);
    b.extend_from_slice(b"LIQUIDCELLS/v1/shard");
    b.extend_from_slice(base);
    b.extend_from_slice(&(index as u64).to_be_bytes());
    keccak(&b)
}

/// K independent Liquid Cells pools (shards). Each shard is a full [`Sequencer`]; they share
/// nothing and advance in parallel, so the single-anchor bottleneck of one pool is gone.
pub struct ShardedSequencer {
    shards: Vec<Sequencer>,
}

impl ShardedSequencer {
    /// Create `k` shards with deterministic, independent pool ids derived from `base_pool_id`.
    pub fn new(base_pool_id: Hash, chain_id: u64, k: usize) -> Self {
        let shards = (0..k)
            .map(|i| Sequencer::genesis(shard_pool_id(&base_pool_id, i), chain_id))
            .collect();
        Self { shards }
    }

    /// Number of shards.
    pub fn k(&self) -> usize {
        self.shards.len()
    }

    pub fn shard(&self, i: usize) -> &Sequencer {
        &self.shards[i]
    }
    pub fn shard_mut(&mut self, i: usize) -> &mut Sequencer {
        &mut self.shards[i]
    }

    /// The home shard a key is assigned to (deterministic: high 8 bytes of the key mod K). A hint
    /// for routing deposits; a user may still hold leaves in other shards they have received in.
    pub fn shard_of(&self, key: &Hash) -> usize {
        let hi = u64::from_be_bytes(key[..8].try_into().unwrap());
        (hi % self.shards.len() as u64) as usize
    }

    /// Seal every shard that has pending intents, returning `(shard_index, result)` for each.
    /// The shards are independent, so a real deployment proves and submits these concurrently.
    pub fn seal_all(
        &mut self,
        current_epoch: u64,
        fee_withdrawal: u128,
    ) -> Vec<(usize, Result<CheckpointJob, StfError>)> {
        self.shards
            .iter_mut()
            .enumerate()
            .filter(|(_, s)| s.pending() > 0)
            .map(|(i, s)| (i, s.seal_batch(current_epoch, fee_withdrawal)))
            .collect()
    }

    /// Total value across all shards.
    pub fn total(&self) -> u128 {
        self.shards.iter().map(|s| s.total()).sum()
    }

    /// Total pending intents across all shards.
    pub fn pending(&self) -> usize {
        self.shards.iter().map(|s| s.pending()).sum()
    }
}
