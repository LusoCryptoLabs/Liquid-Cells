//! # liquid-cells-sequencer
//!
//! The off-chain half of the keystone. The sequencer runs the *exact*
//! [`liquid_cells_stf`] state-transition function the SP1 guest proves, accepts signed
//! intents into a mempool, and **seals successive checkpoints**, each building on the
//! last committed root. It produces a [`CheckpointJob`] per checkpoint: everything a
//! prover + CKB submission driver needs (the SP1 guest input, the anchor cell bytes for
//! both states, the DA blob, and the deposit/withdrawal cell specs), with the in-memory
//! root advanced so the next seal chains onto it.
//!
//! It carries **no proving dependency** on purpose. Proving a [`CheckpointJob::sp1_input`]
//! to a Groth16 proof, and building/sending the checkpoint transaction, are a separate
//! (heavy) driver; this crate is the deterministic loop, and its succession property is
//! tested in milliseconds.
//!
//! The trust model is unchanged by anything here: the sequencer only *orders*, it cannot
//! steal, inflate, censor permanently, or withhold data, because the on-chain anchor type
//! script re-derives and checks every fact this crate emits.
//!
//! ```no_run
//! # use liquid_cells_sequencer::Sequencer;
//! # use liquid_cells_stf::{keccak, Deposit};
//! let mut seq = Sequencer::genesis(keccak(b"sp1-pool"), 0x434b42);
//! seq.submit_deposit(Deposit { to_key: keccak(b"alice"), amount: 10_000_000_000 });
//! let job = seq.seal_batch(0, 0).unwrap(); // current_epoch = 0, fee_withdrawal = 0
//! // prove job.sp1_input -> Groth16, then submit a checkpoint tx pinning job.new_anchor.
//! ```

use liquid_cells_stf::da::da_commitment;
use liquid_cells_stf::{
    apply, codec, Batch, Deposit, Hash, HtlcClaim, HtlcLock, HtlcRefund, PoolState, PublicValues,
    State, StfError, Transfer, Withdrawal,
};

/// Anchor cell data length (bytes): `root(32) ‖ seq(8) ‖ total(16) ‖ fee_acc(16) ‖ last_epoch(8)`.
/// Byte-identical to the on-chain `ANCHOR_LEN` in the anchor type script.
pub const ANCHOR_LEN: usize = 80;

/// Encode an anchor cell's data from a pool state and the epoch the last checkpoint recorded.
/// Layout matches the contract exactly (offsets root=0, seq=32, total=40, fee_acc=56,
/// last_epoch=72), so `prev_anchor`/`new_anchor` are the literal bytes the checkpoint tx
/// consumes and creates.
pub fn encode_anchor(pool: &PoolState, last_epoch: u64) -> [u8; ANCHOR_LEN] {
    let mut a = [0u8; ANCHOR_LEN];
    a[0..32].copy_from_slice(&pool.root);
    a[32..40].copy_from_slice(&pool.seq.to_be_bytes());
    a[40..56].copy_from_slice(&pool.total.to_be_bytes());
    a[56..72].copy_from_slice(&pool.fee_acc.to_be_bytes());
    a[72..80].copy_from_slice(&last_epoch.to_be_bytes());
    a
}

/// Everything a prover + CKB submission driver needs to turn one sealed batch into an
/// on-chain checkpoint, and everything the next checkpoint chains onto.
#[derive(Clone, Debug)]
pub struct CheckpointJob {
    /// The input anchor cell's data (state *n*). Equals the previous job's `new_anchor`
    /// (or, for the first checkpoint, the genesis anchor).
    pub prev_anchor: [u8; ANCHOR_LEN],
    /// The output anchor cell's data (state *n+1*) the checkpoint tx must create.
    pub new_anchor: [u8; ANCHOR_LEN],
    /// The SP1 guest input bundle `(prev, witness, batch)`, feed straight to the prover.
    pub sp1_input: Vec<u8>,
    /// The public values the guest commits (and the anchor type script pins). `keccak`-bound
    /// to `da_blob` and consistent with `prev_anchor`/`new_anchor`.
    pub public_values: PublicValues,
    /// The data-availability blob to publish in the checkpoint tx's anchor witness
    /// `output_type`. `keccak(da_blob) == public_values.da_commitment`.
    pub da_blob: Vec<u8>,
    /// Deposits credited this checkpoint, the driver builds one input cell per entry
    /// (data = `to_key`, capacity = `amount`).
    pub deposits: Vec<Deposit>,
    /// Withdrawals paid this checkpoint as `(target_lock_hash, amount)`, the driver builds
    /// one output cell per entry (that lock, capacity = amount).
    pub withdrawals: Vec<(Hash, u128)>,
    /// CKB drawn from accumulated fees to fund the L1 miner fee (the tx's miner fee must
    /// equal this; the anchor solvency check pins it).
    pub fee_withdrawal: u128,
    /// The epoch this checkpoint records into `new_anchor.last_epoch` (the force-exit clock).
    pub current_epoch: u64,
}

impl CheckpointJob {
    /// The new committed root (state *n+1*).
    pub fn new_root(&self) -> Hash {
        self.public_values.new_root
    }
    /// The new sequence number.
    pub fn new_seq(&self) -> u64 {
        self.public_values.new_seq
    }
}

/// Intents waiting to be sealed into the next checkpoint. Drained on a successful
/// [`Sequencer::seal_batch`]; left intact if the seal fails (so a bad intent can be removed
/// and the batch retried).
#[derive(Default, Clone, Debug)]
struct Mempool {
    deposits: Vec<Deposit>,
    transfers: Vec<Transfer>,
    htlc_locks: Vec<HtlcLock>,
    htlc_claims: Vec<HtlcClaim>,
    htlc_refunds: Vec<HtlcRefund>,
    withdrawals: Vec<Withdrawal>,
}

impl Mempool {
    fn len(&self) -> usize {
        self.deposits.len()
            + self.transfers.len()
            + self.htlc_locks.len()
            + self.htlc_claims.len()
            + self.htlc_refunds.len()
            + self.withdrawals.len()
    }
    fn into_batch(self, current_epoch: u64, fee_withdrawal: u128) -> Batch {
        Batch {
            current_epoch,
            deposits: self.deposits,
            transfers: self.transfers,
            htlc_locks: self.htlc_locks,
            htlc_claims: self.htlc_claims,
            htlc_refunds: self.htlc_refunds,
            withdrawals: self.withdrawals,
            fee_withdrawal,
        }
    }
}

/// A running Liquid Cells sequencer: an in-memory pool [`State`], a mempool of pending
/// signed intents, and the epoch the last checkpoint recorded. Seal batches off it to get a
/// chain of [`CheckpointJob`]s.
pub struct Sequencer {
    state: State,
    mempool: Mempool,
    last_epoch: u64,
}

impl Sequencer {
    /// A fresh sequencer over an empty pool. Its first checkpoint's `prev_anchor` equals the
    /// canonical genesis anchor (empty root, all counters zero).
    pub fn genesis(pool_id: Hash, chain_id: u64) -> Self {
        Self { state: State::genesis(pool_id, chain_id), mempool: Mempool::default(), last_epoch: 0 }
    }

    /// Resume a sequencer from an already-advanced state (e.g. rebuilt from L1 DA) and the
    /// epoch its latest checkpoint recorded.
    pub fn resume(state: State, last_epoch: u64) -> Self {
        Self { state, mempool: Mempool::default(), last_epoch }
    }

    // --- mempool: clients submit already-signed intents (the sequencer can't forge them) ---

    pub fn submit_deposit(&mut self, d: Deposit) {
        self.mempool.deposits.push(d);
    }
    pub fn submit_transfer(&mut self, t: Transfer) {
        self.mempool.transfers.push(t);
    }
    pub fn submit_htlc_lock(&mut self, l: HtlcLock) {
        self.mempool.htlc_locks.push(l);
    }
    pub fn submit_htlc_claim(&mut self, c: HtlcClaim) {
        self.mempool.htlc_claims.push(c);
    }
    pub fn submit_htlc_refund(&mut self, r: HtlcRefund) {
        self.mempool.htlc_refunds.push(r);
    }
    pub fn submit_withdrawal(&mut self, w: Withdrawal) {
        self.mempool.withdrawals.push(w);
    }

    /// Number of pending intents not yet sealed.
    pub fn pending(&self) -> usize {
        self.mempool.len()
    }

    // --- read-only views of the committed state ---

    pub fn pool(&self) -> &PoolState {
        &self.state.pool
    }
    pub fn root(&self) -> Hash {
        self.state.pool.root
    }
    pub fn seq(&self) -> u64 {
        self.state.pool.seq
    }
    pub fn total(&self) -> u128 {
        self.state.pool.total
    }
    pub fn fee_acc(&self) -> u128 {
        self.state.pool.fee_acc
    }
    pub fn last_epoch(&self) -> u64 {
        self.last_epoch
    }
    /// The committed full state (for building extra witnesses, e.g. a force-exit proof).
    pub fn state(&self) -> &State {
        &self.state
    }
    /// The anchor cell data for the *current* committed state, the cell a checkpoint or
    /// force-exit consumes.
    pub fn anchor(&self) -> [u8; ANCHOR_LEN] {
        encode_anchor(&self.state.pool, self.last_epoch)
    }

    /// Seal the mempool into one checkpoint. Builds the SP1 guest input and the anchor bytes
    /// from the state *before* applying, applies the batch to advance the in-memory root,
    /// records `current_epoch` as the new `last_epoch`, and returns the [`CheckpointJob`].
    ///
    /// Atomic: if the batch is invalid (`StfError`), the state and mempool are left unchanged
    /// so the offending intent can be dropped and the batch retried. `fee_withdrawal` must be
    /// ≤ the pool's accumulated fee revenue (`fee_acc` + this batch's fee_delta) or apply
    /// rejects with [`StfError::InsufficientFees`].
    pub fn seal_batch(
        &mut self,
        current_epoch: u64,
        fee_withdrawal: u128,
    ) -> Result<CheckpointJob, StfError> {
        let batch = self.mempool.clone().into_batch(current_epoch, fee_withdrawal);

        // Snapshot the pre-state: this is exactly what the guest proves against.
        let prev_pool = self.state.pool;
        let prev_anchor = encode_anchor(&prev_pool, self.last_epoch);
        let witness = self.state.build_witness(&batch);
        let sp1_input = codec::encode_input(&prev_pool, &witness, &batch);

        // Advance the committed root. On error, `apply` does NOT mutate state (it returns
        // before folding), so we leave the mempool intact and surface the error.
        let public_values = apply(&mut self.state, &batch)?;

        // Commit: record the epoch and the post-state DA blob, then clear the mempool.
        self.last_epoch = current_epoch;
        let new_anchor = encode_anchor(&self.state.pool, self.last_epoch);
        let da_blob = self.state.da_blob(&batch);
        debug_assert_eq!(
            da_commitment(&da_blob),
            public_values.da_commitment,
            "DA blob must match the proven da_commitment"
        );

        let deposits = batch.deposits.clone();
        let withdrawals =
            batch.withdrawals.iter().map(|w| (w.target_lock_hash, w.amount)).collect();
        self.mempool = Mempool::default();

        Ok(CheckpointJob {
            prev_anchor,
            new_anchor,
            sp1_input,
            public_values,
            da_blob,
            deposits,
            withdrawals,
            fee_withdrawal,
            current_epoch,
        })
    }
}

/// Re-export so a driver can reconstruct/verify a checkpoint chain's DA without depending on
/// `liquid_cells_stf` directly.
pub use liquid_cells_stf::reconstruct;

/// Convenience: the keccak of a checkpoint chain's published DA blobs, oldest-first, must
/// rebuild a tree whose root equals the latest checkpoint's `new_root`. This is the property
/// a unilateral exiter relies on; exposed here so a driver can assert it after submission.
pub fn chain_reconstructs_to(blobs: &[Vec<u8>], expected_root: Hash) -> bool {
    match reconstruct(blobs) {
        Some(smt) => smt.root() == expected_root,
        None => false,
    }
}
