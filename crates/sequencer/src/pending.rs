//! Deposit confirmation-depth gate, closes the **deposit reorg → phantom balance** risk (M4).
//!
//! A deposit cell observed on L1 must not be folded into a checkpoint until it is buried under a
//! conservative number of confirmations. Otherwise a short reorg that removes the deposit tx (and
//! any checkpoint that swept it) would leave the sequencer's in-memory state crediting a deposit
//! that no longer exists on the canonical chain, a credit the next proof would carry forward while
//! the on-chain anchor reverted.
//!
//! [`PendingDeposits`] is the gate. It is **chain-agnostic**, it holds no RPC; the operator's L1
//! watcher supplies the block height each deposit cell was first seen at and the current tip, and on
//! a detected reorg tells it the canonical height to prune back to. Deposits only leave the gate (to
//! be handed to [`crate::Sequencer::submit_deposit`]) once they are `depth` blocks deep, by which
//! point a reorg removing them is negligibly likely; a reorg deeper than `depth` (catastrophic, far
//! beyond CKB's practical finality) is handled by the heavier resume-from-L1-DA path
//! ([`crate::Sequencer::resume`]), not by this gate.

use liquid_cells_stf::Deposit;

/// Identifier for a deposit cell on L1: its outpoint, `tx_hash(32) ‖ index(4 LE)`. Used so
/// re-observing the same cell across polls stages it only once.
pub type DepositId = [u8; 36];

#[derive(Clone, Debug)]
struct Staged {
    id: DepositId,
    height: u64,
    deposit: Deposit,
}

/// A confirmation-depth gate for deposits. See the module docs.
#[derive(Clone, Debug)]
pub struct PendingDeposits {
    depth: u64,
    pending: Vec<Staged>,
}

impl PendingDeposits {
    /// New gate requiring `depth` confirmations (`tip − first_seen_height ≥ depth`) before a
    /// deposit is eligible to seal. `depth = 0` accepts immediately (no gate).
    pub fn new(depth: u64) -> Self {
        Self { depth, pending: Vec::new() }
    }

    /// The confirmation depth this gate enforces.
    pub fn depth(&self) -> u64 {
        self.depth
    }

    /// Number of deposits currently staged (observed, not yet promoted).
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Stage a deposit cell first seen at L1 `height`. Idempotent by `id` (re-observing the same
    /// outpoint is a no-op). Returns `true` if it was newly staged.
    pub fn observe(&mut self, id: DepositId, height: u64, deposit: Deposit) -> bool {
        if self.pending.iter().any(|s| s.id == id) {
            return false;
        }
        self.pending.push(Staged { id, height, deposit });
        true
    }

    /// Remove and return the deposits that are now at least `depth` confirmations deep at `tip`,
    /// oldest-first (by observed height). These are safe to hand to `Sequencer::submit_deposit`.
    /// A deposit from a block *above* `tip` (can happen briefly mid-reorg) is never ready.
    pub fn take_ready(&mut self, tip: u64) -> Vec<Deposit> {
        let depth = self.depth;
        let ready: Vec<Deposit> = {
            let mut idx: Vec<usize> = (0..self.pending.len())
                .filter(|&i| tip >= self.pending[i].height && tip - self.pending[i].height >= depth)
                .collect();
            idx.sort_by_key(|&i| self.pending[i].height);
            idx.iter().map(|&i| self.pending[i].deposit).collect()
        };
        self.pending
            .retain(|s| !(tip >= s.height && tip - s.height >= depth));
        ready
    }

    /// On a detected reorg, drop any staged deposit whose block is **above** the new canonical
    /// height `canonical_height` (it may no longer be on the canonical chain). Returns the count
    /// dropped. Because the gate only promotes deposits ≥ `depth` deep, anything a reorg of less
    /// than `depth` removes is still here, un-promoted, and is cleanly dropped by this call.
    pub fn prune_above(&mut self, canonical_height: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|s| s.height <= canonical_height);
        before - self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(n: u8) -> Deposit {
        let mut k = [0u8; 32];
        k[31] = n;
        Deposit { to_key: k, amount: 1_000 * n as u128 }
    }
    fn id(n: u8) -> DepositId {
        let mut x = [0u8; 36];
        x[0] = n;
        x
    }

    #[test]
    fn gates_until_depth_confirmations() {
        let mut p = PendingDeposits::new(6);
        p.observe(id(1), 100, dep(1));
        p.observe(id(2), 101, dep(2));
        assert!(p.take_ready(105).is_empty(), "5 confirmations < depth 6");
        assert_eq!(p.take_ready(106), vec![dep(1)], "deposit@100 hits 6 confirmations at tip 106");
        assert_eq!(p.len(), 1, "deposit@101 still gated");
        assert_eq!(p.take_ready(107), vec![dep(2)]);
        assert!(p.is_empty());
    }

    #[test]
    fn observe_is_idempotent_by_outpoint() {
        let mut p = PendingDeposits::new(0);
        assert!(p.observe(id(1), 100, dep(1)));
        assert!(!p.observe(id(1), 100, dep(1)), "same outpoint staged once");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn promoted_deposits_are_not_returned_again() {
        let mut p = PendingDeposits::new(0);
        p.observe(id(1), 100, dep(1));
        assert_eq!(p.take_ready(100), vec![dep(1)]);
        assert!(p.take_ready(101).is_empty(), "already promoted");
    }

    #[test]
    fn reorg_prunes_orphaned_deposits_before_they_seal() {
        let mut p = PendingDeposits::new(6);
        p.observe(id(1), 100, dep(1));
        p.observe(id(2), 105, dep(2)); // in a block a reorg will orphan
        // reorg back to height 102: the deposit@105 is no longer canonical.
        assert_eq!(p.prune_above(102), 1);
        assert_eq!(p.len(), 1);
        // and it never sealed, because at the time it was only <6 deep.
        assert_eq!(p.take_ready(108), vec![dep(1)]);
    }

    #[test]
    fn ready_is_oldest_first() {
        let mut p = PendingDeposits::new(0);
        p.observe(id(3), 103, dep(3));
        p.observe(id(1), 101, dep(1));
        p.observe(id(2), 102, dep(2));
        assert_eq!(p.take_ready(200), vec![dep(1), dep(2), dep(3)]);
    }
}
