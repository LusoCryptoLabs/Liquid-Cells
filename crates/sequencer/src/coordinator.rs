//! Anti-griefing: deterministic off-chain leader election (Phase 6b).
//!
//! With a permissive anchor lock anyone may checkpoint, so two sequencers racing from the same
//! root both burn a slow proof and the loser wastes it. This is an EFFICIENCY problem, not a
//! trust one: the system is already safe (force-exit) and economically rational (the sequencer
//! reward), so the worst case of racing is a wasted proof, never loss. This coordinator removes
//! the waste in the common case with no on-chain mechanism.
//!
//! For each new root, every sequencer computes the SAME deterministic priority order over the
//! known active set (`keccak(id ‖ root)`, lowest wins), so only the leader (rank 0) proves and
//! submits. If the leader does not land a checkpoint within a timeout, the next-ranked sequencer
//! takes over, and so on, so liveness does not depend on any single sequencer. Because the order
//! is keyed by the root, leadership rotates fairly and unpredictably.
//!
//! Sequencers learn the active set by gossip (off-chain infrastructure, out of scope here); given
//! that set the selection is pure and stateless. Relying on cooperation is acceptable precisely
//! because this is not a trust boundary: a sequencer that ignores the schedule and races anyway
//! cannot steal or forge, it only risks wasting its own proof. The maximally-trustless
//! alternative, an on-chain commit-reveal leader, is deferred as over-engineering for a non-trust
//! concern (it would need an anchor-layout change, backward-compat for the live pools, and a
//! re-deploy, to solve a problem that is purely about wasted work).

use liquid_cells_stf::{keccak, Hash};

/// A sequencer's priority value for a round: `keccak(id ‖ root)`. Lower wins.
fn priority(id: &Hash, root: &Hash) -> Hash {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(id);
    b[32..].copy_from_slice(root);
    keccak(&b)
}

/// The active sequencers in priority order for `root` (index 0 = the leader who should prove
/// first; the rest are failovers in order). Deterministic, so every sequencer computes the same
/// order from the same active set.
pub fn priority_order(active: &[Hash], root: &Hash) -> Vec<Hash> {
    let mut v: Vec<Hash> = active.to_vec();
    v.sort_by(|a, b| priority(a, root).cmp(&priority(b, root)));
    v
}

/// This sequencer's rank for `root` (0 = leader). `None` if `my_id` is not in the active set.
pub fn rank(my_id: &Hash, active: &[Hash], root: &Hash) -> Option<usize> {
    priority_order(active, root).iter().position(|id| id == my_id)
}

/// Should this sequencer prove and submit the next checkpoint right now? True only for the leader
/// (rank 0). A failover sequencer waits `rank * timeout` and re-checks whether the root has
/// already advanced before stepping in.
pub fn should_lead(my_id: &Hash, active: &[Hash], root: &Hash) -> bool {
    rank(my_id, active, root) == Some(0)
}

/// The leader for `root`, or `None` if the active set is empty.
pub fn leader(active: &[Hash], root: &Hash) -> Option<Hash> {
    priority_order(active, root).into_iter().next()
}
