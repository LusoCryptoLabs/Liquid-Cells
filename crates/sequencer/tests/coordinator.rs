//! Anti-griefing leader election: deterministic, agreed by all, rotating, with ordered failover.

use liquid_cells_sequencer::coordinator::{leader, priority_order, rank, should_lead};
use liquid_cells_stf::{keccak, Hash};

fn id(n: u8) -> Hash {
    keccak(&[n])
}

#[test]
fn all_sequencers_agree_on_the_leader() {
    let active = vec![id(1), id(2), id(3), id(4), id(5)];
    let root = keccak(b"root-A");
    // Whatever order each sequencer holds the active set in, they compute the same leader.
    let l = leader(&active, &root).unwrap();
    let mut shuffled = active.clone();
    shuffled.reverse();
    assert_eq!(leader(&shuffled, &root).unwrap(), l, "leader is independent of local set order");

    // Exactly one sequencer considers itself the leader.
    let leaders: usize = active.iter().filter(|s| should_lead(s, &active, &root)).count();
    assert_eq!(leaders, 1, "exactly one leader per round");
    assert!(should_lead(&l, &active, &root));
}

#[test]
fn leadership_rotates_with_the_root() {
    let active = vec![id(1), id(2), id(3), id(4), id(5), id(6), id(7)];
    // Over many roots, leadership is not pinned to a single sequencer.
    let mut seen = std::collections::BTreeSet::new();
    for r in 0..32u8 {
        let root = keccak(&[0xaa, r]);
        seen.insert(leader(&active, &root).unwrap());
    }
    assert!(seen.len() > 1, "leadership must rotate across roots, not pin to one sequencer");
}

#[test]
fn ranks_are_a_total_order_and_failover_is_consistent() {
    let active = vec![id(10), id(20), id(30), id(40)];
    let root = keccak(b"root-B");
    let order = priority_order(&active, &root);
    assert_eq!(order.len(), active.len());
    // Every active sequencer has a unique rank, and the order matches priority_order.
    for (i, s) in order.iter().enumerate() {
        assert_eq!(rank(s, &active, &root), Some(i), "rank matches the agreed priority order");
    }
    // A non-member has no rank and never leads.
    let outsider = id(99);
    assert_eq!(rank(&outsider, &active, &root), None);
    assert!(!should_lead(&outsider, &active, &root));
}

#[test]
fn empty_set_has_no_leader() {
    assert_eq!(leader(&[], &keccak(b"x")), None);
}
