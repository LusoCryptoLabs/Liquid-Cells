//! Dust-egress swap coordinator: the state machine drives a full atomic swap against a mocked
//! counterparty (Fiber) leg, and refuses to lose funds on every adversarial branch. No Fiber node
//! is involved. One end-to-end test (under `htlc_sha256`) settles the pool legs through the real STF.

use liquid_cells_client::swap::{
    decide, swap_hashlock, Action, CounterpartyLeg, LegState, MockLeg, Role, SwapTerms,
};
use liquid_cells_stf::{keccak, Hash};

const SECRET: &[u8] = b"dust-egress-secret";

fn pool_id() -> Hash {
    keccak(b"swap-pool")
}

fn terms() -> SwapTerms {
    SwapTerms {
        pool_id: pool_id(),
        maker_key: keccak(b"maker"),
        taker_key: keccak(b"taker"),
        dust: 5_000_000,
        fiber_amount: 4_900_000, // LP keeps a 100k spread
        hashlock: swap_hashlock(SECRET),
        pool_timeout: 50,
        fiber_timeout: 10,
        lock_nonce: 0,
    }
}

fn pool_locked(t: &SwapTerms) -> LegState {
    LegState::Locked { hashlock: t.hashlock, amount: t.dust, timeout: t.pool_timeout }
}

/// Drive both roles to completion against a mocked counterparty leg, applying each action to the
/// modelled pool leg / mock leg. Returns the final leg states and the action log.
fn run(t: &SwapTerms, now: u64) -> (LegState, LegState, Vec<(Role, Action)>) {
    let mut pool = LegState::Empty;
    let mut cp = MockLeg::new();
    let mut log = Vec::new();
    for _ in 0..12 {
        let ma = decide(Role::Maker, t, &pool, &cp.state(), now);
        log.push((Role::Maker, ma.clone()));
        match &ma {
            Action::LockPool => {
                pool = LegState::Locked { hashlock: t.hashlock, amount: t.dust, timeout: t.pool_timeout }
            }
            Action::ClaimCounterparty => cp.claim(SECRET),
            Action::RefundPool => pool = LegState::Refunded,
            _ => {}
        }
        let ta = decide(Role::Taker, t, &pool, &cp.state(), now);
        log.push((Role::Taker, ta.clone()));
        match &ta {
            Action::LockCounterparty => cp.lock(t.hashlock, t.fiber_amount, t.fiber_timeout),
            Action::ClaimPool { preimage } => pool = LegState::Claimed { preimage: preimage.clone() },
            Action::RefundCounterparty => cp.refund(),
            _ => {}
        }
        if matches!(ma, Action::Done) && matches!(ta, Action::Done) {
            break;
        }
    }
    (pool, cp.state(), log)
}

#[test]
fn happy_path_settles_both_legs_atomically() {
    let t = terms();
    t.validate().unwrap();
    let (pool, cp, log) = run(&t, 0);

    // Both legs claimed with the same secret: the maker got the counterparty payment and the
    // taker got the in-pool dust.
    assert_eq!(pool, LegState::Claimed { preimage: SECRET.to_vec() }, "taker claimed the pool dust");
    assert_eq!(cp, LegState::Claimed { preimage: SECRET.to_vec() }, "maker claimed the counterparty leg");

    // The action sequence is the canonical swap order.
    let actions: Vec<Action> = log.iter().map(|(_, a)| a.clone()).collect();
    assert!(actions.contains(&Action::LockPool));
    assert!(actions.contains(&Action::LockCounterparty));
    assert!(actions.contains(&Action::ClaimCounterparty));
    assert!(actions.iter().any(|a| matches!(a, Action::ClaimPool { .. })));
}

#[test]
fn taker_rejects_a_mismatched_pool_lock() {
    let t = terms();
    // wrong hashlock
    let bad = LegState::Locked { hashlock: keccak(b"wrong"), amount: t.dust, timeout: t.pool_timeout };
    assert!(matches!(decide(Role::Taker, &t, &bad, &LegState::Empty, 0), Action::Abort(_)));
    // wrong amount (LP would be underpaid for the dust it claims)
    let bad = LegState::Locked { hashlock: t.hashlock, amount: t.dust - 1, timeout: t.pool_timeout };
    assert!(matches!(decide(Role::Taker, &t, &bad, &LegState::Empty, 0), Action::Abort(_)));
    // wrong timeout
    let bad = LegState::Locked { hashlock: t.hashlock, amount: t.dust, timeout: t.pool_timeout + 1 };
    assert!(matches!(decide(Role::Taker, &t, &bad, &LegState::Empty, 0), Action::Abort(_)));
    // a sound lock is accepted (taker locks its leg)
    assert_eq!(decide(Role::Taker, &t, &pool_locked(&t), &LegState::Empty, 0), Action::LockCounterparty);
}

#[test]
fn maker_does_not_reveal_against_a_bad_counterparty_lock() {
    let t = terms();
    let pool = pool_locked(&t);
    // wrong hashlock => never reveal the secret
    let bad = LegState::Locked { hashlock: keccak(b"wrong"), amount: t.fiber_amount, timeout: t.fiber_timeout };
    assert_eq!(decide(Role::Maker, &t, &pool, &bad, 0), Action::Wait);
    // underpaid
    let bad = LegState::Locked { hashlock: t.hashlock, amount: t.fiber_amount - 1, timeout: t.fiber_timeout };
    assert_eq!(decide(Role::Maker, &t, &pool, &bad, 0), Action::Wait);
    // counterparty timeout not strictly before pool timeout
    let bad = LegState::Locked { hashlock: t.hashlock, amount: t.fiber_amount, timeout: t.pool_timeout };
    assert_eq!(decide(Role::Maker, &t, &pool, &bad, 0), Action::Wait);
    // a sound counterparty lock => reveal
    let good = LegState::Locked { hashlock: t.hashlock, amount: t.fiber_amount, timeout: t.fiber_timeout };
    assert_eq!(decide(Role::Maker, &t, &pool, &good, 0), Action::ClaimCounterparty);
}

#[test]
fn aborted_swap_refunds_both_legs() {
    let t = terms();
    let pool = pool_locked(&t);
    // LP never locked its leg: after pool_timeout the maker refunds the pool dust.
    assert_eq!(decide(Role::Maker, &t, &pool, &LegState::Empty, t.pool_timeout), Action::RefundPool);
    assert_eq!(decide(Role::Maker, &t, &pool, &LegState::Empty, t.pool_timeout - 1), Action::Wait);
    // Maker never claimed: after fiber_timeout the taker refunds its counterparty leg.
    let cp_locked = LegState::Locked { hashlock: t.hashlock, amount: t.fiber_amount, timeout: t.fiber_timeout };
    assert_eq!(decide(Role::Taker, &t, &pool, &cp_locked, t.fiber_timeout), Action::RefundCounterparty);
    assert_eq!(decide(Role::Taker, &t, &pool, &cp_locked, t.fiber_timeout - 1), Action::Wait);
}

#[test]
fn operator_dark_residual_is_flagged_not_silently_lost() {
    let t = terms();
    let pool = pool_locked(&t);
    let cp_claimed = LegState::Claimed { preimage: SECRET.to_vec() };
    // Secret revealed but the taker can still claim before pool_timeout.
    assert!(matches!(decide(Role::Taker, &t, &pool, &cp_claimed, t.pool_timeout - 1), Action::ClaimPool { .. }));
    // Past pool_timeout (operator went dark mid-swap), the window is missed: surfaced as Abort.
    assert!(matches!(decide(Role::Taker, &t, &pool, &cp_claimed, t.pool_timeout), Action::Abort(_)));
}

#[test]
fn validate_enforces_ordering_and_amounts() {
    assert!(terms().validate().is_ok());
    let mut t = terms();
    t.fiber_timeout = t.pool_timeout; // no margin
    assert!(t.validate().is_err());
    t = terms();
    t.dust = 0;
    assert!(t.validate().is_err());
    t = terms();
    t.fiber_amount = t.dust + 1; // LP overpays
    assert!(t.validate().is_err());
    t = terms();
    t.taker_key = t.maker_key;
    assert!(t.validate().is_err());
}

#[cfg(feature = "htlc_sha256")]
#[test]
fn pool_legs_settle_through_the_real_stf() {
    use liquid_cells_client::Account;
    use liquid_cells_stf::{apply, Batch, Deposit, State};

    const CHAIN: u64 = 0x434b_42;
    let mut maker = Account::new(pool_id(), CHAIN, [7u8; 32]);
    let taker_key = Account::new(pool_id(), CHAIN, [9u8; 32]).key();

    // Fund the maker, then propose a swap of 5M dust for a 4.9M counterparty payment.
    let mut st = State::genesis(pool_id(), CHAIN);
    apply(&mut st, &Batch {
        current_epoch: 0,
        deposits: vec![Deposit { to_key: maker.key(), amount: 10_000_000 }],
        ..Default::default()
    }).unwrap();

    let t = SwapTerms::propose(&maker, taker_key, 5_000_000, 4_900_000, SECRET, 50, 10);
    t.validate().unwrap();

    // Maker escrows the dust (pool leg) under H = sha256(secret).
    let lock = t.maker_lock(&mut maker, 1_000);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    // Taker claims with the revealed secret; the sha256 hashlock requires the htlc_sha256 STF.
    let claim = t.taker_claim(SECRET.to_vec());
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();

    assert_eq!(st.get_leaf(&taker_key).balance, 5_000_000, "the LP received the in-pool dust");
}
