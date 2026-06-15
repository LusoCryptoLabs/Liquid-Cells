//! Hybrid fee schedule + fee sponsorship. The schedule is pure pricing; sponsorship is exercised
//! end-to-end through the real STF to prove a sub-cent tip (whose floor fee exceeds the tip) only
//! settles when a platform covers the fee.

use liquid_cells_client::{Account, FeeSchedule};
use liquid_cells_stf::{apply, keccak, Batch, Deposit, Hash, State, StfError};

const CHAIN: u64 = 0x434b42;

fn pool_id() -> Hash {
    keccak(b"fees-pool")
}

fn funded_state(deposits: &[(Hash, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN);
    let batch = Batch {
        current_epoch: 0,
        deposits: deposits.iter().map(|(k, a)| Deposit { to_key: *k, amount: *a }).collect(),
        ..Default::default()
    };
    apply(&mut st, &batch).unwrap();
    st
}

#[test]
fn fee_for_is_max_of_floor_and_basis_points() {
    let s = FeeSchedule::new(5, 100); // floor 5, 1%
    assert_eq!(s.fee_for(1), 5, "1% of 1 == 0, floor dominates");
    assert_eq!(s.fee_for(100), 5, "1% of 100 == 1 < 5, floor dominates");
    assert_eq!(s.fee_for(1000), 10, "1% of 1000 == 10 > 5, percentage dominates");
    assert_eq!(s.fee_for(0), 5, "floor on a zero amount");
    assert_eq!(FeeSchedule::flat(7).fee_for(1_000_000), 7, "bps 0 is a flat floor");
    // saturating: a huge amount clamps instead of overflowing.
    assert_eq!(FeeSchedule::new(0, 250).fee_for(u128::MAX), u128::MAX / 10_000);
}

#[test]
fn transfer_scheduled_attaches_the_scheduled_fee() {
    let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
    let s = FeeSchedule::new(5, 100);
    assert_eq!(alice.transfer_scheduled(keccak(b"bob"), 1000, &s, 100).fee, 10);
    assert_eq!(alice.transfer_scheduled(keccak(b"bob"), 1, &s, 100).fee, 5);
}

#[test]
fn sub_cent_tip_fails_without_sponsorship() {
    let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
    let creator = Account::new(pool_id(), CHAIN, [8u8; 32]);
    let mut st = funded_state(&[(alice.key(), 1)]); // alice holds exactly her 1-unit tip
    let s = FeeSchedule::new(5, 100); // floor 5 > the tip

    let tip = alice.transfer_scheduled(creator.key(), 1, &s, 100); // needs amount 1 + fee 5 = 6
    let batch = Batch { current_epoch: 0, transfers: vec![tip], ..Default::default() };
    assert!(
        matches!(apply(&mut st, &batch), Err(StfError::InsufficientBalance)),
        "a 1-unit balance cannot cover the 5-unit floor fee, the unsponsored tip can't settle"
    );
}

#[test]
fn sub_cent_tip_succeeds_with_fee_sponsorship() {
    let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
    let mut platform = Account::new(pool_id(), CHAIN, [9u8; 32]);
    let creator = Account::new(pool_id(), CHAIN, [8u8; 32]);
    let mut st = funded_state(&[(alice.key(), 1), (platform.key(), 1000)]);
    let s = FeeSchedule::new(5, 100);
    let fee = s.fee_for(1); // 5

    // The platform sponsors the fee, ORDERED FIRST so alice can afford tip + fee.
    let topup = platform.sponsor_fee(alice.key(), fee, 100);
    let tip = alice.transfer_scheduled(creator.key(), 1, &s, 100);
    let batch = Batch { current_epoch: 0, transfers: vec![topup, tip], ..Default::default() };
    apply(&mut st, &batch).unwrap();

    assert_eq!(st.get_leaf(&alice.key()).balance, 0, "alice's marginal cost is just the 1-unit tip");
    assert_eq!(st.get_leaf(&creator.key()).balance, 1, "creator received the tip");
    assert_eq!(st.get_leaf(&platform.key()).balance, 995, "platform absorbed the 5-unit fee");
    assert_eq!(st.pool.fee_acc, 5, "the sponsored fee accrued to the pool");
    assert_eq!(st.pool.total, 1001, "value conserved (deposits 1 + 1000, no exits)");
}
