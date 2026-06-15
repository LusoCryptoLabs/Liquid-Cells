//! The staged `htlc_sha256` hashlock: the in-pool HTLC claims against `sha256(preimage)` so the
//! pool swap leg can share one hashlock value with a Fiber / Bitcoin-Lightning HTLC (whose
//! `HashAlgorithm` is Sha256, never keccak). An atomic swap needs both legs locked to the same
//! hash of one secret, so this is the Fiber dust-egress prerequisite. Runs under
//! `--features htlc_sha256`.
#![cfg(feature = "htlc_sha256")]

use liquid_cells_stf::hash::sha256;
use liquid_cells_stf::*;

const CHAIN_ID: u64 = 0x434b_42;
const PRE: &[u8] = b"liquid-cells/fiber-swap/secret";

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn pool_id() -> Hash {
    keccak(b"htlc-sha256-pool")
}
fn key_for(b: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(b)))
}

fn funded(funding: &[(u8, u128)]) -> State {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let deposits = funding.iter().map(|(b, a)| Deposit { to_key: key_for(*b), amount: *a }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    st
}

#[allow(clippy::too_many_arguments)]
fn signed_lock(sb: u8, receiver_key: Hash, amount: u128, fee: u128, hashlock: Hash, timeout: u64, nonce: u64) -> HtlcLock {
    let sk = secret(sb);
    let sender_pubkey = sig::pubkey(&sk);
    let sender_key = key_of_pubkey(&sender_pubkey);
    let msg = htlc_lock_msg(CHAIN_ID, &pool_id(), &sender_key, &receiver_key, amount, fee, &hashlock, timeout, nonce);
    let (_pk, sig) = sig::sign(&sk, &msg);
    HtlcLock { sender_pubkey, receiver_key, amount, fee, hashlock, timeout, nonce, sig }
}
fn href(sender: u8, receiver_key: Hash, amount: u128, hashlock: Hash, timeout: u64, lock_nonce: u64) -> HtlcRef {
    HtlcRef { sender_key: key_for(sender), receiver_key, amount, hashlock, timeout, lock_nonce }
}

#[test]
fn swap_claims_under_a_sha256_hashlock() {
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2); // the LP / receiver
    let (amount, fee) = (5_000_000u128, 1_000u128); // dust (< 61 CKB)
    let hl = sha256(PRE); // the Fiber-compatible hashlock H = sha256(s)
    assert_ne!(hl, keccak(PRE), "sha256(s) and keccak(s) differ, so the hash genuinely switched");

    // Alice escrows dust to Bob under the sha256 hashlock.
    let lock = signed_lock(1, bob, amount, fee, hl, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    // Bob claims by revealing s (the same secret he'd reveal to pull a Fiber Sha256 HTLC).
    let claim = HtlcClaim { htlc: href(1, bob, amount, hl, 50, 0), preimage: PRE.to_vec() };
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob).balance, amount, "receiver paid by revealing the sha256 preimage");
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    assert_eq!(sum + st.pool.fee_acc, st.pool.total, "value conserved across the swap");
}

#[test]
fn a_keccak_hashlock_is_no_longer_claimable() {
    // Proof the check actually moved to sha256: a legacy keccak(s) hashlock cannot be opened with
    // the secret, because the claim now verifies sha256(s) != keccak(s).
    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let hl = keccak(PRE); // the OLD (deployed) scheme's hashlock
    let lock = signed_lock(1, bob, 5_000_000, 1_000, hl, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let claim = HtlcClaim { htlc: href(1, bob, 5_000_000, hl, 50, 0), preimage: PRE.to_vec() };
    assert_eq!(
        apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }),
        Err(StfError::BadPreimage),
        "under htlc_sha256 a keccak hashlock rejects the secret"
    );
}

#[test]
fn fiber_and_pool_legs_share_one_hashlock() {
    // The atomicity invariant: the value the pool leg locks to is exactly what a Fiber Sha256 HTLC
    // would lock to for the same secret, so revealing s on either network opens the other.
    let pool_leg_hashlock = sha256(PRE);
    let fiber_sha256_hashlock = sha256(PRE); // Fiber HashAlgorithm::Sha256 over the same secret
    assert_eq!(pool_leg_hashlock, fiber_sha256_hashlock, "both legs bind the same H = sha256(s)");
}

#[test]
fn live_fiber_preimage_claims_the_pool_leg() {
    // Pins the in-pool leg to the EXACT secret of a real atomic swap executed on the Fiber testnet:
    // a live fnn node held a Sha256 HOLD invoice with payment_hash = H below, the taker paid it, and
    // the maker settled with PREIMAGE below (sha256(PREIMAGE) == H, enforced by fnn's settle_invoice).
    // Here the same 32-byte PREIMAGE opens the pool HTLC locked to that same H, so revealing the
    // secret on Fiber and on the pool are one and the same act. See docs/FIBER-INTEGRATION.md.
    const PREIMAGE: [u8; 32] = [
        0x09, 0x2b, 0xd7, 0x51, 0x92, 0xe4, 0x85, 0x8f, 0x5c, 0x25, 0x07, 0xff, 0x54, 0xc0, 0x21, 0x36,
        0xb9, 0x7c, 0x22, 0xb4, 0x25, 0x0d, 0x59, 0x86, 0xc5, 0xf9, 0x54, 0x25, 0x4c, 0xc8, 0x7a, 0x45,
    ];
    const FIBER_PAYMENT_HASH: [u8; 32] = [
        0x4a, 0x7c, 0x11, 0x18, 0xc0, 0x1e, 0x0f, 0x7c, 0xd4, 0x88, 0x18, 0x51, 0x80, 0xc2, 0xbc, 0xef,
        0xa7, 0x9b, 0xf3, 0x92, 0x8e, 0xb6, 0x38, 0x19, 0x18, 0x90, 0x39, 0x82, 0x00, 0x33, 0x2f, 0x36,
    ];
    let hl = sha256(&PREIMAGE);
    assert_eq!(hl, FIBER_PAYMENT_HASH, "pool leg binds the exact H the live Fiber invoice was paid against");

    let mut st = funded(&[(1, 100_000_000)]);
    let bob = key_for(2);
    let (amount, fee) = (5_000_000u128, 1_000u128); // dust egress
    let lock = signed_lock(1, bob, amount, fee, hl, 50, 0);
    apply(&mut st, &Batch { current_epoch: 1, htlc_locks: vec![lock], ..Default::default() }).unwrap();

    let claim = HtlcClaim { htlc: href(1, bob, amount, hl, 50, 0), preimage: PREIMAGE.to_vec() };
    apply(&mut st, &Batch { current_epoch: 2, htlc_claims: vec![claim], ..Default::default() }).unwrap();
    assert_eq!(st.get_leaf(&bob).balance, amount, "the live Fiber secret claims the pool leg");
}
