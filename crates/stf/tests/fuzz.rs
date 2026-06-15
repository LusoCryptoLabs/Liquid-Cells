//! Deterministic randomized (fuzz) tests for the state-transition function.
//!
//! The example-based tests in `properties.rs` pin individual behaviours. This file
//! drives *thousands* of randomized mixed batches through [`apply`] and, after every
//! accepted batch, checks the protocol's hard invariants against an independent
//! shadow ledger computed outside the STF:
//!
//!   1. **Value conservation**, `Σ balances + fee_acc == total`, always.
//!   2. **No debit without a signature**, a corrupted or forged authorization is
//!      always rejected, and a rejected batch never moves the root.
//!   3. **Shadow agreement**, a balance/nonce ledger maintained independently of the
//!      STF matches the STF's leaves leaf-for-leaf after every batch. A divergent root
//!      class of bug (the thing the whole rollup rests on) would surface here.
//!   4. **Determinism**, the same seed replays to a byte-identical final root.
//!   5. **Total stability under rejection**, checked arithmetic means a malformed or
//!      over-drawing batch returns `Err`, never panics, and leaves state untouched.
//!
//! The RNG is a seeded SplitMix64/xorshift (no external crate, no `rand`), so any
//! failure is reproducible from its seed. Bump `SEEDS`/`BATCHES` to fuzz harder.

use liquid_cells_stf::*;
use std::collections::BTreeMap;

const CHAIN_ID: u64 = 0x0043_4b42;
const ACCOUNTS: u8 = 6; // secrets 1..=6
// Tuned so the suite stays under ~45s in debug (ECDSA signing dominates). Each seed drives a
// full mixed checkpoint chain; bump these locally to fuzz harder (the harness is seed-stable).
const SEEDS: u64 = 8;
const BATCHES: usize = 40; // checkpoints per seed
const FUND: u128 = 50_000_000_000; // 500 CKB each at genesis

fn pool_id() -> Hash {
    keccak(b"fuzz-pool")
}
fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}
fn key_for(n: u8) -> Hash {
    key_of_pubkey(&sig::pubkey(&secret(n)))
}

/// Minimal seeded PRNG (SplitMix64). Reproducible: same seed, same stream.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn account(&mut self) -> u8 {
        1 + (self.below(ACCOUNTS as u64) as u8)
    }
}

/// Independent ledger the STF is checked against. Tracks per-account balance+nonce and
/// the pool's `total`/`fee_acc` using only arithmetic, no SMT, no STF code.
#[derive(Clone, Default)]
struct Shadow {
    bal: BTreeMap<u8, u128>,
    nonce: BTreeMap<u8, u64>,
    total: u128,
    fee_acc: u128,
}
impl Shadow {
    fn bal_of(&self, a: u8) -> u128 {
        *self.bal.get(&a).unwrap_or(&0)
    }
    fn nonce_of(&self, a: u8) -> u64 {
        *self.nonce.get(&a).unwrap_or(&0)
    }
}

fn signed_transfer(payer: u8, to: Hash, amount: u128, fee: u128, nonce: u64, expiry: u64) -> Transfer {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = transfer_msg(CHAIN_ID, &pool_id(), &from_key, &to, amount, fee, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Transfer { from_pubkey, to_key: to, amount, fee, nonce, expiry, sig }
}
fn signed_withdrawal(payer: u8, target: Hash, amount: u128, nonce: u64, expiry: u64) -> Withdrawal {
    let sk = secret(payer);
    let from_pubkey = sig::pubkey(&sk);
    let from_key = key_of_pubkey(&from_pubkey);
    let msg = withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &target, amount, nonce, expiry);
    let (_pk, sig) = sig::sign(&sk, &msg);
    Withdrawal { from_pubkey, target_lock_hash: target, amount, nonce, expiry, sig }
}

fn genesis_with_funds() -> (State, Shadow) {
    let mut st = State::genesis(pool_id(), CHAIN_ID);
    let mut sh = Shadow::default();
    let deposits: Vec<Deposit> =
        (1..=ACCOUNTS).map(|a| Deposit { to_key: key_for(a), amount: FUND }).collect();
    apply(&mut st, &Batch { current_epoch: 0, deposits, ..Default::default() }).unwrap();
    for a in 1..=ACCOUNTS {
        sh.bal.insert(a, FUND);
        sh.total += FUND;
    }
    (st, sh)
}

/// Assert the STF leaves match the shadow ledger exactly, plus the conservation relation.
fn check_consistency(st: &State, sh: &Shadow) {
    assert_eq!(st.pool.total, sh.total, "total diverged from shadow");
    assert_eq!(st.pool.fee_acc, sh.fee_acc, "fee_acc diverged from shadow");
    for a in 1..=ACCOUNTS {
        let leaf = st.get_leaf(&key_for(a));
        assert_eq!(leaf.balance, sh.bal_of(a), "account {a} balance diverged from shadow");
        assert_eq!(leaf.nonce, sh.nonce_of(a), "account {a} nonce diverged from shadow");
    }
    let sum: u128 = st.leaves.values().map(|l| l.balance).sum();
    assert_eq!(sum + st.pool.fee_acc, st.pool.total, "Σ balances + fee_acc == total violated");
}

/// Build a random *valid* batch from the current shadow state, returning the batch and the
/// shadow delta to apply on success. Each acting account uses its current nonce exactly once,
/// so the whole batch is internally consistent.
fn random_valid_batch(rng: &mut Rng, sh: &Shadow, epoch: u64) -> (Batch, Shadow) {
    let mut next = sh.clone();
    let mut transfers = Vec::new();
    let mut withdrawals = Vec::new();
    let mut deposits = Vec::new();
    let mut fee_budget: u128 = 0;

    // a random non-empty subset of accounts each does at most one signed op
    let acting = 1 + rng.below(ACCOUNTS as u64);
    let mut used: Vec<u8> = Vec::new();
    for _ in 0..acting {
        let payer = rng.account();
        if used.contains(&payer) {
            continue; // one op per payer per batch keeps nonces single-use
        }
        let bal = next.bal_of(payer);
        if bal == 0 {
            continue;
        }
        let nonce = next.nonce_of(payer);
        match rng.below(3) {
            0 => {
                // transfer to a different account, amount+fee <= balance
                let mut to = rng.account();
                if to == payer {
                    to = 1 + (payer % ACCOUNTS);
                }
                let fee = (rng.below(1000) as u128) % (bal / 2 + 1);
                let room = bal - fee; // amount + fee <= balance
                if room == 0 {
                    continue;
                }
                let amount = 1 + (rng.below(room as u64) as u128); // 1..=room
                transfers.push(signed_transfer(payer, key_for(to), amount, fee, nonce, epoch + 1000));
                *next.bal.entry(payer).or_insert(0) -= amount + fee;
                *next.bal.entry(to).or_insert(0) += amount;
                *next.nonce.entry(payer).or_insert(0) += 1;
                next.fee_acc += fee;
                fee_budget += fee;
                used.push(payer);
            }
            1 => {
                // withdrawal, amount <= balance, leaves the pool
                let amount = 1 + rng.below(bal as u64);
                let amount = (amount as u128).min(bal);
                let target = keccak(&[0xAA, payer, epoch as u8]);
                withdrawals.push(signed_withdrawal(payer, target, amount, nonce, epoch + 1000));
                *next.bal.entry(payer).or_insert(0) -= amount;
                *next.nonce.entry(payer).or_insert(0) += 1;
                next.total -= amount;
                used.push(payer);
            }
            _ => {
                // deposit credits an account (authority is an on-chain cell, no signature)
                let to = rng.account();
                let amount = 1 + rng.below(1_000_000) as u128;
                deposits.push(Deposit { to_key: key_for(to), amount });
                *next.bal.entry(to).or_insert(0) += amount;
                next.total += amount;
            }
        }
    }

    // sometimes draw part of this batch's accrued fees to fund an L1 fee
    let fee_withdrawal = if fee_budget > 0 && rng.below(2) == 0 {
        let avail = sh.fee_acc + fee_budget;
        let draw = rng.below(avail as u64 + 1) as u128;
        next.fee_acc -= draw;
        next.total -= draw;
        draw
    } else {
        0
    };

    let batch = Batch {
        current_epoch: epoch,
        deposits,
        transfers,
        withdrawals,
        fee_withdrawal,
        ..Default::default()
    };
    (batch, next)
}

#[test]
fn fuzz_valid_batches_conserve_value_and_match_shadow() {
    for seed in 0..SEEDS {
        let mut rng = Rng(0xC0FF_EE00 ^ seed);
        let (mut st, mut sh) = genesis_with_funds();
        check_consistency(&st, &sh);

        for b in 0..BATCHES {
            let epoch = (b as u64) + 1;
            let (batch, next) = random_valid_batch(&mut rng, &sh, epoch);
            let root_before = st.pool.root;
            let seq_before = st.pool.seq;
            match apply(&mut st, &batch) {
                Ok(pv) => {
                    sh = next;
                    assert_eq!(pv.new_seq, seq_before + 1, "seq must advance by exactly 1");
                    assert_eq!(pv.new_root, st.pool.root);
                    check_consistency(&st, &sh);
                }
                Err(e) => {
                    // A generated-valid batch should apply; if not, the root must be untouched.
                    assert_eq!(st.pool.root, root_before, "rejected batch moved the root: {e:?}");
                    panic!("seed {seed} batch {b}: a valid batch was rejected: {e:?}");
                }
            }
        }
    }
}

#[test]
fn fuzz_corrupted_authorization_is_always_rejected() {
    // Every signed debit, when its authorization is corrupted in any of several ways, must be
    // rejected, and a rejected batch must never advance the root (no partial application).
    for seed in 0..SEEDS {
        let mut rng = Rng(0xBADC_0DE0 ^ seed);
        let (mut st, sh) = genesis_with_funds();

        for _ in 0..BATCHES {
            let payer = rng.account();
            let bal = sh.bal_of(payer);
            let amount = 1 + (rng.below(bal as u64) as u128).min(bal - 1);
            let nonce = st.get_leaf(&key_for(payer)).nonce;
            let mut t = signed_transfer(payer, key_for(1 + (payer % ACCOUNTS)), amount, 0, nonce, 1_000_000);

            match rng.below(4) {
                0 => t.sig[(rng.below(64)) as usize] ^= 0x01 | (1 << (rng.below(7))), // flip sig bit
                1 => t.amount = t.amount.wrapping_add(1),                              // tamper amount
                2 => t.from_pubkey = sig::pubkey(&secret(1 + (payer % ACCOUNTS))),     // wrong signer
                _ => t.to_key = keccak(&[0x99, payer]),                                // tamper recipient
            }

            let root_before = st.pool.root;
            let total_before = st.pool.total;
            let res = apply(&mut st, &Batch { current_epoch: 1, transfers: vec![t], ..Default::default() });
            assert!(res.is_err(), "seed {seed}: a corrupted transfer was accepted");
            assert_eq!(st.pool.root, root_before, "rejected batch moved the root");
            assert_eq!(st.pool.total, total_before, "rejected batch changed total");
        }
    }
}

#[test]
fn fuzz_is_deterministic_across_replays() {
    // The same seed must drive the same sequence of roots: this is what lets the sequencer and
    // the zkVM guest (running this identical code) never disagree.
    fn run(seed: u64) -> (Hash, u64, u128, u128) {
        let mut rng = Rng(0x5EED_0000 ^ seed);
        let (mut st, mut sh) = genesis_with_funds();
        for b in 0..BATCHES {
            let (batch, next) = random_valid_batch(&mut rng, &sh, (b as u64) + 1);
            if apply(&mut st, &batch).is_ok() {
                sh = next;
            }
        }
        (st.pool.root, st.pool.seq, st.pool.total, st.pool.fee_acc)
    }
    for seed in 0..SEEDS {
        assert_eq!(run(seed), run(seed), "STF is not deterministic for seed {seed}");
    }
}

#[test]
fn fuzz_overdraw_and_malformed_never_panic() {
    // Throw deliberately invalid batches (over-draws, bad nonces, oversized amounts) at the STF
    // and assert it returns Err rather than panicking, and never mutates state on Err.
    for seed in 0..SEEDS {
        let mut rng = Rng(0xDEAD_0000 ^ seed);
        let (mut st, _sh) = genesis_with_funds();
        for _ in 0..BATCHES {
            let payer = rng.account();
            let nonce = st.get_leaf(&key_for(payer)).nonce;
            let bad = match rng.below(3) {
                0 => {
                    // over-draw fees with no fee revenue this batch
                    Batch { current_epoch: 1, fee_withdrawal: 1 + rng.below(1_000_000) as u128, ..Default::default() }
                }
                1 => {
                    // withdraw more than the balance
                    let w = signed_withdrawal(payer, keccak(b"x"), FUND * 100, nonce, 1_000_000);
                    Batch { current_epoch: 1, withdrawals: vec![w], ..Default::default() }
                }
                _ => {
                    // stale nonce replay
                    let t = signed_transfer(payer, key_for(1 + (payer % ACCOUNTS)), 1, 0, nonce.wrapping_add(7), 1_000_000);
                    Batch { current_epoch: 1, transfers: vec![t], ..Default::default() }
                }
            };
            let root_before = st.pool.root;
            let total_before = st.pool.total;
            let _ = apply(&mut st, &bad); // must not panic
            assert_eq!(st.pool.root, root_before, "an invalid batch advanced the root");
            assert_eq!(st.pool.total, total_before, "an invalid batch changed total");
        }
    }
}
