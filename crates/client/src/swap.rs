//! Dust-egress atomic-swap coordinator (off-chain orchestration; no Fiber node required).
//!
//! Drives the hash-locked swap that moves a sub-61-CKB in-pool balance to a liquidity provider in
//! exchange for an off-chain payment, atomically, via one shared preimage. The **in-pool leg** is an
//! LC HTLC ([`crate::Account::htlc_lock`] + the pool `htlc_claim`/`htlc_refund`); the **counterparty
//! leg** is a Fiber / Bitcoin-Lightning HTLC (or an L1 HTLC), abstracted behind [`CounterpartyLeg`]
//! so the same coordinator runs against an in-memory [`MockLeg`] in tests and, later, a real `fnn`
//! node behind the same trait, with no logic change.
//!
//! Both legs lock to the SAME `H = sha256(secret)` (Fiber's hash; see docs/EGRESS.md), the only thing
//! that binds them to one secret with no trusted third party. [`decide`] is the state machine; it
//! encodes the safety so neither party loses funds:
//!
//!   * the **taker** (LP) never locks its payment until it has verified the pool lock binds the
//!     agreed `H`, amount, and timeout (and the `htlc_id` it located the escrow by already names the
//!     taker as receiver), and it claims the pool leg the instant the secret is revealed;
//!   * the **maker** (dust holder) never reveals the secret until it has verified the counterparty
//!     leg is locked to the same `H`, pays at least the agreed amount, and expires before
//!     `pool_timeout`; otherwise it waits and refunds the pool after `pool_timeout`;
//!   * the **timeout ordering** `fiber_timeout < pool_timeout` (enforced by [`SwapTerms::validate`])
//!     guarantees the taker has a window `[fiber_timeout, pool_timeout]` to claim the pool leg after
//!     the maker reveals.
//!
//! The one residual (docs/EGRESS.md): if the operator goes dark *after* the maker reveals but
//! *before* the taker claims the pool leg, the taker can miss its window, the priced LP risk
//! surfaced here as [`Action::Abort`] with the operator-dark note.

use crate::Account;
use liquid_cells_stf::{htlc_id, Hash, HtlcClaim, HtlcLock, HtlcRef, HtlcRefund};

/// The Fiber-compatible swap hashlock `H = sha256(secret)`. Both legs lock to this.
pub fn swap_hashlock(secret: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(secret);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// The pool leg must outlive the counterparty leg by at least this, so the taker has a claim window
/// after the maker reveals the secret. (Abstract clock units; a real integration maps CKB epochs and
/// the Fiber timeout onto a common timeline, keeping this ordering.)
pub const MIN_TIMEOUT_MARGIN: u64 = 1;

/// The agreed swap terms, shared by both parties. The maker escrows `dust` in the pool to the taker;
/// the taker pays `fiber_amount` to the maker on the counterparty leg. Both lock to `hashlock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapTerms {
    pub pool_id: Hash,
    /// Dust holder; sender of the pool leg.
    pub maker_key: Hash,
    /// LP; receiver of the pool leg.
    pub taker_key: Hash,
    /// In-pool amount escrowed (the pool leg).
    pub dust: u128,
    /// What the taker pays the maker on the counterparty leg.
    pub fiber_amount: u128,
    /// `H = sha256(secret)`.
    pub hashlock: Hash,
    /// `T_pool` (CKB epochs): the pool escrow is refundable to the maker at/after this.
    pub pool_timeout: u64,
    /// `T_fiber`: the counterparty leg's deadline (must precede `pool_timeout`).
    pub fiber_timeout: u64,
    /// The maker's account nonce at lock time (binds the escrow `htlc_id`).
    pub lock_nonce: u64,
}

impl SwapTerms {
    /// Propose terms from a maker account and a secret. Sets `hashlock = sha256(secret)` and
    /// `lock_nonce = maker.nonce()` (so [`maker_lock`](Self::maker_lock) and the escrow `htlc_id`
    /// agree). Validate before acting.
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        maker: &Account,
        taker_key: Hash,
        dust: u128,
        fiber_amount: u128,
        secret: &[u8],
        pool_timeout: u64,
        fiber_timeout: u64,
    ) -> Self {
        Self {
            pool_id: maker.pool_id(),
            maker_key: maker.key(),
            taker_key,
            dust,
            fiber_amount,
            hashlock: swap_hashlock(secret),
            pool_timeout,
            fiber_timeout,
            lock_nonce: maker.nonce(),
        }
    }

    /// Validate amounts and the timeout ordering. Both parties run this before engaging.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.dust == 0 {
            return Err("zero dust");
        }
        if self.fiber_amount == 0 {
            return Err("zero counterparty payment");
        }
        if self.fiber_amount > self.dust {
            return Err("taker overpays (fiber_amount > dust)");
        }
        if self.maker_key == self.taker_key {
            return Err("maker == taker");
        }
        if self.fiber_timeout + MIN_TIMEOUT_MARGIN > self.pool_timeout {
            return Err("fiber_timeout must precede pool_timeout by the margin");
        }
        Ok(())
    }

    /// The escrow leaf key the pool leg lives at.
    pub fn pool_htlc_id(&self) -> Hash {
        htlc_id(
            &self.pool_id, &self.maker_key, &self.taker_key, self.dust, &self.hashlock,
            self.pool_timeout, self.lock_nonce,
        )
    }

    /// The `HtlcRef` terms used by the pool claim/refund.
    pub fn href(&self) -> HtlcRef {
        HtlcRef {
            sender_key: self.maker_key,
            receiver_key: self.taker_key,
            amount: self.dust,
            hashlock: self.hashlock,
            timeout: self.pool_timeout,
            lock_nonce: self.lock_nonce,
        }
    }

    /// The maker's pool `htlc_lock` intent (signed by `maker`, whose nonce must equal `lock_nonce`).
    pub fn maker_lock(&self, maker: &mut Account, fee: u128) -> HtlcLock {
        debug_assert_eq!(maker.nonce(), self.lock_nonce, "maker nonce must match lock_nonce");
        let (lock, _r) =
            maker.htlc_lock(self.taker_key, self.dust, fee, self.hashlock, self.pool_timeout);
        lock
    }

    /// The taker's pool `htlc_claim` intent, revealing the preimage (unsigned; the receiver is fixed
    /// by `htlc_id`).
    pub fn taker_claim(&self, preimage: Vec<u8>) -> HtlcClaim {
        HtlcClaim { htlc: self.href(), preimage }
    }

    /// The maker's pool `htlc_refund` intent (unsigned; valid only at/after `pool_timeout`).
    pub fn maker_refund(&self) -> HtlcRefund {
        HtlcRefund { htlc: self.href() }
    }
}

/// The observable state of one swap leg.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LegState {
    /// Not locked.
    #[default]
    Empty,
    /// Locked under `hashlock` for `amount`, expiring at `timeout`.
    Locked { hashlock: Hash, amount: u128, timeout: u64 },
    /// Claimed by revealing `preimage` (now public on that network).
    Claimed { preimage: Vec<u8> },
    /// Refunded after its timeout.
    Refunded,
}

/// The off-chain counterparty payment leg (a Fiber/Lightning HTLC, or an L1 HTLC). A real
/// implementation wraps an `fnn` node; tests use [`MockLeg`].
pub trait CounterpartyLeg {
    /// Lock `amount` to the beneficiary under `hashlock`, expiring at `timeout` (taker action).
    fn lock(&mut self, hashlock: Hash, amount: u128, timeout: u64);
    /// Claim by revealing `preimage` (maker action); the preimage becomes public.
    fn claim(&mut self, preimage: &[u8]);
    /// Refund after the leg's timeout (taker action, if the maker never claimed).
    fn refund(&mut self);
    /// The current observable state.
    fn state(&self) -> LegState;
}

/// An in-memory counterparty leg for tests, modelling a Fiber HTLC.
#[derive(Default)]
pub struct MockLeg {
    state: LegState,
}

impl MockLeg {
    pub fn new() -> Self {
        Self { state: LegState::Empty }
    }
}

impl CounterpartyLeg for MockLeg {
    fn lock(&mut self, hashlock: Hash, amount: u128, timeout: u64) {
        self.state = LegState::Locked { hashlock, amount, timeout };
    }
    fn claim(&mut self, preimage: &[u8]) {
        self.state = LegState::Claimed { preimage: preimage.to_vec() };
    }
    fn refund(&mut self) {
        self.state = LegState::Refunded;
    }
    fn state(&self) -> LegState {
        self.state.clone()
    }
}

/// Which side of the swap the coordinator is driving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Dust holder, sender of the pool leg.
    Maker,
    /// Liquidity provider, receiver of the pool leg / payer of the counterparty leg.
    Taker,
}

/// The next action the coordinator should take, given both legs' observed state and the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Maker: escrow the dust in the pool HTLC.
    LockPool,
    /// Taker: lock the counterparty leg (the pool lock checked out).
    LockCounterparty,
    /// Maker: claim the counterparty leg by revealing the secret (this publishes it).
    ClaimCounterparty,
    /// Taker: claim the pool leg with the now-public preimage.
    ClaimPool { preimage: Vec<u8> },
    /// Maker: refund the pool leg at/after `pool_timeout` (the swap did not complete).
    RefundPool,
    /// Taker: refund the counterparty leg at/after `fiber_timeout` (the maker never revealed).
    RefundCounterparty,
    /// Nothing to do yet; wait for the counterparty.
    Wait,
    /// Settled from this role's perspective.
    Done,
    /// A safety check failed; do not proceed.
    Abort(&'static str),
}

/// Decide the next action for `role`, given the swap `terms`, the observed `pool` and `counterparty`
/// leg states, and the current epoch `now`. Pure: reads state, returns an action, mutates nothing.
pub fn decide(role: Role, terms: &SwapTerms, pool: &LegState, counterparty: &LegState, now: u64) -> Action {
    match role {
        Role::Maker => decide_maker(terms, pool, counterparty, now),
        Role::Taker => decide_taker(terms, pool, counterparty, now),
    }
}

fn decide_maker(terms: &SwapTerms, pool: &LegState, cp: &LegState, now: u64) -> Action {
    match pool {
        LegState::Empty => Action::LockPool,
        LegState::Claimed { .. } | LegState::Refunded => Action::Done,
        LegState::Locked { .. } => match cp {
            // LP hasn't locked: wait, or refund the pool once it can be (LP bailed).
            LegState::Empty | LegState::Refunded => {
                if now >= terms.pool_timeout {
                    Action::RefundPool
                } else {
                    Action::Wait
                }
            }
            // LP locked: only reveal the secret if its leg is sound (else wait, then refund pool).
            LegState::Locked { hashlock, amount, timeout } => {
                if *hashlock != terms.hashlock
                    || *amount < terms.fiber_amount
                    || *timeout >= terms.pool_timeout
                    || now >= *timeout
                {
                    return Action::Wait;
                }
                Action::ClaimCounterparty
            }
            // Maker already revealed; the taker will claim the pool. Done.
            LegState::Claimed { .. } => Action::Done,
        },
    }
}

fn decide_taker(terms: &SwapTerms, pool: &LegState, cp: &LegState, now: u64) -> Action {
    match pool {
        LegState::Empty => Action::Wait, // maker hasn't locked the pool yet
        LegState::Claimed { .. } | LegState::Refunded => Action::Done,
        LegState::Locked { hashlock, amount, timeout } => {
            // Verify the pool lock binds the agreed terms before paying anything.
            if *hashlock != terms.hashlock {
                return Action::Abort("pool lock: wrong hashlock");
            }
            if *amount != terms.dust {
                return Action::Abort("pool lock: wrong amount");
            }
            if *timeout != terms.pool_timeout {
                return Action::Abort("pool lock: wrong timeout");
            }
            if terms.fiber_timeout + MIN_TIMEOUT_MARGIN > terms.pool_timeout {
                return Action::Abort("pool lock: insufficient timeout margin");
            }
            match cp {
                LegState::Empty => {
                    if now >= terms.pool_timeout {
                        Action::Abort("pool lock already expired")
                    } else {
                        Action::LockCounterparty
                    }
                }
                LegState::Locked { .. } => {
                    if now >= terms.fiber_timeout {
                        Action::RefundCounterparty // maker didn't claim in time
                    } else {
                        Action::Wait
                    }
                }
                LegState::Claimed { preimage } => {
                    if swap_hashlock(preimage) != terms.hashlock {
                        Action::Abort("revealed preimage does not match H")
                    } else if now >= terms.pool_timeout {
                        Action::Abort("missed the pool-claim window (operator-dark residual)")
                    } else {
                        Action::ClaimPool { preimage: preimage.clone() }
                    }
                }
                LegState::Refunded => Action::Done,
            }
        }
    }
}
