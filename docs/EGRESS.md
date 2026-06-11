# Dust Egress via Atomic Swap (Phase 5)

Force-exit ([FORCE-EXIT.md](FORCE-EXIT.md)) gives any holder a trustless way out — but it
produces a single L1 cell, which needs **~61 CKB** of capacity. A sub-61-CKB balance can't
become its own cell; that's physics, not a trust choice. So the *normal* exit for small
balances is not a self-cell, it's a **hash-locked atomic swap**: the dust stays in the pool
(it moves to a liquidity provider), and the LP pays the user on L1 or over Fiber — with no
denomination floor, and fully trustlessly because the two legs share one preimage.

## The in-pool HTLC

This repo implements the **in-pool leg**: a hash-time-locked escrow inside the pool state
(the L1 leg is a standard CKB HTLC lock or a Fiber hop — external). Three STF operations:

* **`htlc_lock`** — the sender signs an escrow of `amount` (+fee) to a receiver under a
  `hashlock` with a `timeout`. The funds leave the sender's account and live as a leaf at
  `htlc_id`.
* **`htlc_claim`** — anyone revealing the preimage (`keccak(preimage) == hashlock`) before
  `timeout` moves the escrow to the receiver.
* **`htlc_refund`** — at/after `timeout`, the escrow returns to the sender.

The escrow leaf's key commits to **every** term:

```
htlc_id = keccak(DOMAIN ‖ pool_id ‖ sender_key ‖ receiver_key ‖ amount ‖ hashlock ‖ timeout ‖ lock_nonce)
```

so claim/refund must re-derive the same `htlc_id` to find the funds — they can only ever
resolve to the **agreed** receiver/sender on the agreed terms. The leaf itself is an
ordinary `{balance, nonce}` account leaf, so the SMT, partial witness, DA blob, and the
on-chain anchor contract are all unchanged: **HTLCs are pure pool state, settled by normal
checkpoints.** Value is conserved at every step (`total` never moves; the lock fee goes to
`fee_acc`), and because the escrow leaves the sender's spendable balance immediately, the
sender **cannot double-spend** the locked funds while the swap is pending.

## The swap (dust holder Alice → LP Bob)

Classic HTLC, secret held by the party who claims first:

1. Alice picks secret `s`, `H = keccak(s)`.
2. **Pool leg** — Alice `htlc_lock`s her dust to Bob under `H`, timeout `T_pool` (long).
3. **L1/Fiber leg** — Bob locks his payment to Alice under the same `H`, timeout
   `T_L1 < T_pool`.
4. Alice claims the L1/Fiber payment by revealing `s` (before `T_L1`). `s` is now public.
5. Bob `htlc_claim`s the pool leg with `s` (before `T_pool`) and receives the in-pool dust.

If Alice never reveals `s`, both legs refund — no one loses. `T_L1 < T_pool` gives Bob the
window to claim the pool leg after Alice reveals.

## Trust & the honest caveat

Locking escrows the funds, so the **double-spend that a naive non-escrow "hash-locked
transfer" would allow** (claim L1, then keep/force-exit the in-pool balance) is closed: once
locked, the funds are only resolvable by claim or refund, neither of which leaves them with
the sender.

**Liveness limitation (documented).** An HTLC leaf is keyed by `htlc_id`, not by
`keccak(pubkey)`, so it cannot be force-exited. If the operator goes dark *while a swap is
pending*, the escrow can be neither claimed nor refunded until checkpoints resume — those
specific, in-flight dust amounts are stuck (not lost: a returning operator must honor the
escrow). This is mitigated by (a) HTLCs being short-lived and dust-sized, (b) LPs only
swapping while the operator is demonstrably live, and (c) a future **force-refund** (let the
sender force-exit a *timed-out* HTLC leaf by proving the lock terms), which would remove the
limitation entirely. The bulk of user funds — ordinary account balances — remain protected
by force-exit regardless.

## Status

* In-pool HTLC lock/claim/refund: implemented in the STF and proven (`crates/stf/tests/htlc.rs` —
  swap completion, refund, wrong preimage, claim-after-timeout, refund-before-timeout,
  receiver binding, no-double-spend). Since HTLCs are pure pool state, the on-chain contract
  is unchanged; they ride inside the normal checkpoint proof + DA.
* The L1 HTLC counterparty lock and Fiber integration are external/standard and out of scope
  here; the force-refund refinement is future work.
