# Dust Egress via Atomic Swap (Phase 5)

Force-exit ([FORCE-EXIT.md](FORCE-EXIT.md)) gives any holder a trustless way out, but it
produces a single L1 cell, which needs **~61 CKB** of capacity. A sub-61-CKB balance can't
become its own cell; that's physics, not a trust choice. So the *normal* exit for small
balances is not a self-cell, it's a **hash-locked atomic swap**: the dust stays in the pool
(it moves to a liquidity provider), and the LP pays the user on L1 or over Fiber, with no
denomination floor, and fully trustlessly because the two legs share one preimage.

## The in-pool HTLC

This repo implements the **in-pool leg**: a hash-time-locked escrow inside the pool state
(the L1 leg is a standard CKB HTLC lock or a Fiber hop, external). Three STF operations:

* **`htlc_lock`**, the sender signs an escrow of `amount` (+fee) to a receiver under a
  `hashlock` with a `timeout`. The funds leave the sender's account and live as a leaf at
  `htlc_id`.
* **`htlc_claim`**, anyone revealing the preimage (`keccak(preimage) == hashlock`) before
  `timeout` moves the escrow to the receiver.
* **`htlc_refund`**, at/after `timeout`, the escrow returns to the sender.

The escrow leaf's key commits to **every** term:

```
htlc_id = keccak(DOMAIN ‖ pool_id ‖ sender_key ‖ receiver_key ‖ amount ‖ hashlock ‖ timeout ‖ lock_nonce)
```

so claim/refund must re-derive the same `htlc_id` to find the funds, they can only ever
resolve to the **agreed** receiver/sender on the agreed terms. The leaf itself is an
ordinary `{balance, nonce}` account leaf, so the SMT, partial witness, DA blob, and the
on-chain anchor contract are all unchanged: **HTLCs are pure pool state, settled by normal
checkpoints.** Value is conserved at every step (`total` never moves; the lock fee goes to
`fee_acc`), and because the escrow leaves the sender's spendable balance immediately, the
sender **cannot double-spend** the locked funds while the swap is pending.

## The swap (dust holder Alice → LP Bob)

Classic HTLC, secret held by the party who claims first:

1. Alice picks secret `s`, `H = keccak(s)`.
2. **Pool leg**, Alice `htlc_lock`s her dust to Bob under `H`, timeout `T_pool` (long).
3. **L1/Fiber leg**, Bob locks his payment to Alice under the same `H`, timeout
   `T_L1 < T_pool`.
4. Alice claims the L1/Fiber payment by revealing `s` (before `T_L1`). `s` is now public.
5. Bob `htlc_claim`s the pool leg with `s` (before `T_pool`) and receives the in-pool dust.

If Alice never reveals `s`, both legs refund, no one loses. `T_L1 < T_pool` gives Bob the
window to claim the pool leg after Alice reveals.

## Trust & the honest caveat

Locking escrows the funds, so the **double-spend that a naive non-escrow "hash-locked
transfer" would allow** (claim L1, then keep/force-exit the in-pool balance) is closed: once
locked, the funds are only resolvable by claim or refund, neither of which leaves them with
the sender.

**The liveness question, and what `force-refund` does and does not fix.** An HTLC leaf is
keyed by `htlc_id`, not by `keccak(pubkey)`, so the ordinary account-leaf force-exit cannot
reach it. If the operator goes dark *while a swap is pending*, the cooperative claim/refund
paths can't run. The two parties are **not symmetric** under a single anchor, and being honest
about that matters:

* **Sender side, closed by `force-refund` (implemented).** After the HTLC `timeout`, the
  receiver can no longer claim (claim-after-timeout is invalid), so refund-to-sender is the
  *only* valid resolution. The on-chain **force-refund** mode lets the sender unilaterally
  reclaim a timed-out escrow against the last committed root by supplying the lock terms, the
  script re-derives `htlc_id`, proves the escrow leaf's SMT inclusion, nullifies it, and forces
  the payout to the sender's own secp lock. Gated by **both** `since ≥ timeout` (so no live
  claim is robbed) and the operator-silence window (so it is an escape hatch, not a routine
  race with the cooperative refund). Like force-exit it pays out to L1, so it inherits the
  **61-CKB cell floor**: it fully closes the escape for ≥61-CKB escrows; a sub-61-CKB escrow
  cannot become its own L1 cell (that is the universal dust constraint, not a new one).

* **Receiver side, *not* expressible under a single anchor (architectural residual).** The
  symmetric "force-claim" (the receiver reveals the preimage and pulls a still-live escrow)
  would have to fire *before* the HTLC `timeout`, i.e. within hours. But any anchor-consuming
  op conflicts with a live operator's checkpoint, so an escape hatch **must** be gated on the
  operator-silence window (~180 epochs ≈ 30 days), exactly as force-exit is; otherwise it is a
  cheap way to invalidate the operator's in-flight (proven, expensive) checkpoints at will. A
  silence-gated claim can never open inside a dust HTLC's short lifetime, so a receiver's
  trustless on-chain claim is **not** giveable here. This is a property of the **single-anchor**
  architecture, not a coding gap: it is what Phase 6 (permissionless sequencing / anchor
  sharding) removes, by ending the checkpoint-vs-escape-hatch conflict.

So `force-refund` does **not** "remove the limitation entirely" (an earlier draft overstated
it): it closes the *sender's* exposure for ≥61-CKB escrows. The *receiver's* protection still
rests on the operator being live across the short swap window, mitigated by (a) HTLCs being
short-lived and dust-sized, (b) LPs only swapping while the operator is demonstrably live, and
(c) the swap's timeout ordering (`T_L1 < T_pool`), which bounds the receiver's exposure to the
pool-leg window. The bulk of user funds, ordinary account balances, remain protected by
force-exit regardless of any of this.

## Status

* In-pool HTLC lock/claim/refund: implemented in the STF and proven (`crates/stf/tests/htlc.rs`, 
  swap completion, refund, wrong preimage, claim-after-timeout, refund-before-timeout,
  receiver binding, no-double-spend). Since HTLCs are pure pool state, the checkpoint contract
  is unchanged; they ride inside the normal checkpoint proof + DA.
* **On-chain force-refund: implemented** as a third anchor mode in the type script
  (`crates/ckb-contract/src/main.rs::force_refund`) and tested adversarially
  (`crates/ckb-contract-tests/tests/forcerefund.rs`, 9 cases: timed-out refund verifies;
  before-silence, before-HTLC-timeout, wrong receiver, tampered amount, wrong/missing payout,
  unnullified root, and bad total all reject). It carries no SP1 proof, like force-exit it is a
  pure SMT-inclusion path against the committed root, so the STF and the baked vkey are
  unchanged.
* The L1 HTLC counterparty lock and Fiber integration are external/standard and out of scope
  here. The receiver-side residual above is resolved by Phase 6, not by additional code in this
  mode.
