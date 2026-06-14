# Integrating Liquid Cells — the generic guide

Liquid Cells is a **use-case-neutral** pooled-balance payment rollup: a ledger of `{key, balance,
nonce}` leaves where the operator provably **cannot steal, mint, censor permanently, or withhold
data**, and any user can **exit unilaterally**. It is not a tipping system, a payroll system, or any
one app — those are all *recipes* composed from the same five primitives. This guide is the generic
starting point; [INTEGRATION-TIPPING.md](INTEGRATION-TIPPING.md) is one worked instance.

A complete runnable lifecycle (no L1, no prover, ~60 lines) is in
`crates/client/examples/payment_pool.rs`:

```
cargo run -p liquid-cells-client --example payment_pool
```

## The five primitives — everything composes from these

| Op | What it does | Authority |
|---|---|---|
| **Deposit** | Credit a leaf from an L1 cell | the consumed on-chain deposit cell (no signature) |
| **Transfer** | Move `amount` (+ `fee`) between leaves | payer's signature |
| **Withdrawal** | Exit `amount` to an arbitrary L1 `target_lock_hash` | owner's signature |
| **HTLC lock / claim / refund** | Hash-time-locked in-pool escrow (swaps, conditional release, dust egress) | sender sig / preimage / timeout |
| **Fee** | Per-transfer/lock fee accrues to `fee_acc`; only the revenue-capped `fee_withdrawal` ever leaves | proven, never from a balance |

There is **no app-specific role** anywhere in the proven STF or the on-chain contract — no "platform",
"author", "employer", "buyer". You build those concepts in your own code as compositions of the above.

## Minimal integration path

1. **Pool identity.** Pick `pool_id` and `chain_id`. They **must equal the deployed anchor
   contract's baked constants** — see [DEPLOY.md](../DEPLOY.md). `Sequencer::genesis(pool_id, chain_id)`.
2. **Deposit.** Build an L1 cell under the **deposit lock** bound to the pool's anchor type hash;
   stage it through the confirmation-depth gate (`PendingDeposits`) and, once deep enough,
   `submit_deposit(Deposit { to_key, amount })`. Receiving needs no registration.
3. **Move value.** Each user holds an `Account::new(pool_id, chain_id, secret)`; `sync_from_da` to
   learn its nonce, then `transfer` / `withdraw` / `htlc_lock`, and `Sequencer::submit_*` the signed
   intent. The operator only **orders** — it cannot forge or alter a signed intent.
4. **Checkpoint.** `seal_batch(epoch, fee_withdrawal)` (or `seal_resilient`, which drops one bad
   intent instead of stalling the batch) → a `CheckpointJob`. A driver proves `job.sp1_input` to a
   Groth16 proof and submits a CKB tx pinning `job.new_anchor` and publishing `job.da_blob`.
5. **Exit / audit.** Anyone reconstructs any balance from the DA blobs alone (`latest_leaf`,
   `reconstruct_tree`); a user force-exits unilaterally with `Account::force_exit_witness` (or the
   `lc-exit` CLI) if the operator stalls.

## Recipe cookbook — compose, don't fork

| Use case | Composition (no protocol change) |
|---|---|
| **P2P payment pool** | deposit → transfer → withdrawal (the base loop) |
| **Micropayments** | many small `Transfer`s batched per checkpoint |
| **Fee split** (tipping, marketplace, affiliate, treasury rake) | `Account::split_payment(recipient, cut_recipient, gross, cut_bps, expiry)` → two transfers, exact conservation |
| **Payroll / batch disbursement / fan-out** | `Account::batch_transfer(&[(to, amt)…], fee, expiry)` → N transfers from one payer, sealed in one checkpoint; `seal_resilient` drops any bad leg |
| **Marketplace / conditional escrow** | `HtlcLock` to the seller; release by preimage, refund on timeout |
| **Swap / dust egress** (sub-61-CKB) | in-pool `HtlcLock` leg + an external L1/Fiber leg on the same hashlock; `force_refund` is the sender's escape |
| **Prepaid / gift balances** | deposit straight to the recipient's key; they sign later to spend |
| **DAO / treasury payouts** | batched `Transfer`/`Withdrawal` from a treasury key; multisig is just the L1 anchor lock |

## Hard invariants for integrators (read once)

- **You reuse the STF; you do not fork it.** The SP1 guest verifying key is fixed (`0x00213af5…`).
  Changing the state machine re-bakes the vkey and breaks every deployed pool's verifier. Your app's
  logic lives **outside** the proven STF — in client composition and your own services.
- **`pool_id` / `chain_id` must match the deployed contract**, or your checkpoints won't verify.
- **Fees never come from balances.** `fee_withdrawal` is capped at accrued fee revenue and proven, so
  an operator can't skim a user's funds to pay L1 — but it also means *you* must charge enough fee
  (or run a `FeePolicy` floor, see [FEES.md](FEES.md)) to fund checkpoints.
- **Withdrawals pay real L1 cells** (≥61 CKB occupied each); accumulate small balances and batch-exit.
- **Data availability is plaintext.** DA blobs publish `key‖balance‖nonce`; there is no amount
  privacy. If you need privacy, that is out of scope today.

## What is deliberately NOT in the protocol (keep it simple)

Streaming/rate primitives, in-pool scripting beyond HTLC, multi-asset/UDT balances, an **atomic
multi-output transfer**, and receiver-side on-chain HTLC force-claim are intentionally **out** — each
would add proven-STF surface (a vkey re-bake) for a narrow payoff. For multi-recipient atomicity in
particular, `batch_transfer` + `seal_resilient` already give de-facto per-payer settle-together
behaviour with zero protocol cost (see `crates/client/tests/batch.rs`). HTLC + an arbitrary withdrawal
`target_lock_hash` already covers trustless conditional egress. The design goal is a small, general,
reusable core — resist pushing your app's specifics into it.
