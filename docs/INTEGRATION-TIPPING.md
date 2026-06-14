# Integrating Liquid Cells as a tipping backend

A worked mapping for a CKB-native creator-tipping platform (e.g. a custodial CKB-balance ledger like
**scryve**) to replace "trust the platform's database" with "the platform provably can't steal or
mint, and creators can always exit." The UX is unchanged — instant off-chain balance updates,
periodic on-chain finality — but the trust model flips to the four pillars (validity proof + DA +
force-exit + no-steal/no-mint).

> This is **one worked instance** of the general integration. For the use-case-neutral starting point
> — the five primitives, a recipe cookbook, and the reuse invariants — see
> **[INTEGRATION-GENERIC.md](INTEGRATION-GENERIC.md)**. Tipping is just `deposit + split_payment + exit`.

The end-to-end flow below is exercised as a test: `crates/client/tests/tipping.rs`.

| Platform operation | Liquid Cells SDK / flow |
|---|---|
| **Fund a tipping balance** (user deposits CKB) | Create a deposit cell under the **deposit lock** bound to the pool's anchor type hash; the operator's L1 watcher stages it through the **confirmation-depth gate** (`PendingDeposits`, M4) and, once `depth`-deep, `Sequencer::submit_deposit` it; sealed into a checkpoint. |
| **Tip an author with a platform cut** | `Account::split_payment(recipient_key, cut_recipient_key, gross, cut_bps, expiry)` (recipient = author, cut recipient = platform) → two signed `Transfer`s (author gets `gross − cut`, platform gets `floor(gross·bps/10000)`, exact conservation); submit both; `Sequencer::seal_resilient` seals them (one bad intent never stalls the batch). `split_payment` is a **generic** fee-split (not tipping-specific). For a *protocol* fee into `fee_acc`, pass a non-zero per-transfer `fee` instead. |
| **Show / audit balances** | Anyone reconstructs any key's balance from the published DA blobs alone: `latest_leaf(&blobs, &key)` / `reconstruct_tree(&blobs)` — no trust in the operator's DB. |
| **Author/platform withdraw to L1** | `Account::withdraw(target_lock_hash, amount, expiry)` → a checkpoint withdrawal paying an on-chain cell (≥61 CKB per output; accumulate then batch-withdraw, as scryve's payout engine already does). Withdrawing does **not** close the account — it keeps receiving tips. |
| **Operator can't trap funds** | If the operator stalls, a creator force-exits unilaterally: `lc-exit` (or `Account::force_exit_witness`) reconstructs the leaf from L1 and emits the force-exit witness — proven live (see DEPLOY.md). |

## Why this is a strict upgrade over a custodial ledger
- **No-steal / no-mint:** every tip is a signed STF transfer proven on-chain; the operator can't move a user's funds without their signature or invent balances.
- **Always-exit:** force-exit against the last committed root recovers a creator's balance even if the platform disappears.
- **Same UX, same currency:** CKB-denominated tips (scryve is already CKB-native), instant off-chain, batched to checkpoints — the platform cut is just a second transfer in the same batch.

## Scope notes
- Liquid Cells covers the **CKB** tipping leg only; fiat (Stripe) and other-chain rails are separate.
- **Testnet-only, unaudited today** — a testnet pilot is the right first step (see ROADMAP); the
  platform runs the sequencer/prover (the ~7-min proof → batch tips per checkpoint; GPU/prover-network
  for a tighter cadence).
- Sub-61-CKB *cash-out* to external wallets needs the HTLC/Fiber egress (in progress); in-pool tips
  and accumulate-then-withdraw have no such floor.
