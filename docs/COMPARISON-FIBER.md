# Liquid Cells vs. Fiber: an honest comparison

> **Intent:** Fiber and Liquid Cells are **complementary**, not rivals. This doc states, plainly and
> with concessions, why a shared pool is a good fit for long-tail microtipping, where Fiber wins, and
> where the two compose. It is written to be attackable by a Fiber/Lightning expert without falling
> over. Status: Liquid Cells is testnet-only and unaudited; some items below are roadmap, marked as
> such. _Working draft._

## TL;DR

This is **not** "pool vs. payment channels." Any channel design that lets thousands of sporadic,
long-tail recipients *receive* without each funding a channel does so via a **hub** that provisions
inbound liquidity. So the real comparison is **non-custodial pool vs. hub**, and the question is what
kind of hub.

- The **channel-free** Fiber tipping design that exists today is a **custodial hub with an internal
  ledger**, which is exactly how the community's [Fiber Link](https://talk.nervos.org/t/dis-fiber-link-a-ckb-fiber-based-pay-layer-tipping-micropayments-for-communities/9845)
  proposal describes itself, and what Scryve's own first-iteration custodial tipping is.
- **Liquid Cells is the non-custodial version of that hub:** the operator cannot steal or inflate
  (on-chain validity proof), every balance is reconstructable from on-chain data, and any user can
  force-exit unilaterally.

We do **not** claim a novelty win (on-chain Groth16 on CKB is precedented; see
[PRIOR-ART.md](PRIOR-ART.md)) or a raw on-chain-cost win. The claim is narrow: **for long-tail,
sporadic, many-recipient inbound, a non-custodial pool gives the "receiving is just a ledger entry"
UX with strictly stronger trust than a custodial hub.**

## The four models

| Axis | Fiber (channels + hub/LSP) | Liquid Cells (non-custodial pool) |
|---|---|---|
| **Trust** | No operator for a *direct* channel, and a direct channel is more decentralized than us. But channel-free long-tail receiving needs a hub, and the one that exists today is custodial. | One operator, but provably non-custodial: cannot steal/mint (validity proof), balances reconstructable from on-chain data, unilateral exit. Adds a single upgrade key (being locked down). |
| **Liveness** | Direct channels are peer-to-peer; safety needs you online or a (third-party) watchtower. | Operator advances checkpoints (a central liveness dependency), with unilateral force-exit as the floor; ordinary users carry no online burden. |
| **Exit** | Close a channel you already hold; cooperative close is fast. | Withdraw anytime via the operator; emergency force-exit only after a ~30-day operator-silence window, and it lands a ≥61-CKB cell, so exiting dust is the weak spot today. |
| **Liquidity / receiving** | The inbound-liquidity problem: channel-free receiving needs a hub/LSP. Lightning has these; for Fiber they are on the 2026 roadmap, not yet shipped. | Zero per-user and per-creator liquidity; receiving is a ledger entry; one shared anchor cell amortized across everyone. |

## The precise constraint (and the rebuttal it must survive)

A naive claim, "each recipient needs their own ≥61-CKB channel", is **false**, and a Fiber expert
would rightly demolish it: **LSPs / hubs** provision inbound liquidity so end users do not each open a
channel. The honest, surviving form:

- To give long-tail recipients a **channel-free "just receive"** experience, you need a hub.
- The hub that exists for Fiber tipping today is **custodial** (internal ledger). On CKB each channel
  the hub *does* open is a 2-of-2 funding cell subject to the per-cell minimum, but the dominant point
  is the **trust profile of the hub**, not per-cell cost.
- Liquid Cells offers the same channel-free receiving UX, but the hub is **validity-constrained**: it
  cannot forge balances, and users can exit without it.

## Where Fiber wins (concede freely)

- **Decentralization in the steady state** for two parties with a direct channel.
- **Finality:** off-chain channel payments are effectively instant and final between the parties;
  Liquid Cells has ~7-min checkpoint finality (soft-confirmation is planned, not shipped).
- **Dust exit / egress:** closing a channel you hold is cleaner than our ≥61-CKB exit-cell floor.
- **A single high-volume, always-online creator with two-way flow** is better served by a direct
  channel (cheaper, more private) than by routing tips through any pool.
- **Maturity:** Fiber is on CKB mainnet (Feb 2025); Liquid Cells is testnet and experimental.
- **Raw on-chain cost:** a mature hub-and-channel-factory Fiber could be cheaper per tip than periodic
  zk-checkpoints. We compete on trust model and long-tail receiving UX, not satoshis on-chain.

## Where they compose

Liquid Cells' designed path for moving a **sub-61-CKB** balance *out* of the pool is an **atomic swap
sharing one hashlock with a Fiber leg**, i.e. Fiber is the intended egress rail.

> **Status (honest):** this is **design and roadmap, not shipped.** The in-pool escrow leg (hash-lock
> + sender-side refund) is built and tested; the Fiber integration, the liquidity-provider side, and
> the receiver-side force-claim are **not built**. See [EGRESS.md](EGRESS.md) and ROADMAP Tier E.

So the honest framing is layered, not competitive: a pool is good at accounting for many tiny balances
and at letting anyone receive without liquidity; Fiber is good at routed, peer-to-peer settlement and
interop, including as our dust-egress rail.

## Our residuals (so this isn't one-sided)

Testnet-only and unaudited; single upgrade key (timelock built, not adopted); ~7-min finality;
~30-day force-exit window and ≥61-CKB exit floor; plaintext DA (no amount privacy); operator liveness
for everyday progress; archival DA retention for recovery. Full list in
[SPEC.md §12](SPEC.md) and [NON-CUSTODY.md](NON-CUSTODY.md).

## References

- Fiber Network light paper, https://github.com/nervosnetwork/fiber/blob/main/docs/light-paper.md
- Fiber Link (custodial-hub tipping proposal), https://talk.nervos.org/t/dis-fiber-link-a-ckb-fiber-based-pay-layer-tipping-micropayments-for-communities/9845
- Fiber 2026 outlook (liquidity solutions are roadmap), https://talk.nervos.org/t/fiber-protocol-complete-network-tested-development-status-challenges-and-2026-outlook/9827
- ckb-zkp (prior art: Groth16 on CKB), https://github.com/sec-bit/ckb-zkp
- CKB cell minimum, https://docs.nervos.org/docs/getting-started/how-ckb-works
- Liquid Cells non-custody & exit, [NON-CUSTODY.md](NON-CUSTODY.md), [FORCE-EXIT.md](FORCE-EXIT.md), [DA.md](DA.md)

---

_Working draft. The four-model table and the hub-symmetry argument are the load-bearing parts and are
intended to stay; expand with concrete numbers (per-tip cost, snapshot/reconstruction cost) once the
benchmark and a Fiber-side cost reference exist._
