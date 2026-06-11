# Liquid Cells — Lightpaper

**A fully trustless, pooled micro-payment rollup for Nervos CKB.**

> **Status (read first):** the protocol's trust design is **complete and tested in a local
> CKB-VM**, but it is **not deployed and not audited**. It is **not usable with real funds
> today.** This document describes what has been built and proven, what remains, and what a
> grant or partnership would fund. We lead with this on purpose — see *§6 What's proven vs.
> what isn't*.

---

## 1. In one paragraph

Nervos CKB's Cell Model charges state rent: every cell must lock **~61 CKB** of capacity.
That is a good design — it is why CKB has no unbounded state bloat — but it has a hard
consequence: **a balance below ~61 CKB cannot exist on-chain.** A 0.3-CKB tip, a game ante,
a per-view streaming payment cannot be a first-class object. Liquid Cells closes that gap: a
**pooled ledger** where thousands of participants hold and move sub-61-CKB balances behind a
single anchor cell, off-chain, **with no trust in the operator** — secured by zero-knowledge
validity proofs the CKB chain verifies on-chain. It unlocks the consumer micro-payment
vertical (tipping, creator payments, gaming, streaming, micro-airdrops) that CKB's base layer
structurally cannot serve.

---

## 2. The opportunity

The highest-volume consumer crypto use cases are *many people moving tiny amounts*: tips,
creator micro-payments, in-game economies, pay-per-use streaming, micro-airdrops, loyalty
points. On CKB, **none of these are possible at Layer 1** — the 61-CKB capacity floor makes
sub-61-CKB balances uneconomical by construction. This gap is **sharper on CKB than on most
chains** (an account-model chain lets a tiny balance simply sit; CKB cannot), and it is a
direct consequence of the very property that makes CKB sustainable as a settlement layer.

CKB's existing primitives each solve part of the problem but not the **pooled, many-to-many
holding** shape:

| Primitive | What it gives | What it can't do |
|---|---|---|
| Direct L1 transfer | Native, trustless | One ≥61-CKB cell per payment — no micro-payments |
| ACP (anyone-can-pay) | Receive any amount into a *live* cell | Needs a ≥61-CKB live cell; not a pooled ledger |
| **Fiber** (payment channels) | Non-custodial routed payments, no per-payment cell | Point-to-point liquidity graph — not a shared, multi-recipient balance ledger |

Liquid Cells is the missing piece: a **pooled, multi-recipient ledger** that no current CKB
primitive provides in a trustless form. It is **complementary to Fiber, not competitive** —
in fact Liquid Cells uses atomic-swap / Fiber as its own exit ramp for dust (§4). Fiber serves
the *payment-flow* half of the consumer vertical; Liquid Cells serves the *pooled-holding*
half.

---

## 3. Why this is credible now

The usual risk for an ambitious rollup — *"can this even work?"* — is **already retired.**
The complete trust-minimization design is built and tested:

- The deterministic state machine, its **SP1 zero-knowledge proof**, and the **on-chain
  verifier** all exist and pass end-to-end. The CKB anchor type script verifies a real
  Groth16 proof **inside CKB-VM** (the RISC-V VM can run the BN254 pairing on-chain).
- All four trust guarantees (§4) are implemented and exercised adversarially:
  **55 tests** (31 native state-machine + 24 CKB-VM integration), including the negative
  cases that matter — tampered proofs, withheld data, premature exits, double-exit attempts.

This is the non-obvious strategic point: **CKB is one of the few chains where a *trustless*
pooled micro-payment ledger is technically possible at all**, because it can verify a zk proof
cheaply on-chain. The chain's own capability is what makes the solution to the chain's own gap
feasible — and we have demonstrated it works.

---

## 4. How it works, and the four guarantees

Balances live off-chain in a sparse Merkle tree anchored by **one on-chain cell**. An operator
("sequencer") orders transactions and advances the tree — but it is **powerless to cheat**.
The keystone: *the sequencer runs the exact same code the zk-proof attests*, so the two can
never disagree, and every checkpoint to L1 carries a validity proof the anchor cell verifies.

```
        off-chain                              on-chain (CKB)
   participants ── signed intents ──▶  sequencer = state machine
                                            │  builds a batch, new root
                                            ▼
                                       SP1 proof + state-diff
                                            │
                                            ▼
                                  anchor cell (pool funds)
                                  type script verifies:
                                  • the proof   • the diff is published
                                  • value conserved   • exits honored
```

The operator degrades to a pure sequencer. Four guarantees, each implemented and tested:

| Guarantee | What it kills |
|---|---|
| **Validity proofs** — every state change carries a zk proof the anchor verifies | Theft, balance inflation, forged or stale settlement — *impossible by construction*, no fraud-proof game |
| **On-chain data availability** — each checkpoint publishes the state diff, bound to the proof | Data withholding — any user can rebuild their balance and an exit proof from L1 alone |
| **Force-exit / escape hatch** — after operator silence, any user withdraws unilaterally against the last committed state | Censorship / freezing — the operator cannot trap funds by going dark |
| **Atomic-swap egress** — hash-locked swaps move sub-61-CKB balances out without a 61-CKB cell | Dust entrapment — small balances have a trustless exit, at any denomination |

The only trust assumptions are cryptographic hardness and CKB Layer 1 itself — the same base
as any on-chain transaction.

---

## 5. Roadmap

| Stage | Deliverable | State |
|---|---|---|
| Trust design | State machine + zk proof + on-chain verifier + all four guarantees, tested | **done** |
| Testnet deploy | Anchor + code cell on Pudge; sequencer builds real checkpoint transactions | next |
| **External audit** | Independent review of the state machine + contract | **gates mainnet** |
| Egress integration | L1 HTLC counterparty + Fiber payment leg for dust swaps | planned |
| Throughput | Permissionless sequencing + anchor sharding (remove single-anchor contention) | planned |
| Wallet / app integration | SDK + reference tipping / creator / game integrations | planned |

---

## 6. What's proven vs. what isn't (the honest part)

Sophisticated reviewers have seen enough vaporware to value candor. Here it is.

**Proven / de-risked**
- The full trust design is implemented and adversarially tested (55 tests).
- The Groth16 proof is verified **on-chain in CKB-VM** — not a spec, running code.
- The four guarantees are exercised including their attack cases.

**Not yet — and why each matters**
- **Unaudited.** A validity proof attests that the program *ran* correctly, **not that the
  program is correct.** Closing that gap is an external audit's job and is the hard gate
  before any real value. *(Fundable milestone.)*
- **Local-only.** Verified in a faithful local CKB-VM, not yet on a public testnet. *(Fundable.)*
- **Trusted setup.** The Groth16 proving system inherits a trusted-setup assumption; this is a
  real, named assumption, mitigated by using an established public ceremony.
- **Throughput.** All checkpoints currently serialize through one anchor cell, and each carries
  a fixed on-chain verification cost. The design is suited to *high-volume batched* throughput;
  removing single-anchor contention is planned (sharding), not built.
- **Egress liveness.** A pending atomic-swap escrow relies on the operator resuming to settle;
  a documented refinement (force-refund of a timed-out swap) removes the last edge.

None of these are unknowns — they are scoped, named, and on the roadmap.

---

## 7. Non-goals (v1)

- **Privacy** — on-chain data availability reveals transfer diffs. A future version can add
  encrypted DA + amount-hiding proofs.
- **General smart contracts** — Liquid Cells is a focused pooled-payment rollup, not an EVM/L2
  platform. The narrow surface is deliberate: it keeps the trust story simple.

---

## 8. The ask

A grant or partnership would fund the path from *proven design* to *production primitive*:

1. **External security audit** of the state machine and on-chain contract — the mainnet gate.
2. **Testnet → mainnet deployment**, plus the sequencer and liquidity-provider infrastructure.
3. **Egress integration** with Fiber / atomic-swap liquidity for dust exits.
4. **Wallet and application integrations** (SDK + reference tipping / creator / gaming apps) to
   bring CKB the consumer micro-payment vertical it cannot serve today.

> _Specifics — funding amount, milestone timeline, team, and any existing ecosystem
> conversations — to be completed by the project lead._

---

*Liquid Cells is pre-alpha, local-only, and unaudited. Nothing here is an offer or a
recommendation to deposit funds. Deep technical documentation lives alongside the code
(`docs/ARCHITECTURE.md`, `THREAT-MODEL.md`, `DA.md`, `FORCE-EXIT.md`, `EGRESS.md`).*
