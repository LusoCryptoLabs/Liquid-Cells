# Liquid Cells, Lightpaper

**An operator-trustless, pooled micro-payment rollup for Nervos CKB.**

> **Status (read first):** the protocol's trust design is **complete, tested, and live on the
> CKB Pudge testnet**: the anchor type script verifies real SP1 Groth16 proofs inside CKB-VM on
> a public chain, the sequencer has landed a chain of successive checkpoints, and sequencing is
> **permissionless** (a checkpoint that nobody signed has advanced the root on-chain). It is
> **testnet-only and not audited**, so it is **not usable with real funds today.** We lead with
> this on purpose, see *§6 What's proven vs. what isn't*. It has passed an internal adversarial
> red-team (56 cases, no break); suspected vulnerabilities go through private, coordinated
> disclosure, see [SECURITY.md](SECURITY.md).

---

## 1. In one paragraph

Nervos CKB's Cell Model charges state rent: every cell must lock **~61 CKB** of capacity.
That is a good design, it is why CKB has no unbounded state bloat, but it has a hard
consequence: **a balance below ~61 CKB cannot exist on-chain.** A 0.3-CKB tip, a game ante,
a per-view streaming payment cannot be a first-class object. Liquid Cells closes that gap: a
**pooled ledger** where thousands of participants hold and move sub-61-CKB balances behind a
single anchor cell, off-chain, **with no trust in the operator**, secured by zero-knowledge
validity proofs the CKB chain verifies on-chain. It unlocks the consumer micro-payment
vertical (tipping, creator payments, gaming, streaming, micro-airdrops) that CKB's base layer
structurally cannot serve.

---

## 2. The opportunity

The highest-volume consumer crypto use cases are *many people moving tiny amounts*: tips,
creator micro-payments, in-game economies, pay-per-use streaming, micro-airdrops, loyalty
points. On CKB, **none of these are possible at Layer 1**, the 61-CKB capacity floor makes
sub-61-CKB balances uneconomical by construction. This gap is **sharper on CKB than on most
chains** (an account-model chain lets a tiny balance simply sit; CKB cannot), and it is a
direct consequence of the very property that makes CKB sustainable as a settlement layer.

CKB's existing primitives each solve part of the problem but not the **pooled, many-to-many
holding** shape:

| Primitive | What it gives | What it can't do |
|---|---|---|
| Direct L1 transfer | Native, trustless | One ≥61-CKB cell per payment, no micro-payments |
| ACP (anyone-can-pay) | Receive any amount into a *live* cell | Needs a ≥61-CKB live cell; not a pooled ledger |
| **Fiber** (payment channels) | Non-custodial routed payments, no per-payment cell | Point-to-point liquidity graph, not a shared, multi-recipient balance ledger |

Liquid Cells is the missing piece: a **pooled, multi-recipient ledger** that no current CKB
primitive provides in a trustless form. It is **complementary to Fiber, not competitive**, 
in fact Liquid Cells uses atomic-swap / Fiber as its own exit ramp for dust (§4). Fiber serves
the *payment-flow* half of the consumer vertical; Liquid Cells serves the *pooled-holding*
half.

---

## 3. Why this is credible now

The usual risk for an ambitious rollup, *"can this even work?"*, is **retired, on a public
chain.** The complete trust-minimization design is built, tested, and deployed:

- The deterministic state machine, its **SP1 zero-knowledge proof** wrapped to Groth16, and the
  **on-chain verifier** all exist and pass end-to-end. The CKB anchor type script verifies a
  real BN254 pairing proof **inside CKB-VM on the live Pudge testnet**, not in a simulator.
  The on-chain verifier uses **ark-bn254** (a plain 4-pairing Groth16 check) at **~80M cycles,
  ~2.3% of CKB's ~3.50B block limit**, with the same proofs verifying and all 40 contract tests
  green. (An earlier `substrate-bn` verifier needed a 3-pairing `e(alpha,beta)` precompute just to
  fit at ~3.47B; the ark port cut that ~43x.) We make **no strong novelty claim**, on-chain Groth16
  on CKB is well-precedented (sec-bit's ckb-zkp), an SP1-verifier-for-ckb-vm effort is active, and
  sec-bit's Clover is a zkRollup on the same cell model. See
  [docs/PRIOR-ART.md](docs/PRIOR-ART.md) for the honest side-by-side positioning.
- The **sequencer runs the exact same state machine the proof attests**, and it has sealed and
  landed a chain of **successive checkpoints** on Pudge, each carrying its own on-chain proof.
- Sequencing is **permissionless**: with a permissive anchor lock and an on-chain lock-continuity
  rule, anyone with a valid proof can advance the root. A checkpoint that carried **no signature
  at all** has advanced a live pool, gated only by the proof.
- All trust guarantees (§4) are implemented and exercised adversarially across **80+ tests**
  spanning the state machine, the on-chain contract, the sequencer, and the client, including
  the negative cases that matter: tampered proofs, withheld data, premature exits, double-exit
  and capture attempts.

This is the non-obvious strategic point: **CKB is one of the few chains where a *trustless*
pooled micro-payment ledger is technically possible at all**, because it can verify a zk proof
cheaply on-chain. The chain's own capability is what makes the solution to the chain's own gap
feasible, and we have demonstrated it works on the public testnet.

---

## 4. How it works, and the guarantees

Balances live off-chain in a sparse Merkle tree anchored by **one on-chain cell**. An operator
("sequencer") orders transactions and advances the tree, but it is **powerless to cheat**, and
under permissionless sequencing it is not even privileged: anyone with a valid proof can take
its place. The keystone: *the sequencer runs the exact same code the zk-proof attests*, so the
two can never disagree, and every checkpoint to L1 carries a validity proof the anchor cell
verifies.

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

The operator degrades to a pure, replaceable sequencer. The guarantees, each implemented and
tested:

| Guarantee | What it kills |
|---|---|
| **Validity proofs**, every state change carries a zk proof the anchor verifies | Theft, balance inflation, forged or stale settlement, *impossible by construction*, no fraud-proof game |
| **On-chain data availability**, each checkpoint publishes the state diff, bound to the proof | Data withholding, any user can rebuild their balance and an exit proof from L1 alone |
| **Force-exit / escape hatch**, after operator silence, any user withdraws unilaterally against the last committed state | Censorship / freezing, the operator cannot trap funds by going dark |
| **Atomic-swap egress** (+ a sender force-refund for timed-out swaps), hash-locked swaps move sub-61-CKB balances out without a 61-CKB cell | Dust entrapment, small balances have a trustless exit, at any denomination |
| **Permissionless sequencing**, a permissive anchor lock + lock continuity let anyone advance the root, with a fee reward so it is self-sustaining | A privileged operator, sequencing is open and capture-proof |

The only trust assumptions are cryptographic hardness and CKB Layer 1 itself, the same base
as any on-chain transaction.

---

## 5. Roadmap

| Stage | Deliverable | State |
|---|---|---|
| Trust design | State machine + zk proof + on-chain verifier + all guarantees, tested | **done** |
| Testnet deploy | Anchor + code cell on Pudge; real checkpoints with the proof verified on live CKB-VM | **done** |
| Sequencer + client | Off-chain sequencer sealing successive checkpoints; a client SDK to sign intents and exit from L1 data | **done** |
| Permissionless + reward + sharding | Anyone may sequence (lock continuity), a fee reward makes it self-sustaining, K independent pools for throughput | **done** |
| **External audit** | Independent review of the state machine + contract | **gates mainnet** |
| Egress integration | L1 HTLC counterparty + Fiber payment leg for dust swaps | planned |
| Wallet / app integration | TS/WASM SDK + reference tipping / creator / game integrations | planned |

---

## 6. What's proven vs. what isn't (the honest part)

Sophisticated reviewers have seen enough vaporware to value candor. Here it is.

**Proven / de-risked**
- The full trust design is implemented and adversarially tested (80+ tests).
- The Groth16 proof is verified **on-chain in a live CKB block on Pudge**, not a spec, running code.
- The sequencer has landed **successive** checkpoints on-chain, and an **unsigned, permissionless**
  checkpoint has advanced a live pool. The guarantees are exercised including their attack cases.

**Not yet, and why each matters**
- **Unaudited.** A validity proof attests that the program *ran* correctly, **not that the
  program is correct.** Closing that gap is an external audit's job and is the hard gate
  before any real value. *(Fundable milestone.)*
- **Testnet only.** Live on Pudge, not mainnet; no real funds. *(Fundable.)*
- **Trusted setup.** The Groth16 proving system inherits a trusted-setup assumption; this is a
  real, named assumption, mitigated by using an established public ceremony.
- **Throughput at scale.** Sharding (K independent pools) is built, so throughput scales by
  running more pools, but it has not been stress-tested at production volume, and each checkpoint
  still carries a fixed on-chain verification cost.
- **Egress, receiver side.** The sender of a timed-out atomic swap can now force-refund on-chain;
  the symmetric receiver "force-claim" is not expressible under a single anchor (a documented,
  architectural residual), so the receiver still relies on the operator being live across the
  short swap window.

None of these are unknowns, they are scoped, named, and on the roadmap.

---

## 7. Non-goals (v1)

- **Privacy**, on-chain data availability reveals transfer diffs. A future version can add
  encrypted DA + amount-hiding proofs.
- **General smart contracts**, Liquid Cells is a focused pooled-payment rollup, not an EVM/L2
  platform. The narrow surface is deliberate: it keeps the trust story simple.

---

## 8. The ask

A grant or partnership would fund the path from *proven, live-on-testnet primitive* to
*production primitive*:

1. **External security audit** of the state machine and on-chain contract, the mainnet gate.
2. **Mainnet deployment**, plus the production sequencer and liquidity-provider infrastructure.
3. **Egress integration** with Fiber / atomic-swap liquidity for dust exits.
4. **Wallet and application integrations** (TS/WASM SDK + reference tipping / creator / gaming
   apps) to bring CKB the consumer micro-payment vertical it cannot serve today.

> _Specifics, funding amount, milestone timeline, team, and any existing ecosystem
> conversations, to be completed by the project lead._

---

*Liquid Cells is pre-alpha, testnet-only, and unaudited. Nothing here is an offer or a
recommendation to deposit funds. Deep technical documentation lives alongside the code
(`docs/ARCHITECTURE.md`, `THREAT-MODEL.md`, `DA.md`, `FORCE-EXIT.md`, `EGRESS.md`, `DEPLOY.md`).*
