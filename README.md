# Liquid Cells

**An operator-trustless, pooled micro-payment rollup for Nervos CKB.**

> New here? The **[lightpaper](LIGHTPAPER.md)** is the 5-minute overview (problem, trust
> model, status, roadmap). This README is the developer entry point.

Liquid Cells lets many participants hold and move sub-1-CKB balances off-chain, 
tips, game antes, creator micro-payments, anchored by a single on-chain cell,
with **no trust in the operator**. It is a zk-rollup (validity proofs + on-chain
data availability), not a custodial pool: the sequencer cannot steal, cannot
inflate balances, cannot censor permanently, and cannot withhold the data users
need to exit. The only trust assumptions are cryptographic hardness and CKB Layer 1
itself, the same base as any on-chain transaction.

> Status: **Live on Pudge testnet, pre-alpha.** The deterministic STF, its SP1 proof
> wrapped to Groth16, and the on-chain anchor type script are implemented and tested
> end-to-end (80 STF + 111 contract integration tests): proof verification on CKB-VM bound to real
> deposit/withdrawal cells, value conservation, a proven L1 fee model, **data availability**,
> a **force-exit escape hatch**, **in-pool HTLCs** for atomic-swap dust egress, and an
> on-chain **force-refund** hatch that lets a swap's sender unilaterally reclaim a timed-out
> escrow. An off-chain **sequencer loop** (`crates/sequencer`) seals **successive** checkpoints
> off the same STF, so the chain composes past the first one. **It is
> now deployed on the CKB Pudge testnet: a genesis pool was created and a first checkpoint
> landed with the SP1 Groth16 BN254 proof verified on live CKB-VM** ([DEPLOY.md](DEPLOY.md)).
> The on-chain verifier uses **ark-bn254**: a plain 4-pairing Groth16 check measured at **~80M
> cycles (~2.3% of CKB's ~3.50B block limit)**, with the same SP1 proofs verifying and the
> contract suite green. (It previously used `substrate-bn` and needed a 3-pairing `e(alpha,beta)`
> precompute just to fit at ~3.47B = 99.3%; the port to `ark-bn254` cut that ~43x and removed the
> hack, see [docs/PRIOR-ART.md](docs/PRIOR-ART.md).) What remains to be a usable system (not more
> cryptography): a client SDK, the L1/Fiber swap leg, throughput (Phase 6), and, before any real
> value, an external audit. Testnet only, unaudited.

> **Hardening.** A production-hardening pass added a differential test of the hand-ported ark
> verifier (vs the independent substrate-bn implementation, over a fuzzed corpus), an STF fuzzer
> with an independent shadow ledger, a crash-tolerant sequencer replay journal, a deposit lock that
> closes the always-success theft window (**deployed and verified live on Pudge**: a third-party
> spend was rejected on-chain, a refund accepted, and a deposit bound to a type-id'd pool's unique
> anchor hash **swept end-to-end by a Groth16-proven checkpoint that advanced that pool seq 0 → 1**),
> and session-key recovery. See **[HARDENING.md](HARDENING.md)**
> for the work and the honest, audit-aside roadmap to mainnet.

> **Security.** An internal adversarial red-team ran **56
> adversarial cases** (in CKB-VM + the STF in-process) across accounting, escape hatches, the deposit lock, and the STF, no
> exploitable break found; they live as permanent regression tests (`redteam_*.rs`), with findings
> in **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)**. Suspected vulnerabilities go through **private,
> coordinated disclosure**, see **[SECURITY.md](SECURITY.md)**. Testnet-only and unaudited; an
> external audit is the next step before any real-value use.

> **Honest positioning (prior art).** This is a working *implementation*, not a novel protocol.
> Nearly every ingredient has prior art, much of it on CKB: sec-bit's **Clover** (a zkRollup on the
> same CKB cell model), Ethereum's **Intmax2** (a pooled, payment-focused zk-rollup with
> client-side proofs), **ckb-zkp** (on-chain Groth16 verification on CKB-VM, ~77M cycles), the
> optimistic **Godwoken**, payment-channel **Fiber** (live, serves CKB micropayments), and an
> active **SP1-verifier-for-ckb-vm** effort. The contribution here is engineering and integration
> on a live chain, plus a couple of CKB-idiomatic choices. See
> **[docs/PRIOR-ART.md](docs/PRIOR-ART.md)** for the side-by-side comparison and what narrowly
> differs.

---

## Why it exists

On CKB every Layer-1 state change consumes and creates cells, and a standard cell
needs **~61 CKB** of capacity. That makes direct micro-payments uneconomical, you
cannot give someone a 0.25-CKB tip as its own cell. Existing primitives each solve
part of the problem:

| Primitive | Strength | Gap Liquid Cells fills |
|---|---|---|
| Direct transfer | Native, trustless | One L1 cell per payment; no micro-payments |
| ACP | Receive any amount into a live cell | Needs a live recipient cell; not a pooled ledger |
| Fiber | Non-custodial, routed channel payments | Point-to-point liquidity graph, not pooled multi-recipient |
| Open Transaction | Aggregation primitive | Not a persistent balance protocol |

Liquid Cells is the missing piece: a **pooled, multi-recipient ledger** where
balances live off-chain in a sparse Merkle tree, every transition is proven correct,
and any user can always recover their funds, combined with **Fiber/atomic-swap
egress** so even dust balances have a trustless way out.

---

## The keystone idea: the sequencer *is* the zk guest

There is exactly one implementation of the state-transition function, the
[`liquid-cells-stf`](crates/stf) crate. The same bytes are:

```
liquid_cells_stf::apply(state, batch) -> (new_root, PublicValues)
   ├─ sequencer:  run natively to advance the root, serve the API, post DA
   └─ SP1 guest:  prove the identical run -> Groth16 -> CKB anchor verifies it
```

Because both run identical code, they can never disagree on a root, and the proof
attests the two invariants the protocol's safety rests on (enforced in
[`transition.rs`](crates/stf/src/transition.rs)):

1. **No debit without a signature**, a leaf's balance only decreases via a
   `Transfer`/`Withdrawal` carrying a valid secp256k1 signature from that leaf's owner.
2. **Value conservation**, `Σ balances + fees == total`, and
   `new_total == prev_total + Σ deposits − Σ withdrawals`.

Together these make operator theft and balance inflation *impossible*, not merely
disputable. There is no fraud-proof game to get wrong.

---

## Trust model, the four pillars

| # | Pillar | What it kills |
|---|---|---|
| 1 | **Validity proofs**, every root transition carries an SP1→Groth16 proof the anchor type script verifies | Forged transitions, balance inflation, stale-root settlement, the need for honest watchers |
| 2 | **On-chain data availability**, each checkpoint posts the compressed state diff in tx **witnesses** (fee-priced, not capacity-locked) | Data withholding; every user can always reconstruct their leaf + proof from L1 alone |
| 3 | **Permissionless escape hatch**, after operator silence for `T` epochs, anyone force-exits against the last committed root with a plain SMT inclusion proof | Liveness capture; the operator cannot freeze funds by going dark |
| 4 | **Atomic-swap / Fiber egress**, hash-locked swaps move any-size balances out without a 61-CKB cell | Dust entrapment, while staying fully trustless (the swap is atomic) |

The operator degrades to a **sequencer**: it can order transactions and be live,
nothing more.

### The 61-CKB reality (stated plainly)

A balance below ~61 CKB cannot become its *own* L1 cell, that is physics, not a
trust choice. So the **normal** exit is not a self-cell; it is a hash-locked atomic
swap where an LP (or Fiber) pays the user on L1/Fiber against an in-pool transfer
locked by the same preimage. No reveal → both legs time out → no harm. The
≥61-CKB self-exit remains only as the whale-grade escape hatch.

---

## Architecture

```
            off-chain                          on-chain (CKB)
  ┌───────────────────────────┐       ┌──────────────────────────────┐
  │ participants  ── intents ─▶│       │  anchor cell (pool funds)    │
  │ (signed transfers)        │       │   data: pool_id, seq, root,  │
  │            │              │       │         total, fee_acc       │
  │            ▼              │       │   type script:               │
  │   sequencer = STF ────────┼──────▶│   • Groth16 verify (SP1)     │
  │   (liquid-cells-stf)      │ proof │   • public inputs == cell    │
  │   builds batch, new root  │ + DA  │   • deposits/withdrawals     │
  │            │              │       │     bound to real cells      │
  │            ▼              │       │   • DA blob committed        │
  │   DA blob (leaf diffs)  ──┼──────▶│  witness (reconstructable)   │
  └───────────────────────────┘       └──────────────────────────────┘
        every user can rebuild the tree from L1 and force-exit unilaterally
```

The on-chain checkpoint accepts a transition iff: the proof verifies against the
baked verification key; `prev_root/seq/total` match the old anchor and `new_*` the
new one with `new_seq == prev_seq + 1`; the deposits/withdrawals commitments match
the deposit cells consumed and output cells created; the DA commitment equals the
witness blob; and the epoch bound matches the tx `since`. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Repository layout

```
liquid-cells/
  crates/
    stf/                 # liquid-cells-stf, the deterministic STF (Phase 0, done)
      src/
        hash.rs          # keccak-256 (SP1-precompile friendly)
        smt.rs           # sparse Merkle tree over 256-bit keccak keys
        types.rs         # canonical byte layouts: Leaf, Transfer, Withdrawal, ...
        sig.rs           # secp256k1 ECDSA (patched to SP1 precompile in the guest)
        transition.rs    # apply(state, batch): the two-invariant state machine
        error.rs
      tests/properties.rs# no-debit-without-sig, conservation, replay, SMT proofs
    sequencer/           # liquid-cells-sequencer, runs the STF off-chain: a mempool +
      src/lib.rs         #   seal_batch() that emits a CheckpointJob and advances the root,
                         #   so successive checkpoints chain (STF-only dep, no SP1)
      tests/             # loop_succession.rs, multi-checkpoint chain, conservation, DA
    client/              # liquid-cells-client, the SDK: build+sign intents and reconstruct
      src/lib.rs         #   your leaf + force-exit/refund witness from L1 DA, on the SAME STF
      tests/             # client.rs, intents accepted by the STF; witnesses verify on-chain
    demo-ui/             # liquid-cells-demo-ui, interactive browser demo over the real crates:
      src/main.rs        #   a creator-tipping scenario (tips, checkpoints, trustless recovery,
      src/index.html     #   escape hatch). cargo run -p liquid-cells-demo-ui
    sp1-guest/           # wraps the STF as an SP1 program -> Groth16 proof
    sp1-host/            # cycle/equivalence driver + fixture/proof generator
    ckb-contract/        # anchor type script: Groth16 verify + force-exit + force-refund
    ckb-contract-tests/  # ckb-testtool integration suite (+ redteam_*.rs adversarial cases)
    groth16/             # the deployed BN254 Groth16 verifier lib used by the anchor type script
    verifier-difftest/   # differential test: hand-ported verifier vs an independent impl (correctness safeguard)
    wasm/                # liquid-cells-wasm, the browser SDK: wasm-bindgen skin so the same STF runs in-browser
    sequencer-service/   # tiny HTTP front for the sequencer (submit/seal/info/leaf/da), prover runs separately
  docs/
    SPEC.md              # consolidated technical spec (working draft; links the per-topic docs)
    COMPLETION.md        # living path-to-mainnet tracker (findings, v2 re-bake, gates)
    ARCHITECTURE.md      # the full trustless design
    COMPARISON-FIBER.md  # honest Liquid Cells vs Fiber comparison (trust/liveness/exit/liquidity)
    REPRODUCE-EXIT.md    # run lc-exit yourself: rebuild a balance + exit proof from L1 alone
    OPERATING.md         # operator runbook: auto-restart, host-death failover, recovery, monitoring
    THREAT-MODEL.md      # red-team findings -> mitigations
    INTEGRATION-GENERIC.md # START HERE to reuse: the 5 primitives + recipe cookbook + invariants
    INTEGRATION-TIPPING.md # one worked instance of the generic guide (deposit/split-payment/exit)
    NON-CUSTODY.md       # non-custody + censorship-resistance (for integrators/LPs/reviewers)
    UPGRADE-TIMELOCK.md  # timelocked code-cell upgrades (announce -> delay -> execute)
    SEQUENCING.md        # operator model is a knob: single / federated / permissionless (live evidence + gaps)
    FEES.md              # per-intent fee floor: live sequencer policy + staged in-proof version
    EGRESS.md FORCE-EXIT.md DA.md ...
  DEPLOY.md              # every live Pudge hash
  SECURITY.md            # responsible-disclosure policy
  ROADMAP.md             # cost/time/scale improvement plan + foundation-critical next work
  DEVELOPMENT.md         # running dev log
```

---

## Build & test

The Rust / RISC-V / SP1 toolchain lives in the **ChiralSP1 WSL distro** (not on the
Windows PATH).

```bash
# inside the ChiralSP1 WSL distro
export HOME=/root
export PATH=/root/.cargo/bin:/root/.sp1/bin:$PATH
cd /root/liquid-cells

cargo test            # build the STF and run the property tests
cargo build --release # optimized native build

# the generic "hello world": full off-chain lifecycle (deposit -> transfer -> checkpoint ->
# reconstruct from DA -> force-exit) in ~60 lines, no L1 or prover needed:
cargo run -p liquid-cells-client --example payment_pool
```

**Reusing it for your own app?** Start with **[docs/INTEGRATION-GENERIC.md](docs/INTEGRATION-GENERIC.md)**:
the five primitives, a recipe cookbook (payments / payroll / escrow / fee-split / swap), and the
hard invariants (you *reuse* the fixed STF, you don't fork it).

SP1 (`cargo-prove`, toolchain) is installed under `/root/.sp1`; the keccak SMT and
secp256k1 choices are deliberate so the same STF proves cheaply in the zkVM.

### Try it: the interactive on-chain demo ("CellTip")

```bash
cargo run -p liquid-cells-demo-ui     # then open http://127.0.0.1:8088
```

A browser demo that drives a **real pool on the Pudge testnet**, end to end: connect a JoyID
wallet (CCC), **deposit real testnet CKB** into the pool (a real on-chain tx, then a proven
checkpoint credits it, ~7 min), **tip creators** in sub-1-CKB amounts off-chain (instant), and
**withdraw** back to your own wallet (another proven checkpoint). Deposits and withdrawals
**batch** so many users share one proof. The session key that signs your tips is generated
in-browser and never leaves your device (self-custodial), so each wallet is its own pool account
and the operator can never move or redirect your funds. The server holds the `Sequencer` synced
to the live anchor and spawns the prove+submit pipeline per checkpoint (`crates/demo-ui`).
Operator deploy/driver scripts (genesis, checkpoint submit) build the real Pudge transactions.

> **Heads up (a fresh clone will not run the live demo out of the box):** the operator deploy and
> driver scripts (the `lc-*.mjs` files) live off-repo on the operator machine, they are not in this
> repository. The demo-ui also requires a generated `fixtures/demo/state.json`. You can still run the
> off-chain client lifecycle (`cargo run -p liquid-cells-client --example payment_pool`) with no L1,
> prover, or operator scripts needed.

---

## Roadmap

| Phase | Deliverable | State |
|---|---|---|
| **0** | `liquid-cells-stf` crate + property tests (this is also the sequencer core) | **done** |
| **1** | Partial-witness refactor + SP1 guest + cycle measurement (~0.62M cycles/transfer with precompiles); `MAX_LEAVES_PER_BATCH=1024` | **done** |
| **2a** | Groth16 wrap of the transition proof (356-byte proof, verified) + on-chain verifier spec ([docs/ONCHAIN-VERIFY.md](docs/ONCHAIN-VERIFY.md)) + fixtures | **done** |
| **2b-1** | CKB anchor type script verifies the real Groth16 proof on CKB-VM (`ckb-debugger` exit 0, ~3.6B cycles = g16ckb parity) + baked pins | **done** |
| **2b-2** | Real type script: reads proof/PV from witness, pins prev/new to anchor cells (root/seq/total/fee_acc); 5/5 ckb-testtool tests incl. adversarial | **done** |
| **2b-3** | Implicit cell format: deposit/withdrawal commitments recomputed from real cells + value conservation (accounting + solvency); 10/10 ckb-testtool tests incl. deposit adversarial | **done** |
| **2b-4** | Withdrawal-path coverage (deterministic lock-hash coordination); comprehensive deposit+withdrawal checkpoint; 14/14 ckb-testtool tests | **done** |
| **2b-5** | Proven L1 fee model: `fee_withdrawal` drawn only from accumulated fees (user balances provably untouched), fee-aware accounting + solvency pin the miner fee to the proven draw; 15/15 ckb-testtool tests | **done** |
| **4** | **Data availability**: in-circuit `da_commitment` over touched post-state, bound on-chain to the published witness blob; independent reconstruction rebuilds the tree + a force-exit inclusion proof from L1 alone ([docs/DA.md](docs/DA.md)). 17/17 ckb-testtool + DA reconstruction test | **done** (standalone CLI `lc-exit` shipped; see [docs/REPRODUCE-EXIT.md](docs/REPRODUCE-EXIT.md)) |
| **3** | **Force-exit / escape hatch**: a second anchor mode, unilateral single-leaf withdrawal vs the last committed root (SMT inclusion, no proof), payout forced to the owner's secp lock, leaf nullified, gated by an operator-silence timeout (`last_epoch` + tx `since`). 24/24 ckb-testtool (incl. 7 force-exit) ([docs/FORCE-EXIT.md](docs/FORCE-EXIT.md)) | **done** |
| **5** | **Atomic-swap egress** for sub-61-CKB (dust): in-pool HTLC (`htlc_lock`/`claim`/`refund`), escrow keyed by all lock terms, the in-pool leg of a hash-locked swap with an L1/Fiber payment ([docs/EGRESS.md](docs/EGRESS.md)). 32 STF tests | **done** (in-pool leg) |
| **5b** | **On-chain force-refund**: a third anchor mode, the swap *sender* unilaterally reclaims a *timed-out* HTLC escrow against the committed root (htlc_id re-derived, SMT inclusion, payout forced to the sender's secp lock), gated by `since ≥ timeout` **and** operator silence. 9 ckb-testtool tests. Closes the sender's exposure; the receiver-side residual is architectural (single anchor → Phase 6), documented honestly in [docs/EGRESS.md](docs/EGRESS.md) | **done** (live on Pudge, upgrade tx `0xf393b367…`) |
| **2b-6** | **Deployed to Pudge**: code cell + genesis anchor live, first checkpoint with the BN254 proof verified on live CKB-VM. Needed the 3-pairing precompute (`e(alpha,beta)` baked) to fit CKB's ~3.50B block cycle limit ([DEPLOY.md](DEPLOY.md)) | **done** |
| **Seq** | **Sequencer loop** (`crates/sequencer`): the off-chain STF runner, a mempool of signed intents + `seal_batch()` that emits a `CheckpointJob` (SP1 guest input, both anchor-cell byte images, DA blob, deposit/withdrawal cell specs) and advances the in-memory root, so **successive checkpoints chain**. STF-only dep (no SP1), tests in ms. 2 loop tests assert genesis-pinning, anchor-chaining (`seq+1`), value conservation across the chain, and DA reconstruction (final root + a force-exit proof from L1 alone). **Driven live on Pudge: the deployed pool advanced seq 1→2→3, each a BN254 proof verified on-chain** (`crates/sp1-host/src/bin/sequence.rs`, [DEPLOY.md](DEPLOY.md)) | **done** |
| **SDK** | **Client SDK** (`crates/client`): build + sign `Transfer`/`Withdrawal`/`HTLC` intents and reconstruct your `{balance, nonce}` + an SMT inclusion proof from L1 DA, plus assemble the exact force-exit / force-refund witness bytes, all on the **same** `liquid-cells-stf`, so a client can never diverge from the sequencer or contract. 32 tests: intents accepted by the STF, reconstruction recovers the true leaf, witnesses verify against the committed root, `batch_transfer` fan-out + snapshot/reconstruct | **done** (Rust; subsumes the standalone DA CLI) |
| **6a** | **Permissionless sequencing** (foundational): anchor **lock continuity** (`output anchor lock == input anchor lock`) turns the genesis lock into a permanent policy for who may sequence, so an always-success genesis lock yields a permanently permissionless, capture-proof pool. Capture-rejection test added. **Live on Pudge: a second pool with an always-success lock, where cp2 (seq 1 to 2) advanced the root UNSIGNED**, gated only by the proof + lock continuity ([DEPLOY.md](DEPLOY.md)) | **done** (safety + capture-proofness; reward + anti-griefing next) |
| **6b-1** | **Sequencer reward** (contract-only): the operator pays itself out of the proven `fee_withdrawal` via a marked reward output (excluded from withdrawals, bounded by fee revenue so never from a user balance), which makes permissionless sequencing self-sustaining. No proof change. **Live on Pudge** (upgrade tx `0x4ea3eb48…`). anchor.rs 11 | **done** |
| **6b-2** | **Anti-griefing**: a deterministic off-chain leader schedule (`keccak(id ‖ root)`, lowest leads) so only one sequencer proves per round, with ranked failover (`crates/sequencer/src/coordinator.rs`). Racing is an efficiency problem, not a trust one, so the on-chain commit-reveal alternative is deliberately deferred. 4 tests | **done** |
| **6b-3** | **Anchor sharding** (`ShardedSequencer`): K independent pools advanced in parallel for K-fold throughput, no contract change (the type script already supports any number of pools), no cross-shard atomicity needed. 2 tests | **done** |

Throughput concerns (single-anchor contention, batch cycle budget) are deliberately
deferred to Phase 6b, with the escape hatch in place they are performance knobs, not
trust assumptions.

---

## Security properties & non-goals

**Guaranteed (Phases 1-4, live on testnet):** no operator theft; no balance inflation; no
permanent censorship; no data withholding; trustless exit at any denomination.

**Out of scope (v1):** privacy, on-chain DA reveals transfer diffs (a future
version can add encrypted DA + amount-hiding proofs); general-purpose smart contracts
, Liquid Cells is a focused pooled-payment rollup.

---

## License

Licensed under MIT (see LICENSE).
