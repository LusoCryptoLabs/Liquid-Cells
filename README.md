# Liquid Cells

**A fully trustless, pooled multi-recipient payment rollup for Nervos CKB.**

Liquid Cells lets many participants hold and move sub-1-CKB balances off-chain —
tips, game antes, creator micro-payments — anchored by a single on-chain cell,
with **no trust in the operator**. It is a zk-rollup (validity proofs + on-chain
data availability), not a custodial pool: the sequencer cannot steal, cannot
inflate balances, cannot censor permanently, and cannot withhold the data users
need to exit. The only trust assumptions are cryptographic hardness and CKB Layer 1
itself — the same base as any on-chain transaction.

> Status: **Phase 0 — pre-alpha.** The deterministic state-transition function and
> its safety properties are implemented and tested. The SP1 proof, on-chain anchor
> contract, DA layer, and exit paths are scheduled (see [Roadmap](#roadmap)).

---

## Why it exists

On CKB every Layer-1 state change consumes and creates cells, and a standard cell
needs **~61 CKB** of capacity. That makes direct micro-payments uneconomical — you
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
and any user can always recover their funds — combined with **Fiber/atomic-swap
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

1. **No debit without a signature** — a leaf's balance only decreases via a
   `Transfer`/`Withdrawal` carrying a valid secp256k1 signature from that leaf's owner.
2. **Value conservation** — `Σ balances + fees == total`, and
   `new_total == prev_total + Σ deposits − Σ withdrawals`.

Together these make operator theft and balance inflation *impossible*, not merely
disputable. There is no fraud-proof game to get wrong.

---

## Trust model — the four pillars

| # | Pillar | What it kills |
|---|---|---|
| 1 | **Validity proofs** — every root transition carries an SP1→Groth16 proof the anchor type script verifies | Forged transitions, balance inflation, stale-root settlement, the need for honest watchers |
| 2 | **On-chain data availability** — each checkpoint posts the compressed state diff in tx **witnesses** (fee-priced, not capacity-locked) | Data withholding; every user can always reconstruct their leaf + proof from L1 alone |
| 3 | **Permissionless escape hatch** — after operator silence for `T` epochs, anyone force-exits against the last committed root with a plain SMT inclusion proof | Liveness capture; the operator cannot freeze funds by going dark |
| 4 | **Atomic-swap / Fiber egress** — hash-locked swaps move any-size balances out without a 61-CKB cell | Dust entrapment, while staying fully trustless (the swap is atomic) |

The operator degrades to a **sequencer**: it can order transactions and be live,
nothing more.

### The 61-CKB reality (stated plainly)

A balance below ~61 CKB cannot become its *own* L1 cell — that is physics, not a
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
    stf/                 # liquid-cells-stf — the deterministic STF (Phase 0, done)
      src/
        hash.rs          # keccak-256 (SP1-precompile friendly)
        smt.rs           # sparse Merkle tree over 256-bit keccak keys
        types.rs         # canonical byte layouts: Leaf, Transfer, Withdrawal, ...
        sig.rs           # secp256k1 ECDSA (patched to SP1 precompile in the guest)
        transition.rs    # apply(state, batch): the two-invariant state machine
        error.rs
      tests/properties.rs# no-debit-without-sig, conservation, replay, SMT proofs
  docs/
    ARCHITECTURE.md      # the full trustless design
    THREAT-MODEL.md      # red-team findings -> mitigations
  DEVELOPMENT.md         # running dev log (updated every working session)
  # added in later phases:
  #   crates/sequencer    crates/sp1-guest    crates/ckb-contract
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
```

SP1 (`cargo-prove`, toolchain) is installed under `/root/.sp1`; the keccak SMT and
secp256k1 choices are deliberate so the same STF proves cheaply in the zkVM.

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
| **2b-4** | Withdrawal-path test (lock-hash coordination), L1 fee handling, DA blob; deploy to Pudge; sequencer builds checkpoint txs | next |
| **3** | Single-leaf force-exit (native SMT inclusion) + escape-hatch timeout | planned |
| **4** | DA blob format + independent reconstruction/verifier tool | planned |
| **5** | Atomic-swap / Fiber egress (hash-locked transfer variant) | planned |
| **6** | Permissionless sequencing + anchor sharding (throughput) | planned |

Throughput concerns (single-anchor contention, batch cycle budget) are deliberately
deferred to Phase 6 — with the escape hatch in place they are performance knobs, not
trust assumptions.

---

## Security properties & non-goals

**Guaranteed (once Phases 1–4 land):** no operator theft; no balance inflation; no
permanent censorship; no data withholding; trustless exit at any denomination.

**Out of scope (v1):** privacy — on-chain DA reveals transfer diffs (a future
version can add encrypted DA + amount-hiding proofs); general-purpose smart contracts
— Liquid Cells is a focused pooled-payment rollup.

---

## License

MIT. This is a private repository; do not redistribute.
