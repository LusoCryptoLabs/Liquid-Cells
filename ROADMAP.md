# Liquid Cells — Improvement Roadmap

Output of an internal brainstorm pass (cost, time, throughput, economics, blind-spots), with one
hard constraint on every item: **preserve the foundation** — the four pillars (validity proof + data
availability + unilateral force-exit + no-steal/no-mint) and permissionless, capture-proof
sequencing. Each item is tagged `foundation: preserved | strengthens | trade-off`.

This is a planning doc, not a commitment. Items are grouped by *do-once cost* (a vkey re-bake / a
contract upgrade is paid per coordinated release, so STF-changing items are bundled).

## Reframes established by the pass
- **The ~117K-CKB code cell is mostly not a recurring cost.** It is *locked (reclaimable when the
  cell is consumed), shared by every pool via one `cell_dep`, and paid once*; a new pool adds only
  its 80-byte anchor. ~11 KB of it is **dead `.eh_frame` unwind tables** (`panic=abort`), strippable.
- **On-chain verify is ~80M cycles (~43× under CKB's block budget).** Batch size is not near the
  limit; the recurring on-chain cost is the **DA blob**, the capital cost is the **code-cell
  capacity**.
- **The escape hatch is proven-correct but never exercised end-to-end by a real user** (see Tier B).

## Convergence (multiple independent agents landed here — highest confidence)
| Lever | Effect |
|---|---|
| GPU / prover-network + ranked failover | ~7× latency (≈7 min → ~1 min), multiplies with sharding, no trust impact |
| Adaptive batch cadence / break-even seal | Lowers $/payment, closes fee amortization — sequencer-only, no protocol change |
| SMT compression + DA-blob compression | Cuts proving cost *and* the on-chain witness together |

---

## Tier A — cheap wins now (S effort, no vkey re-bake)
- **Strip `.eh_frame`** (~11 KB / ~11K CKB off the code cell). *Investigated:* `-C force-unwind-tables=no` is a no-op (LLVM emits the CFI regardless) and post-link `objcopy --remove-section` only drops the 72-byte header (the bytes sit in a `PT_LOAD` segment). The real method is a **linker-script `/DISCARD/` of `.eh_frame`** at link time; deferred to the next code-cell redeploy (re-run the verifier differential test on the candidate binary). *preserved.*
- **Adaptive cadence + break-even batch policy** in the sequencer seal loop. *preserved.*
- **Instant soft-confirmation receipts** (sequencer signs "accepted" immediately; finality at
  checkpoint cadence) → sub-second perceived latency. *preserved — must be framed liveness-not-finality.*
- ✅ **Mempool ordering / poison-intent footgun** — **done** via `Sequencer::seal_resilient` (`crates/sequencer/src/resilient.rs`): mirrors `apply_ops`, drops only invalid *signed* intents and **transitively defers** their dependents (never reorders, never strands), with the atomic `seal_batch` kept as the authority and a **parity test** pinning byte-identical output when all-valid. Closes a real liveness/censorship gap (one bad intent no longer stalls a whole checkpoint — and `ShardedSequencer` no longer amplifies it K×). A naive "sort by nonce" would have been *unsafe* (cross-account funding deps). Follow-up: journal the drops in `DurableSequencer`. *preserved (strengthens liveness).*
- **Hybrid fee schedule `max(MIN_FEE_PER_LEAF, p%·amount)` + platform-sponsored fees** in the SDK →
  makes sub-cent tips viable. *preserved (client/policy only).*
- ~~Fix the stale DEPLOY.md 293K/3.47B figures~~ — **done.**
- ~~`verify-vkey.sh` pin check in CI~~ — **done** (`.github/workflows/ci.yml`).

## Tier B — foundation-protecting (do before any real value)
These are the "what we're not seeing" items: cheap-to-medium, and the docs currently imply some are
already done. **Detailed scope below.**
- ✅ **DA-reconstruction + force-exit-witness CLI** (`lc-exit`) — **done**: reconstructs your leaf
  from L1 alone and emits the force-exit witness, verified live against the type-id'd pool (B1 below).
- ✅ **Anchor minimum-capacity floor / tail-drain** — **investigated; not an exploitable bug**, now
  documented + tested (B2 below). The implicit invariant (genesis forces `total=0`; every op
  preserves `slack = capacity − total`; so `capacity ≥ slack ≥ occupied` always) prevents stranding.
- ✅ **Deposit confirmation-depth gate (M4)** — **done**: `PendingDeposits` (`crates/sequencer/src/pending.rs`)
  gates a deposit until it is `depth` blocks deep and prunes reorg-orphaned deposits before they seal;
  chain-agnostic (operator feeds heights), no contract change. Closed the docs-vs-code gap.
- **DA snapshotting** — bound reconstruction to O(snapshot+tail), not O(all history), so exit stays
  cheap as the pool ages.
- **Timelocked upgrade (user exit-window on upgrade)** — cap the single-key blast radius *now*,
  regardless of who holds it, ahead of the eventual governance multisig.

## Tier C — coordinated "v2" upgrade bundle (each re-bakes the vkey → ship together, audit once)
- **SMT depth-256 → shallow/extension-node tree** — biggest single cost win, ~30–50% total proving
  cycles (and a smaller witness). *preserved (differential-test the new tree like the verifier port).*
- **Contract-enforced minimum-fee-per-touched-leaf** (`fee_delta ≥ n_billable · MIN_FEE_PER_LEAF`,
  with `n_billable` a new proven public value) — makes the economics *provably* close + a native
  spam floor. *preserved.*
- **`ecrecover` instead of `verify`** — modest cycle save, and drops the 33-byte pubkey from the
  witness. *preserved (equivalent authority check).*
- **DA-blob varint compression** (balance 16B→~8B, nonce) — ~30–40% off the per-checkpoint footprint.
  *preserved (still reconstructable from L1; do **not** drop keys).*
- **High-S rejection** (close THREAT-MODEL L3) — one line, currently stuck behind exactly this re-bake.
  *strengthens.*

## Tier D — scale infrastructure (no protocol change, when volume demands)
- **Operationalize anchor sharding** (the `ShardedSequencer` primitive exists; needs the deploy /
  deposit-router / per-shard HA layer) → linear K-fold throughput **and** K-fold mass-exit relief.
- **GPU / prover-network fleet** across shards; **per-shard sequencer HA/failover**; **persistent /
  incremental SMT** for the sequencer at scale; **recursive aggregation** of the Groth16 wrap across
  K checkpoints (fewer L1 txs, latency-for-cost). *all preserved.*

## Tier E — strategic
- **Fiber egress leg + a reference LP** — turn sub-61-CKB dust egress from theory into product; the
  defensible wedge vs. prior art ("the only *live*, force-exitable, permissionless zk-rollup on CKB
  with a Fiber egress").
- **Drop the dead vendored `bn`** (verifier is ark-bn254 now; keep substrate-bn only as the
  differential-test oracle, clearly marked) — less supply-chain/reviewer surface.
- **Position permissionless sequencing as the censorship answer** (it's framed as a perf feature) and
  add a **non-custody framing** doc — cheap insurance for LP/exchange integration.

---

## Next real work — detailed scope

### B1. DA-reconstruction + force-exit-witness CLI  `[S–M]`  ✅ **DONE**  *strengthens the DA + exit pillars*

**Shipped:** `crates/client/src/bin/lc-exit.rs` (build `cargo build -p liquid-cells-client --features cli`).
It scrapes the pool's checkpoint chain from a CKB RPC via the indexer, folds the DA blobs through
`liquid_cells_stf::reconstruct`, checks the rebuilt root equals the live anchor, and emits the 8249-byte
force-exit witness. **Verified live** against the type-id'd pool (anchor `0x332e49ff…:0`, seq 1): the
reconstructed root matched the on-chain `0x00b5dbaf…` and recovered the depositor's leaf (199.989 CKB,
nonce 1) — from L1 data alone, no sequencer. Regression test in `crates/client/tests/reconstruct.rs`
(fixture `fixtures/typeid/`), CLI build wired into CI. *Original scope below for reference.*


**Why:** the entire "trustless" claim is "any user can rebuild their leaf from L1 alone and exit
without the operator." `stf::reconstruct()` (`crates/stf/src/da.rs`) and the force-exit witness
builder exist, but only as library code called from tests — `crates/client/src/bin/` is empty. No
real user can exercise the hatch today. This turns a paper guarantee into a runnable tool (and a
hackathon-credibility artifact).

**Deliverable:** a binary, e.g. `crates/client/src/bin/lc-exit.rs`, usage roughly
`lc-exit --rpc <url> --pool-type-hash <0x..> --my-key <secret-or-pubkey>`.

**Steps:**
1. Connect to a CKB RPC (CCC; the submit path already uses `@ckb-ccc/core`, and the Rust client can
   use a JSON-RPC client).
2. Locate the pool's **anchor by its type-script hash** (e.g. the type-id'd pool's `0xf7dfded8…`),
   newest live cell first.
3. **Walk the checkpoint chain backward**: each checkpoint consumes the prior anchor and produces the
   next, so follow the input/output anchor lineage to genesis, collecting each checkpoint tx's
   witness `output_type` = the DA blob.
4. **Fold blobs oldest-first** with `stf::reconstruct()` to rebuild the SMT / the caller's leaf
   `{balance, nonce}`.
5. **Assert** the reconstructed root == the current on-chain anchor root (integrity check; if it
   diverges, surface it loudly — that would itself be a finding).
6. **Build the force-exit witness** for the caller's leaf (`pubkey(33) ‖ balance(16) ‖ nonce(8) ‖
   siblings(256·32)`) via the existing client builder, and optionally assemble the full force-exit tx
   ready to sign + submit.
7. **Output:** the caller's balance/nonce, the witness bytes, and (optional) the assembled tx.

**Acceptance test:** point it at the **live type-id'd pool on Pudge** (anchor `0x332e49ff…:0`, seq 1),
reconstruct, confirm the root matches on-chain, and emit a valid force-exit witness for a known leaf.

**Risks / notes:** the chain-walk (finding all checkpoints by anchor type hash via RPC) is the only
non-trivial part; everything downstream already exists. Keep full-diff DA as the source of truth (do
not depend on any snapshot until B4 lands).

### B2. Anchor minimum-capacity floor / tail-drain  ✅ **RESOLVED (not a bug)**  *invariant documented + tested*

**Finding:** on close analysis the stranding concern does **not** materialize. `force_exit` enforces
`out_cap = in_cap − balance` with no explicit floor, but the anchor type script's GENESIS branch
forces `total == 0`, so a real pool starts with `slack = genesis_capacity`, which already clears
CKB's occupied-capacity rule (or the genesis cell could not exist). Every mode preserves `slack`
exactly (force-exit and checkpoints change capacity and total by the same amount), so
`anchor_capacity = total + slack ≥ slack ≥ occupied` at all times — draining `total` to 0 leaves a
valid anchor holding the genesis slack. Confirmed **live** (the type-id'd pool's slack held constant
at 250 CKB across genesis → seq 1) and by a **full-drain test**
(`crates/ckb-contract-tests/tests/redteam_drain.rs`). The invariant is now stated in `escape.rs` so
it is not re-flagged. The genuine sub-≈61-CKB limit is the *payout* cell, not the anchor — the
documented dust-egress case (THREAT-MODEL C1, addressed by the HTLC/Fiber egress). *No contract
change or redeploy needed.* Original scope below for reference.


**Why:** `force_exit` (`crates/ckb-contract/src/escape.rs`) enforces `out_cap == in_cap − balance`,
and the checkpoint path enforces the analogous capacity relation — but **nothing requires the output
anchor cell to retain the ~61 CKB a cell needs to exist**. As exits/withdrawals drain the pool, the
final operations would push the anchor below its own occupied capacity → the output anchor is
unconstructable → the **tail of the pool (and the anchor's own capacity) is stranded**, exactly under
mass-exit-after-silence when the hatch matters most. The docs only ever state "≥61 CKB self-exit" as
the floor on *what you exit*, never the floor the *anchor itself* must keep.

**Goal:** guarantee the pool can fully drain — no user balance is permanently unexitable.

**Options (decide during design):**
- **A — terminal drain mode (recommended):** when an exit/withdrawal takes the pool to `total == 0`,
  allow consuming the anchor entirely (no output anchor) and paying its residual capacity to the last
  exiter's owner secp lock. Cleanest "fully drains" guarantee; adds a recognized terminal case.
- **B — reserve the anchor's occupied capacity** as non-withdrawable (anchor always keeps ~61 CKB).
  Simplest; strands only the anchor's own genesis 61 CKB (operator cost), never user funds.
- **C — anchor-floor invariant:** reject any exit/withdrawal that would push `out_cap` below the
  anchor's occupied capacity, forcing the pool to keep ≥ floor. Prevents stranding *user* funds;
  pair with a genesis convention that the floor is the operator's.

**Scope:** applies to **both** `escape.rs` (force-exit/force-refund) **and** the checkpoint withdrawal
path in `main.rs`/`cells.rs`. Contract change → in-place type-id code-cell upgrade; **vkey-neutral**
(force-exit carries no proof; checkpoint withdrawals are already proven, only the capacity relation
changes). Re-audit the escape path — it is the most safety-sensitive code and touches
capture-proofness, so preserve: each leaf's payout → its owner's secp lock, no overdraw, leaf
nullification, lock continuity.

**Tests:** extend the adversarial escape suite (`crates/ckb-contract-tests/tests/redteam_escape*.rs`)
with a **full-drain sequence** (exit every leaf down to and including the tail) and assert the last
exiter recovers, plus negative tests that a sub-floor output anchor is handled per the chosen option.

**Effort:** M. **Foundation:** real edge today → strengthens once fixed.

---

*Tracking note:* STF-changing items (Tier C) and any change that re-bakes the guest vkey should be
collected into a single **"next vkey re-bake" bundle** so the re-bake + in-place contract upgrade +
re-audit cost is paid once. The high-S fix (L3) is the first entry on that list.
