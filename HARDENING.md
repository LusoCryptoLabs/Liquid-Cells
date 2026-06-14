# Hardening and the road to mainnet

This document records the production-hardening work done on Liquid Cells and, honestly, what
still stands between it and holding real money on mainnet. It is the companion to
[DEPLOY.md](DEPLOY.md) (every live hash), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) (the trust
argument), and [docs/PRIOR-ART.md](docs/PRIOR-ART.md) (what is and is not novel).

The protocol's *trust* design was already complete and live on Pudge: the sequencer cannot steal,
inflate, censor permanently, or withhold data, because the on-chain anchor type script re-derives
and checks every fact, and a force-exit hatch defeats freezing. This pass is about the engineering
that turns a correct-by-design testnet system into one you would trust with value: correctness
evidence for the hand-written crypto, durability, a real deposit lock, and key recovery.

## What this pass shipped

| Area | What | Tests | Where |
|------|------|-------|-------|
| Verifier correctness | **Differential test** of the live ark-bn254 Groth16 verifier against the independent pre-port substrate-bn implementation, over real proofs and a fuzzed corpus. Asserts `accept(ark) == accept(bn)` for the live cp1 proof, every fixture, all 2848 single-bit proof flips, all 2304 public-value flips, and 2500 random multi-byte mutations. Zero disagreements. | 5 | `crates/verifier-difftest` |
| STF safety | **Deterministic fuzzer**: seeded randomized mixed batches checked against an independent shadow ledger after every batch, pinning value conservation, no-debit-without-signature, shadow agreement, determinism, and no-panic-on-malformed across thousands of ops. | 4 | `crates/stf/tests/fuzz.rs` |
| Sequencer durability | **Write-ahead replay journal** (event-sourced, crash-tolerant). `DurableSequencer` logs every intent and seal; `recover()` replays through the identical STF to reconstruct a byte-identical sequencer (root, seq, total, fee_acc, leaves, and pending mempool). Tolerates a torn trailing frame. | 5 | `crates/sequencer/src/journal.rs` |
| Deposit safety | **Deposit lock**: a deposit cell's CKB can move only into a pool checkpoint (sweep, credits the depositor) or refund to the depositor after a timeout. Never to a third party, closing the always-success window. | 6 | `crates/ckb-contract/src/deposit_lock.rs` |
| Key recovery | **Session-key export/import** in the demo so losing browser storage no longer means losing access, with an honest note on why deterministic derivation is not possible under JoyID. | n/a | `crates/demo-ui/src/index.html` |
| Reproducibility | **vkey consistency check** asserting the guest vkey is identical across the contract, the fixture, and the prover assertion, plus the documented full-rebuild procedure. | n/a | `scripts/verify-vkey.sh` |

Suite (all green): **49 STF**, **23 sequencer**, **100 contract integration**, **10 client**, and the **5-test differential verifier** crate — including, added since this pass, the **55-case adversarial red-team**, the resilient-seal, full-drain, deposit-confirmation-gate, tipping-integration, DA-snapshot, and timelocked-upgrade-lock suites.

### Why the differential verifier test matters most

The single biggest correctness risk in the codebase was the hand-port of the BN254 Groth16 verifier
from `substrate-bn` to `ark-bn254` (done to fit CKB's cycle budget without the `e(alpha,beta)`
precompute hack). A hand-port of curve math can silently change behaviour on inputs the one happy-path
fixture never exercises. The differential test runs *both* implementations, two different libraries,
two different deserializers, written months apart, and asserts they agree on accept/reject for every
input thrown at them. That is the closest thing to a proof of equivalence we can get without a formal
one, and it is the work that most reduces "did the optimization introduce a soundness bug" risk.

## What it takes to hold real money (engineering, audit aside)

Setting the external audit aside (it remains the genuine risk for a money-holding zk system, not a
formality): the buildable path, ranked by leverage. Items marked done were closed in this pass.

**Correctness (internal, partially substitutes for audit confidence)**
- [x] Differential-test the verifier vs an independent implementation.
- [x] Fuzz the STF against an independent shadow ledger.
- [~] Reproducible-build attestation that the deployed code cell is exactly this source: the
  `verify-vkey.sh` full-rebuild path has now been **run and reproduces the baked vkey `0x00213af5…`
  exactly** (which also caught and fixed a real drift — post-Phase-5 journal helpers had leaked into
  the proven guest ELF; now feature-gated out). The vkey **pin-agreement check now runs in CI** (`.github/workflows/ci.yml`); remaining: the heavier
  full guest-ELF rebuild in CI (needs the sideloaded succinct toolchain) and a clean-room/formal
  re-derivation of the Groth16 verify equation.

**Protocol fixes (on-chain)**
- [x] Deposit lock that removes the third-party theft window (sweep-or-refund).
- [x] Deploy the deposit lock live (Pudge codeHash `0x0d610c61…3d3574`) and verify it on-chain: a
  deposit cell was created under it, a third-party spend was rejected (`Inputs[0].Lock
  ValidationFailure`), and a refund to the depositor was accepted (see [DEPLOY.md](DEPLOY.md)).
- [x] Route a deposit through it end-to-end: a deposit cell created under the deposit lock was
  **swept by a proven checkpoint** of the type-id'd pool (live on Pudge, tx `0x91b0bcdf…` →
  `0x332e49ff…`; see the type-id'd-pool row below and [DEPLOY.md](DEPLOY.md)). Folding this into the
  `crates/demo-ui` happy path (today still an always-success lock) is the remaining ergonomics step.
- [x] Type-id the anchor so each pool has a unique type hash (contract capability, backward
  compatible): empty args = the legacy baked `POOL_ID`; 32-byte args = a type-id'd pool whose
  identity is enforced at genesis as `blake2b(first input)`. 50 contract tests green.
- [x] Activate it: live code-cell upgrade (in place, codeHash preserved) + a type-id'd pool
  genesis'd on Pudge (tx `0x805e6252…`, pool_id `0x06865b65…`, unique anchor type hash
  `0xf7dfded8…`). The genesis type-id enforcement is verified live (the tx committed, so the
  on-chain `anchor_type_id() == args` check passed). See [DEPLOY.md](DEPLOY.md).
- [x] Prove the cross-pool guarantee at the contract level: a deposit bound to one pool's type
  hash is refused by a *different* pool's checkpoint (`SweepWithForeignPool` /
  `sweep_into_a_foreign_pool_rejected` in `crates/ckb-contract-tests/tests/deposit_lock.rs`, 7
  deposit-lock tests). This makes "binding to a type-id'd anchor closes the cross-pool sweep
  caveat" a tested fact rather than prose.
- [x] Advance the type-id'd pool with a proved checkpoint and route the deposit lock to its unique
  type hash. Done **live on Pudge**: a 200 CKB deposit cell created under the deposit lock bound to
  the type-id'd pool's unique anchor type hash `0xf7dfded8…` (tx `0x91b0bcdf…:0`), then swept by a
  checkpoint that advanced that pool **seq 0 → 1** (tx `0x332e49ff…`) whose BN254 Groth16 proof —
  produced with the sequencer configured for `pool_id = type-id` — **verifies on-chain** against the
  baked vkey `0x00213af5…`. The deposit's `to_key` is credited inside the proof and the funds fold
  into the new anchor (root `0x00b5dbaf…`, seq 1). See [DEPLOY.md](DEPLOY.md).
- [ ] Receiver-side force-claim for HTLC egress: the one documented architectural residual
  (`force_refund` closes the sender side only). See [docs/EGRESS.md](docs/EGRESS.md).

**Production infrastructure**
- [x] Durable sequencer state (replay journal). Remaining: HA/failover, HSM/KMS key custody,
  monitoring/alerting, and the sequencer's own CKB node with a reliable RPC (the intermittent Pudge
  `waitTransaction` hangs seen during deploys would be incidents at scale).
- [ ] Fast, redundant proving: GPU or the SP1 prover network, ~7 min CPU becomes ~1 min, with failover.
- [x] A DA reconstruction tool so users rebuild balances + force-exit proofs **from L1 alone**, no
  operator: `lc-exit` (`crates/client/src/bin/lc-exit.rs`), verified live ([DEPLOY.md](DEPLOY.md)),
  with advisory snapshotting for O(snapshot+tail) recovery. (An always-on indexer *service* is the
  remaining scale nicety.)

**Economics and egress**
- [ ] A fee model that closes: per-checkpoint proving cost amortized over the batch must be covered by
  tip/withdraw fees plus margin (notes below).
- [ ] Real sub-61-CKB exits via the HTLC/Fiber atomic-swap egress plus liquidity providers (the in-pool
  HTLC leg exists; the L1/Fiber leg and LPs do not).

**Launch**
- [~] Upgrade-key lockdown (governance multisig + timelock), done last, it is irreversible and blocks
  further iteration, so it is a mainnet step, not a testnet one. The **timelock half is now built**:
  `crates/ckb-contract/src/upgrade_lock.rs` (announce → `delay`-epoch user-exit window → execute, 6
  tests; [docs/UPGRADE-TIMELOCK.md](docs/UPGRADE-TIMELOCK.md)). Remaining: a governance multisig as the
  gov lock, and the live migration (redeploy the code cell under it) — both deliberately mainnet-last.
- [~] Adversarial review + coordinated disclosure. An internal adversarial red-team ran (56 cases,
  no break found; permanent regression suite + findings in
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)). Suspected vulnerabilities go through private,
  coordinated disclosure ([SECURITY.md](SECURITY.md)). An external audit is the next gate before any
  real-value use. (A public adversarial-testing program is not currently planned.)

## Deposit-lock deploy procedure (done on Pudge)

The lock is deployed and verified live (codeHash `0x0d610c61…3d3574`, deploy/test hashes in
[DEPLOY.md](DEPLOY.md)); only step 4 (routing the demo deposit flow through it) remains. The steps:

1. Build: `cargo build --release` in `crates/ckb-contract` produces
   `target/riscv64imac-unknown-none-elf/release/liquid-cells-deposit-lock` (~17 KB).
2. Deploy it as a code cell (type-id) on Pudge with the offckb deployer key (mirror `lc-deploy.mjs`);
   record `codeHash` + dep `outPoint` in [DEPLOY.md](DEPLOY.md).
3. Compute the deposit lock for a user: `args = pool_type_hash(32) ‖ refund_lock_hash(32) ‖
   timeout_epoch(8 BE)`, where `pool_type_hash` is the live anchor type-script hash, `refund_lock_hash`
   is the depositor's own lock hash, and `timeout_epoch` is a sane future epoch.
4. Change the demo deposit script (`lc-demo-userdeposit.mjs`) to create deposit cells with this lock
   instead of always-success. **No sequencer change is needed**: a checkpoint already consumes the
   pool anchor as an input, which satisfies the lock's sweep path.
5. Verify on-chain: a deposit cell can be swept by a checkpoint and refunded after timeout, and a
   third-party spend attempt fails.

## Fee model notes

The protocol already proves the L1 fee is never skimmed from a user balance (`fee_withdrawal` is capped
in-circuit at accumulated fee revenue, and the anchor solvency check pins the miner fee to it). What is
not yet designed is the *revenue* side: each checkpoint costs one Groth16 proof (CPU ~7 min, or GPU
cost) plus the L1 miner fee. For the system to be sustainable, the in-pool fees collected per batch
(`fee_delta`) must exceed proving cost + miner fee + margin, amortized across batch size. Concretely:
larger batches amortize the fixed proof cost better, so the fee model and the batch-window/size policy
(`MAX_LEAVES_PER_BATCH = 1024`) are coupled. This is an economic design task, not a protocol gap.

## Reproducibility and pinning

The guest verifying key `0x00213af5…c1e8` binds the on-chain verifier to exactly this STF. It is pinned
in three places (contract `VKEY_HASH`, `fixtures/vkey.txt`, `prove_one.rs EXPECTED_VKEY`);
`scripts/verify-vkey.sh` asserts they agree and prints the full-rebuild check. Build inputs that must
match to reproduce the vkey byte-for-byte: **succinct rustc 1.94.0** (cargo-prove's toolchain, == the
`ghcr.io/succinctlabs/sp1:v6.2.4` image), **sp1-zkvm / sp1-sdk 6.2.4** (the committed lock), the guest's
**`journal` feature off** (default — the journal-only codec helpers are gated out so they never enter
the proven ELF), and the **absolute build path** (`$HOME/liquid-cells`, since SP1 embeds the source path
in the ELF). The full rebuild has been run and **reproduces `0x00213af5…` exactly**. Any STF change
re-bakes the vkey and requires an in-place contract upgrade (the anchor preserves its code hash across
upgrades).

## Status

Testnet only, unaudited, no value at risk. This pass closed the highest-leverage correctness and
durability gaps and the deposit theft window; the remaining items above are real and are what stand
between here and mainnet.
