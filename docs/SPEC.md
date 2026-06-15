# Liquid Cells: Technical Specification (working draft)

> **Status: working draft / scaffold.** Liquid Cells is **testnet-only, unaudited** software with no
> real value at stake (deployed on the Nervos **Pudge** testnet). This document consolidates the
> per-topic docs into one spec. Sections marked _expand_ are stubs that point at the authoritative
> detail doc; the normative constants, trust model, data-availability, and non-custody sections are
> complete and verified against the code. Developed by **Luso Crypto Labs**.

## 0. How to read this

- **Normative** sections (parameters, trust model, DA, exit) describe what the deployed contract and
  STF actually enforce, and cite the code.
- **Informative / _expand_** sections summarize and defer to a detailed doc.
- Every strong claim should be reproducible; see [REPRODUCE-EXIT.md](REPRODUCE-EXIT.md) for the
  end-to-end exit reconstruction and the test suite for the rest.

## 1. Overview

Liquid Cells is a **pooled-balance validity rollup** for sub-cell-minimum payments on CKB. Many
participants hold and move balances below the ~61-CKB cell minimum behind a **single on-chain anchor
cell**, with state advanced by checkpoints that each carry a zk validity proof CKB verifies on-chain.

It is an **implementation, not an invention**: the architecture (pooled balances, validity proofs,
on-chain DA, force-exit) has prior art (Intmax2 is the closest cousin; on-chain Groth16 on CKB was
done by ckb-zkp). See [PRIOR-ART.md](PRIOR-ART.md). The contribution is a complete, live, force-exitable
instance on CKB behind a real product trajectory (Scryve).

### The four pillars (the trust model in one line)

A checkpoint cannot **steal** (no debit without a signature), **inflate** (value conservation),
**censor permanently** (permissionless sequencing + unilateral force-exit), or **withhold exit data**
(on-chain DA). Details in §5–§8.

## 2. Roles

- **User**, holds a balance (a leaf in the state tree), signs intents, can exit unilaterally.
- **Sequencer / operator**, orders intents, builds checkpoints, generates proofs, posts DA. Has
  **no spending authority** (§7).
- **Anyone**, under the deployed permissionless lock, any party that can produce a valid proof may
  advance the root (§9). Not a privileged role.

## 3. On-chain objects  _(expand → [CELL-FORMAT.md](CELL-FORMAT.md), [DEPLOY.md](../DEPLOY.md))_

- **Anchor cell**, the single cell carrying the pool's type script; its data is
  `root(32) ‖ seq(8) ‖ total(16) ‖ fee_acc(16) ‖ last_epoch(8)` (80 bytes). One per pool.
- **Code cell**, the shared anchor type-script binary (~112 KB), referenced by every pool via one
  `cell_dep`; upgradable in place by type-id (§11).
- **Deposit lock**, sweep-or-refund lock binding a deposit to a pool's anchor type hash.

## 4. State and the state-transition function  _(expand → [ARCHITECTURE.md](ARCHITECTURE.md))_

State is a sparse Merkle tree (**depth 256**, keccak) of leaves `{key, balance, nonce}`. The STF
(`crates/stf`) is the single source of semantics, shared byte-for-byte by the zk guest, the
sequencer, and the client (so none can diverge). The five-operation core:

| Op | Authority | Effect |
|---|---|---|
| `Deposit` | a real on-chain deposit cell | credit a leaf |
| `Transfer` | sender signature + nonce | debit sender, credit recipient (+ fee) |
| `Withdrawal` | owner signature + nonce | debit leaf, pay an L1 cell |
| `HtlcLock` | sender signature | escrow into a hash-locked leaf (in-pool swap leg) |
| `HtlcClaim` / `HtlcRefund` | preimage / timeout | resolve an escrow |

_expand: full per-op pre/post-conditions and encodings._

## 5. Checkpoints and on-chain verification  _(expand → [ONCHAIN-VERIFY.md](ONCHAIN-VERIFY.md))_

Each checkpoint proves a state transition with **SP1 → Groth16 (BN254)**. The anchor type script
verifies the proof on CKB-VM (deployed ark-bn254 verifier, **~80M cycles, ~2.3% of the 3.5B block
budget, ~43x reduction** from the prior substrate-bn verifier) and binds the proof's public values to
chain facts (prev/new root, seq, totals, fee, DA commitment). A batch touches at most
**`MAX_LEAVES_PER_BATCH = 1024`** leaves.

## 6. Data availability  _(normative, [DA.md](DA.md))_

Every checkpoint **force-publishes** its full state diff in the transaction witness (`output_type`):
each touched leaf as `key(32) ‖ balance(16 BE) ‖ nonce(8 BE)` = 56 bytes. The proof commits
`da_commitment = keccak(da_blob)` in-circuit, and the anchor type script rejects any checkpoint whose
witness blob does not match (**reject code 59**). So the operator cannot advance the root while
withholding or altering the diff.

### 6.1 Reconstruction and its cost (normative)

Folding all published blobs from genesis rebuilds the exact tree, from which any leaf's
`(balance, nonce)` and sibling path (the exit proof) follow. `lc-exit` does this from a generic CKB
node's indexer and asserts the rebuilt root equals the live on-chain anchor root (so a lying data
source is detected, not trusted).

- **Cost shape:** full replay is `O(history)`; per-checkpoint blob is ≤ ~57 KB (56 × 1024).
- **When it bites:** the cold-recovery / force-exit path, not the everyday path.
- **Snapshot path:** `reconstruct_from_snapshot(snapshot, snapshot_root, tail)` bounds it to
  `O(snapshot + tail)`, self-verifying against the on-chain root (no new trust). Full replay is the
  zero-dependency backstop. **Advisory until checkpoint-compaction (Tier D/B4) lands.**
- **Retention dependency:** the diffs live in witnesses, so retrieval needs an **archival** CKB node
  (the default full node retains them; a light client does not). This is the standard rollup
  DA-liveness assumption, not an operator dependency.

## 7. Non-custody and the exit guarantees  _(normative, [NON-CUSTODY.md](NON-CUSTODY.md))_

| Guarantee | Mechanism |
|---|---|
| Cannot **steal** | no debit without the owner's signature (proven + re-checked on-chain) |
| Cannot **mint / inflate** | value conservation `Σ balances + fee_acc == total`, re-summed on-chain |
| Cannot **trap funds** | unilateral **force-exit** against the last committed root after operator silence |
| Cannot **withhold exit data** | every proof commits `keccak(da_blob)`; the root can't advance without publishing the diff |

### 7.1 Force-exit  _(expand → [FORCE-EXIT.md](FORCE-EXIT.md))_

After **`FORCE_EXIT_TIMEOUT_EPOCHS = 180` epochs (~30 days)** of operator silence, any user spends
against the last committed root with an **8249-byte** witness
(`pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32)`), reconstructed from L1. The payout is a
single L1 cell, so it is subject to the ~61-CKB minimum (sub-61-CKB dust exit is the weak spot; see
§12). Demonstrated live (recovered a 199.989-CKB leaf from L1 alone; [DEPLOY.md](../DEPLOY.md)).

## 8. Liveness and permissionless sequencing  _(expand → [SEQUENCING.md](SEQUENCING.md))_

Anchor-lock continuity makes the genesis lock a permanent policy for who may sequence; under an
always-success lock, anyone with a valid proof may advance the root (demonstrated: a checkpoint
advanced the root unsigned). A checkpoint can never re-lock the anchor to seize sequencing
(capture-proof, red-team-tested).

## 9. Fees and economics  _(expand → [FEES.md](FEES.md))_

Fees never come from balances (`fee_withdrawal` is capped at accrued fee revenue and proven). Each
checkpoint costs one proof + one L1 miner fee, amortized across the batch. A `FeePolicy` admission
floor (off by default) plus a staged in-proof `min_fee` close the zero-fee-flood gap.

## 10. Throughput and scale

One proof seals up to 1024 transfers, so the cost is per-checkpoint, not per-user. A single CPU pool
sustains roughly **~2.4 transfers/sec** (1024 / ~420 s); **sharding** (`ShardedSequencer`) gives
linear K-fold throughput with no contract change, and GPU/prover-network proving cuts the ~7-min
checkpoint toward ~1 min (planned). See [ROADMAP.md](../ROADMAP.md).

## 11. Upgrade governance  _(expand → [UPGRADE-TIMELOCK.md](UPGRADE-TIMELOCK.md))_

The anchor code cell is upgradable in place by a **single key** today, the one custody-relevant
residual. A **timelocked upgrade lock** (commitment + matured delay, guaranteeing a force-exit
window) is **built and tested** but not yet adopted on the live deployment.

## 12. Known limitations / residuals (consolidated, honest)

- **Testnet-only, unaudited.** An external audit is the gate before real value.
- **Single upgrade key** until the timelock lock is adopted (§11).
- **~7-min finality** (CPU Groth16); ~1-min (GPU/prover-network) and sub-second soft-confirmation are
  **planned, not shipped**.
- **Force-exit:** ~30-day operator-silence window; payout lands a ≥61-CKB cell, so dust exit is the
  weak spot. The **Fiber-leg dust egress is designed but not built** (in-pool HTLC escrow + sender
  refund are built and tested; the Fiber integration, the LP, and receiver-side force-claim are not).
- **Plaintext DA**, no amount privacy.
- **Operator liveness** for everyday progress (mitigated by force-exit) and **archival DA retention**
  for recovery (§6.1).

## 13. Parameters and deployed constants  _(authoritative values → [DEPLOY.md](../DEPLOY.md))_

| Constant | Value |
|---|---|
| SMT depth | 256 |
| `MAX_LEAVES_PER_BATCH` | 1024 |
| `FORCE_EXIT_TIMEOUT_EPOCHS` | 180 (~30 days) |
| DA record | 56 bytes (`key 32 ‖ balance 16 ‖ nonce 8`) |
| Force-exit witness | 8249 bytes |
| DA mismatch reject code | 59 |
| Anchor type-script codeHash (Pudge) | `0x83158549…` |
| Baked program vkey | `0x00213af5…` |
| On-chain verify cost | ~80M cycles (~2.3% of the 3.5B block budget) |

## 14. Prior art and positioning

See [PRIOR-ART.md](PRIOR-ART.md) and the Fiber comparison in
[COMPARISON-FIBER.md](COMPARISON-FIBER.md).

## 15. Reproducing the claims

- Unilateral exit from L1 alone: [REPRODUCE-EXIT.md](REPRODUCE-EXIT.md).
- Snapshot equivalence + tamper-rejection: `cargo test -p liquid-cells-client --test snapshot`.
- On-chain verification parity: the contract test suite + the differential verifier crate.

---

_This is a working draft. Open items: full STF per-op semantics (§4), the on-chain verification
binding in detail (§5), and the sequencing/capture-proof argument (§8) still defer to their detail
docs and should be promoted into normative text here._
