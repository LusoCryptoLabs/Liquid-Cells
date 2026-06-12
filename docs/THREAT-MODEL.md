# Liquid Cells, Threat Model

This maps the findings from the initial adversarial review of the original pooled
design to how the **trustless** architecture neutralizes each one. Severities are the
original ones. "Status" is where the design (not yet the full implementation) stands.

Legend: ✅ eliminated by design · 🟡 bounded / scheduled · ⚙️ performance not trust.

---

## Critical

### C1, Sub-61-CKB balances had no trustless exit · 🟡 bounded
A standard CKB cell needs ~61 CKB, so a tiny balance cannot become its own cell.
That is physics. **Mitigation:** the normal exit is a **hash-locked atomic swap**
(LP/Fiber pays out any denomination against an in-pool transfer; atomic, so zero
trust). The ≥61-CKB self-exit remains only as the whale escape hatch. Stated plainly
in the README rather than hidden as "dust." Implementation: Phase 5.

### C2, Operator-only receipts made the dispute game unsound · ✅ eliminated
There is **no dispute game**. Validity is proven by the SP1→Groth16 proof, and the
circuit enforces *no debit without the owner's signature*. The operator cannot forge
a balance change or refute a valid exit. Implementation: Phases 1–2.

### C3, Root on-chain but preimage off-chain (validium) · ✅ eliminated
Each checkpoint posts the state **diff blob on-chain** (in witnesses, fee-priced),
and the type script binds `da_commitment` to it. Every user can reconstruct their
leaf + proof from L1 alone. This is a rollup, not a validium. Implementation: Phase 4.

---

## High

### H1, Deposit binding not enforced on-chain · ✅ eliminated
Deposits are bound by the **deposits commitment**, which the type script recomputes
from the deposit cells actually consumed by the checkpoint tx, both ways (no phantom
credits, no dropped deposits). No off-chain "registration" is load-bearing.

### H2, Roadmap front-loaded custodial risk · ✅ eliminated
The protocol is never custodial at any phase: real value only moves once the proof +
on-chain binding (Phases 1–2) and force-exit (Phase 3) exist. Until then nothing
holds user funds.

### H3, Single-anchor hot-cell contention / mass-exit serialization · ⚙️ performance
Real, but with the escape hatch it is throughput, not trust. **Mitigation:** anchor
sharding by key prefix + batched force-exit. Phase 6.

### H4, No operator bond, unincentivized watchers · ✅ eliminated
Neither is needed. There are no watchers to incentivize and no fraud game to bond, 
validity is proven, not challenged.

### H5, Missing domain separation / canonical serialization · ✅ eliminated
All signed messages are domain-separated (`keccak("LIQUIDCELLS/v1/<purpose>")`) and
bound to `chain_id`/`pool_id`. All hashed structures use explicit fixed-width
big-endian layouts. Implemented in [`types.rs`](../crates/stf/src/types.rs).

---

## Medium

### M1, Batch cycle/proving budget · ⚙️ performance
`MAX_LEAVES_PER_BATCH` will be fixed from real SP1 cycle measurements in Phase 1
(secp256k1 verification dominates). Logged, never silently truncated.

### M2, Operator-held-intent inclusion timing · ✅ addressed
`expiry` is a mandatory field checked against `current_epoch`; strict per-account
nonce ordering prevents reordering/holding for advantage. Implemented in the STF.

### M3, Fee rounding & fee-accumulator conservation · ✅ addressed
Fees are explicit integer shannons (no implicit percentages in v1), and `fee_acc` is
inside the conservation invariant (`Σ balances + fee_acc == total`), so a fee bug
cannot mint value, it fails the conservation check. Tested.

### M4, Deposit reorg → phantom balance · 🟡 scheduled
Deposits will only be folded into a batch after a conservative confirmation depth.
Enforced by the sequencer + checkpoint logic in Phase 2.

### M5, Challenge window needs `since` + dispute lock · ✅ simplified away
No challenge window for validity. The escape-hatch timeout uses epoch-based `since`;
force-exit is a plain SMT inclusion check, not an HTLC dispute. Phase 3.

### M6, Two-phase exit double-count · 🟡 scheduled
v1 withdrawals are single-step (debit + bound output in the same proven batch), so
there is no pending/finalize gap to double-count. A `locked_balance` field for escrow
flows is deferred and will be part of the proven state if added.

### M7, Single-key blast radius · 🟡 scheduled
The sequencer key only orders transactions; it cannot steal. Sequencing can become
permissionless (anyone submits a valid batch+proof) in Phase 6, removing even the
liveness dependency.

---

## Low

### L1, SMT key grinding · ✅ eliminated
Keys are `keccak(pubkey)`, randomizing placement; `participant_id` is not
attacker-chosen. Implemented.

### L2, Confiscatory dust/inactivity fees · ✅ removed
No inactivity or dust-consolidation fees. Fees are explicit per-transfer/withdrawal
only and are conserved.

---

## Residual trust (irreducible)

* secp256k1, keccak-256, and Groth16 soundness.
* Nervos CKB Layer-1 liveness and consensus.

Everything else the operator might have been trusted for has been removed by design.
