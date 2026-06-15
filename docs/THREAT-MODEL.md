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

### M4, Deposit reorg → phantom balance · ✅ addressed
Deposits are folded into a batch only after a conservative confirmation depth.
`PendingDeposits` (`crates/sequencer/src/pending.rs`) gates a deposit until it is `depth` blocks
deep before it may be sealed, and `prune_above` drops deposits orphaned by a reorg before they ever
seal, so a short reorg that removes a deposit (and any checkpoint sweeping it) cannot leave the
sequencer crediting a deposit absent from the canonical chain. Chain-agnostic (the operator's L1
watcher supplies heights + tip; no RPC in the crate); a reorg deeper than `depth` (far beyond CKB's
practical finality) falls back to the heavier resume-from-L1-DA path (`Sequencer::resume`).

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

### L2b, Zero-fee checkpoint griefing / operator sustainability · 🟡 mitigated (policy now, proof staged)
The proven STF charges whatever `fee` an intent carries with **no minimum**, so a flood of valid,
funded, *zero-fee* transfers/HTLC-locks each cost the operator a touched leaf's DA + cycles while
adding nothing to `fee_acc`. This is a **sustainability / griefing** gap, **not a fund-safety** one
(`fee_withdrawal` stays capped at fee revenue, so no balance is ever skimmed). Mitigated in two
layers: a **live** sequencer admission floor (`liquid_cells_sequencer::FeePolicy`, rejects/drops
underpayers, policy, off by default), and a **staged provable** floor (`liquid_cells_stf`
`min_fee` feature, `MIN_FEE_PER_LEAF`) that is OFF in the deployed guest (it re-bakes the vkey) and
bundled for the next coordinated upgrade. Both pin to the same constant. See [FEES.md](FEES.md).

### L3, ECDSA high-S signature malleability · 🟡 fix staged (vkey re-bake)
`sig::verify` (`crates/stf/src/sig.rs`) *normalizes* a high-S signature to low-S and then
verifies it, so both encodings of a signature pass, contradicting its own comment ("only the
low-S form verifies"). Impact is **transaction-ID (signature-bytes) malleability only**: it
grants no debit, replay, or value creation, because every state effect is keyed by the signed
message + the leaf nonce (which blocks replay of a mutated copy), and the signature is never
committed to any on-chain fact (the DA blob is `key‖balance‖nonce`; public values carry no
signature). Found by the internal red-team. The fix (reject high-S outright, so only the
canonical low-S encoding verifies) is **implemented and tested behind the `reject_high_s`
feature** (`cargo test -p liquid-cells-stf --features reject_high_s`; `tests/high_s.rs`
malleates a real low-S signature to `(r, n-s)` and asserts it is rejected while legit low-S
flows stay green). Because it changes the STF and therefore re-bakes the guest vkey, the
feature is **OFF in the deployed guest** (vkey `0x00213af5…` unchanged, asserted by
`verify-vkey.sh`), staged to flip on in the coordinated post-audit re-bake bundle alongside
the compact SMT and the in-proof `min_fee` floor.

## Adversarial red-team (internal)

Before opening to the community, an internal red-team built **56 adversarial test cases** that
run real malicious transactions/batches against the contract in CKB-VM (and the STF in-process)
across four surfaces: checkpoint accounting/fee/solvency, the force-exit/force-refund escape
hatches + epoch/`since` handling + anchor-capture, the deposit lock + pool isolation + DA
binding, and the STF safety invariants + contract public-input binding. **No exploitable break
was found**, every fund-safety and capture-proofness invariant held. The tests live alongside
the existing suites (`crates/ckb-contract-tests/tests/redteam_*.rs`, `crates/stf/tests/redteam.rs`)
as permanent regression coverage. Four findings, all low/informational, none enabling fund loss:

* **L3 above**, high-S signature malleability (txid-only).
* **Legacy (empty-args) pools share one anchor type hash**, so a deposit can be swept into a
  *different legacy pool* of the same contract (the depositor is still credited there, recoverable
  by force-exit, not third-party theft). Eliminated by **type-id'd pools** (distinct hashes;
  proven by the `sweep_into_a_foreign_pool_rejected` test and demonstrated live on Pudge).
* **The deposit lock's sweep predicate is deliberately loose** (it unlocks on any input bearing
  the pool's type hash and does not check the sweep destination); safety is **delegated to the
  anchor type script's solvency/commitment checks**, which the red-team confirmed backstop it (a
  diversion-to-attacker tx is rejected). A hard invariant to preserve across future changes.
* **The force-exit epoch cap relies on CKB consensus** rejecting an absolute-epoch `since` before
  its epoch, a standard, correct CKB pattern, and the one defense not fully self-contained in the
  contract.

A further follow-up considered whether a draining pool could strand the last exiter by pushing the
anchor below its occupied capacity. It cannot: GENESIS forces `total == 0`, every mode preserves
`slack = capacity − total`, so `capacity ≥ slack ≥ occupied` always and a full drain leaves a valid
anchor. Documented in `escape.rs` and proven by `crates/ckb-contract-tests/tests/redteam_drain.rs`.
The genuine sub-≈61-CKB limit is the force-exit *payout* cell, the **C1** dust-egress case above.

Scope honesty: this is an internal logic-bug red-team, **not** a substitute for external audit. It
does **not** cover BN254 field-arithmetic soundness of the verifier or game-theoretic/economic
attacks, those remain for formal review and the public program.

---

## Residual trust (irreducible)

* secp256k1, keccak-256, and Groth16 soundness.
* Nervos CKB Layer-1 liveness and consensus.

Everything else the operator might have been trusted for has been removed by design.
