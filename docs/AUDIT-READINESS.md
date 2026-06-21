# Liquid Cells: Audit-Readiness Assessment

**Target:** Liquid Cells, a fully-trustless pooled-balance zk-rollup on Nervos CKB (SP1 validity proofs + on-chain data availability + a CKB anchor type script verifying a Groth16 BN254 proof)
**Status:** Live on Pudge testnet, UNAUDITED, no value at risk
**Scope of this report:** 15 findings confirmed by adversarial cross-verification (at least 2 of 3 independent lenses agreed each is real, exploitable, and security-relevant), drawn from 26 raw findings
**Date:** 2026-06-15

---

## 1. Executive Summary

The core trust machinery of Liquid Cells is sound. The on-chain checkpoint-continuity and accounting path (anchor binding, sequence monotonicity, value conservation, solvency, fee accounting, reward bounding, DA commitment, and the Groth16 proof binding to the in-circuit STF) was reviewed end-to-end against the proven program and found to enforce every safety invariant in scope, with no exploitable theft, inflation, root-forgery, or freeze in that dimension. The escape-hatch SMT walk is byte-identical to the in-circuit verifier, so force-exit and force-refund proofs reconstructed from L1 DA verify on-chain. This is corroborated by a substantial red-team suite. The hard cryptographic and accounting work is genuinely done.

However, the system is **not yet ready to hand to an external auditor without first closing a small number of concrete defects**, and it is emphatically **not ready for mainnet value** until the upgrade key is locked down.

The headline issues:

- **One critical operational gap:** the live anchor code cell is upgradable in place under a single plain secp256k1 key with no timelock. Whoever holds (or steals) that key can swap in an always-accept verifier in one block and drain every pool. The mitigation (`upgrade_lock.rs`) is built and tested but not deployed. This is the single largest fund-loss vector and the team already names it as such.
- **Two high-severity protocol defects on the proven path / on-chain logic:** (a) an HTLC escrow leaf can be permanently frozen by a 1-unit transfer into its `htlc_id` key (keyspace collision between accounts and escrows), and (b) the force-exit / force-refund escape modes place no bound on non-anchor inputs, letting an attacker sweep unswept deposit cells to themselves during the operator-silence window.
- **A cluster of off-chain and economic hardening gaps** (unauthenticated deposit ingest, unbounded request body / single-threaded DoS, zero-fee griefing default, a swap timeout-margin integer overflow) that are real but bounded: none break the on-chain trust model, but they degrade operator liveness/integrity and must be hardened before any public deployment.
- **Several low/info residuals** that are documented, accepted, or pure defense-in-depth (legacy empty-args pool isolation, sub-61-CKB dust egress, overflow-checks=false, decoder pre-allocation, reorg-depth boundary).

Net posture: **strong cryptographic and accounting core, with a clear and finite pre-audit punch list.** Fix the two high-severity proven-path defects and harden the off-chain ingest surfaces before engaging an auditor; lock the upgrade key before mainnet.

---

## 2. Confirmed Findings by Corrected Severity

Severities below are the verifier-corrected values. Where the three lenses disagreed, the rationale for the chosen severity is given.

### CRITICAL

#### C-1. Live anchor code cell controlled by a single plain key with the timelock not applied (instant malicious-verifier swap drains every pool)

- **Location:** `DEPLOY.md` "Notes" section (deploy state: in-place type-id upgradability + the single deployer key); `crates/ckb-contract/src/upgrade_lock.rs:1-121` (the built-but-unused mitigation)
- **Impact:** The anchor type script is deployed type-id and is upgradable in place by spending its code cell (this is exactly how it has already been upgraded repeatedly). The live code cell is locked by the deployer's plain `secp256k1_blake160` lock. Whoever holds or steals that one key can, in a single transaction with no announcement window, replace `verify_sp1_groth16` with an always-accept verifier (`program_entry` returning 0 unconditionally). The next checkpoint then proves nothing: the attacker advances the root to credit themselves the entire pool total and withdraws it. Lock continuity (`main.rs:295-305`) only pins the anchor cell's lock, never the code cell, so it gives zero protection. Every pool sharing this code hash drains at once. The force-exit escape hatch does not help: it opens only after a ~180-epoch (~30-day) silence window, while the malicious swap lands in the next block.
- **Severity note:** Verifiers split critical/high. Code-truth confirmed every claim. The two who said "high" did so only on deploy-state context (testnet-only, no value at risk, a fresh dedicated testnet key, and the most-disclosed scheduled residual). On any value-bearing deployment this is unambiguously critical, which is the rating that matters for the mainnet gate.
- **Fix:** Before any value is at risk, migrate the live code cell's lock to `liquid-cells-upgrade-lock` with `delay_epochs` comfortably greater than `FORCE_EXIT_TIMEOUT_EPOCHS` (180) AND a multisig `governance_lock_hash`, exactly as `UPGRADE-TIMELOCK.md` prescribes. The timelock guarantees a force-exit window; the multisig removes single-key control. Until then the system must be treated strictly as testnet.

---

### HIGH

#### H-1. HTLC escrow leaf can be permanently frozen by a 1-unit transfer/deposit into its `htlc_id` key

- **Location:** `crates/stf/src/transition.rs:175-177` (transfer credit), `:238/:269` (claim/refund balance discriminator), `:133-138` (deposit credit)
- **Impact:** HTLC escrows and ordinary accounts share the same 256-bit SMT keyspace with no structural discriminator. An escrow is keyed by `htlc_id = keccak(domain || pool_id || sender || receiver || amount || hashlock || timeout || nonce)`; accounts by `keccak(pubkey)`. The transfer path blindly does `work[to_key].balance = balance.checked_add(amount)` for any `to_key`, and claim/refund identify the escrow purely by `escrow.balance != h.amount || escrow.nonce != 0`. A signed `Transfer{to_key=htlc_id, amount=1}` bumps the balance to `amount+1`, after which **both** claim and refund return `HtlcMissing` forever. The leaf cannot be debited (its key is an `htlc_id`, not `keccak` of any pubkey, so no signature verifies against it), and crucially **the escape hatch cannot recover it either**: `force_refund` requires the leaf to hash to exactly `leaf_hash(amount, 0)` (inclusion fails at `amount+1`), and `force_exit` keys by `keccak(pubkey)` and cannot address an `htlc_id` leaf. The escrow key is public (written verbatim into the DA blob), so the attacker needs only the 32-byte key, not the lock secrets, at negligible cost. The sequencer admission filter (`resilient.rs:82-119`) applies identical logic and does not drop these, so the freezing transition is admitted, proven, and verified on-chain as a valid checkpoint. A front-run variant pre-credits a predicted `htlc_id` so the legitimate `htlc_lock` hits the `HtlcExists` guard.
- **Severity note:** All three lenses confirmed high. Not critical because value conservation holds (the funds are frozen/griefed, not stolen or inflated, and the attacker's injected unit is also frozen), and it is confined to the optional in-pool HTLC/atomic-swap feature, not the core deposit/transfer/withdraw custody path.
- **Fix:** Domain-separate the escrow keyspace from the account keyspace so a user-chosen `Transfer`/`Deposit` destination can never name an escrow slot. Either (a) carry a leaf kind/discriminator byte and match claim/refund on it rather than an exact-balance equality, or (b) reject any transfer/deposit whose `to_key` is currently an occupied escrow / has an `htlc_id` shape, or (c) store escrows in a structurally separate sub-tree / reserved key prefix. Add a red-team test: lock an escrow, transfer 1 unit into its id, assert claim and refund still succeed (currently they do not).

#### H-2. Force-exit / force-refund let an attacker steal any unswept deposit cell (escape modes never bind non-anchor inputs)

- **Location:** `crates/ckb-contract/src/escape.rs:135-145` (force_exit solvency), `:273-283` (force_refund solvency); enabled by `crates/ckb-contract/src/deposit_lock.rs:79-91` (sweep path) and `main.rs:319-324` (mode dispatch; no `fold_cells` in escape modes)
- **Impact:** The deposit lock's sweep path unlocks a deposit cell whenever ANY input bears the pool anchor type hash, and never inspects where the deposit's capacity goes; its safety is wholly delegated to the anchor type script. That delegation holds only in **checkpoint** mode, where `fold_cells` credits every non-anchor input as a deposit and solvency (`out_cap - in_cap == sum_dep - sum_wd - fee_wd`) forces the deposit's capacity into the anchor. The **force_exit and force_refund modes do not call `fold_cells`** and their solvency checks are anchor-local only (`in_cap - balance == out_cap` on the GroupInput/GroupOutput anchor). They place zero constraint on extra non-anchor inputs or their destinations. So during the ~30-day operator-silence window (or after griefing a permissionless pool into silence), an attacker holding any exitable leaf or timed-out HTLC submits a single force_exit/force_refund that ALSO consumes victim deposit-lock cells, routing each deposit's capacity to an attacker output. The anchor-local solvency holds (anchor drops only by `balance`), CKB capacity conservation holds (capacity is merely re-routed), and `fold_cells` never runs so the depositors are never credited. The deposit funds are stolen by a third party, and unrecoverably (the depositor has no leaf to force-exit). The project's own red-team backstop (`redteam_deposit_e2e.rs`) only ever placed a deposit input in a checkpoint tx, never an escape-mode tx, so the gap was missed. This contradicts the deposit lock's own documented invariant ("Neither path can send the funds to an arbitrary third party").
- **Severity note:** All three lenses confirmed high. Bounded by the ~30-day operator-silence precondition and limited to unswept/pending deposit cells (not the committed pool balance), which is why it is high rather than critical.
- **Fix:** Make the escape modes reject any non-anchor input. After loading the GroupInput anchor in `force_exit`/`force_refund`, enforce a canonical shape: exactly `{anchor_in} -> {anchor_out, single payout}`, or require `Σ inputs == anchor_in_cap` and `Σ outputs == anchor_out_cap + payout`, so no stray capacity can be siphoned. Defense in depth: tighten the deposit lock so its sweep path unlocks only when the anchor is being consumed in checkpoint mode (e.g. require the anchor input's witness length == `WITNESS_LEN`). Add a red-team test that appends an extra deposit-lock input to an otherwise-valid force-exit and asserts rejection.

---

### MEDIUM

#### M-1. Unauthenticated `/submit` deposit lets anyone mint pool balance in the off-chain committed state

- **Location:** `crates/sequencer-service/src/lib.rs:42-70` (`Intent::Deposit -> submit_deposit`), with `crates/sequencer/src/lib.rs:222-224` and `crates/stf/src/types.rs:98-101`
- **Impact:** The `Deposit` intent carries only `{to_key, amount}` and no signature; its only legitimate authority is the consumed on-chain deposit cell. The HTTP `/submit` endpoint accepts a deposit from any anonymous client and pushes it straight into the mempool; the next `seal_batch` folds it, advances the committed root, and increases `pool.total` by the attacker-chosen amount. The proper deposit-authority path (the L1-watcher `PendingDeposits` confirmation-depth gate in `pending.rs`) is not wired into the service at all. **Critically, the on-chain layer caps the damage:** a checkpoint can only seal if the proven `deposits_commitment` equals the commitment recomputed from real consumed L1 input cells (`main.rs:368`), plus value conservation and solvency-vs-real-capacity. A phantom deposit therefore can never be sealed on-chain, so there is no on-chain inflation, theft, or forged root. The real impact is off-chain integrity/liveness: an attacker can wedge the operator's in-memory committed state and DA history with an unbacked root that no honest checkpoint can ever finalize, and any client reconstructing from `/da` sees a phantom balance.
- **Severity note:** Verifiers split medium/low/medium. The service docstring frames `/submit` as "THE production path", and it is a genuine missing-authorization defect on a production-framed ingress, but it cannot reach on-chain fund safety and lives in an explicitly demo/local single-threaded service. Medium is the right calibration.
- **Fix:** Do not accept `Deposit` over the public submit endpoint. Have `Service::submit` reject `Intent::Deposit` and add an internal, non-HTTP `submit_confirmed_deposit(cell_outpoint, to_key, amount)` called only from the confirmed-L1 ingestion path, gated behind the existing confirmation-depth check.

#### M-2. Escape-mode transactions place no bound on extra inputs/outputs (capacity siphoning beyond deposits)

- **Location:** `crates/ckb-contract/src/escape.rs:91-170` (force_exit), `:223-311` (force_refund)
- **Impact:** The standalone root cause behind H-2: both escape handlers validate only the single anchor cell and the existence of one payout output (`has_exit_output`); they impose no structural constraint on the rest of the transaction (no total-input-capacity sum, no output restriction). Any cell whose own lock is satisfiable by the mere presence of the anchor input (concretely, the deposit lock) can have its capacity freely redirected. The escape hatch is meant to be a minimal, surgical, single-purpose transaction, but nothing enforces that minimality on-chain. The concrete, demonstrated case today is the deposit-lock cell; the generalization to "any future anchor-keyed lock" is plausible but speculative.
- **Severity note:** All three lenses agreed medium. Gated by the ~30-day escape window and an unswept-deposit precondition, with the depositor's own refund path racing the attacker once the deposit timeout matures.
- **Fix:** Constrain escape-mode transactions to a canonical shape (exactly one anchor input, exactly two outputs: new anchor + single payout), or enforce `Σ input capacity == anchor_in_cap` and `Σ output capacity == anchor_out_cap + balance`, rejecting anything else. This also fully resolves H-2.
- **Shipped vs. recommended (reconciliation, 2026-06).** What actually shipped is the *defense-in-depth* half: the deposit-lock checkpoint-mode gate (`deposit_lock.rs`), which closes the one concrete vector (a deposit cell cannot be released into an escape-mode tx). The canonical-shape bound above is **NOT** implemented in `escape.rs` and is now carried as a **documented residual** (`COMPLETION.md`), not because it was forgotten but because a strict "reject non-anchor inputs" bound conflicts with the escape tx needing a non-anchor input to pay the CKB miner fee (the anchor cannot fund it without breaking solvency); a strict bound would force a 0-fee tx that default nodes will not relay, crippling the escape hatch. Residual statement: any FUTURE anchor-keyed lock must self-gate on checkpoint mode as the deposit lock does. Flagged as an external-audit item rather than a pre-audit code change.

#### M-3. Zero-fee griefing defense disabled in the live default configuration (both layers off)

- **Location:** `crates/sequencer/src/lib.rs:187-194` (`Sequencer::genesis -> FeePolicy::disabled`); `crates/stf/src/transition.rs:67-68,155-158` (`MIN_FEE_PER_LEAF` behind the `min_fee` feature, OFF)
- **Impact:** The in-proof minimum-fee floor is behind the `min_fee` cargo feature, which is OFF in the deployed guest (consistent with `VKEY_HASH 0x00213af5`). The sequencer-side `FeePolicy` is the only other defense, but `genesis`/`resume` both install `FeePolicy::disabled()` (floor 0), which short-circuits to admit everything. So shipped defaults enforce no fee floor at either layer, and the live driver (`sp1-host/src/bin/sequence.rs:76`) never sets a policy. An attacker funding a handful of accounts can stream valid, nonce-incrementing, zero-fee transfers indefinitely; each costs the operator one leaf of DA + ~0.62M SP1 cycles + L1 fee while `fee_acc` never grows, and `fee_withdrawal` is provably capped at fee revenue (=0), so the operator cannot recoup and runs at a pure loss. No funds are stolen; the pool can be priced out of operation.
- **Severity note:** The finding was filed as medium; two of three verifiers corrected it to low (no safety-invariant break, trivial one-line operator mitigation via `with_fee_policy`/`set_fee_policy`, already documented as `THREAT-MODEL` L2b / `FEES.md` with the in-proof floor staged for the post-audit vkey re-bake). **Corrected severity: low.** Listed here adjacent to the economic cluster for context.
- **Fix:** Ship a non-zero `FeePolicy` by default (or refuse to seal until the operator sets one explicitly) and document the calibrated floor. Treat `FeePolicy::disabled()` as unsafe for any public/permissionless deployment until the in-proof `min_fee` floor is enabled at the coordinated re-bake.

---

### LOW

#### L-1. Legacy empty-args pools share one baked `POOL_ID` and anchor type hash (cross-pool deposit sweep / `htlc_id` collision)

- **Location:** `crates/ckb-contract/src/main.rs:92-95,190-202`; `crates/ckb-contract/src/deposit_lock.rs:24-30`
- **Impact:** For an empty-args pool, `pool_id()` returns the single baked `POOL_ID` constant, identical across every legacy pool, and all such anchors share one type hash. A deposit bound to legacy pool A can be swept into legacy pool B (same type hash) and credited to the depositor's `to_key` in B's tree. This is **not third-party theft** (the depositor is credited at their own key and can force-exit from B; solvency blocks diversion to an attacker), but it is a pool-isolation weakness, and `htlc_id` collisions are possible across legacy pools (same `POOL_ID` + same terms = same id). Explicitly acknowledged in `deposit_lock.rs` and the threat model.
- **Fix:** Already mitigated by type-id'd pools (32-byte args, distinct hashes via `anchor_type_id`), which the live deployments use. Deprecate empty-args pools for any non-test deployment and require the type-id path on mainnet. (Closely related to L-2; effectively two facets of the same legacy residual.)

#### L-2. Cross-pool sweep mitigation depends on an off-chain choice (type-id pools) for the deployed pool

- **Location:** `crates/ckb-contract/src/deposit_lock.rs:24-30,79-91`; `crates/ckb-contract/src/main.rs:190-202`
- **Impact:** Same mechanism as L-1, framed from the deployment angle: nothing in the deposit lock itself enforces the type-id choice, so the only thing preventing misrouting in an empty-args deployment is the operator's decision to use type-id'd anchors. Anyone can genesis a competing legacy pool and sweep a deposit into it; the depositor must then force-exit from a pool they never chose. No third-party theft; funds remain recoverable.
- **Severity note:** Verifiers split low/low/info. Low is defensible (real misrouting + recovery friction); one lens argued info since it is a documented, accepted, off-the-deployed-path residual.
- **Fix:** For mainnet, require deposits to bind to a type-id'd anchor (globally unique `pool_type_hash`); consider rejecting empty-args `pool_type_hash` in the deposit lock, or document prominently that production deposits MUST target a type-id'd pool. Enforce it rather than leaving it an operator choice.

#### L-3. Escape-hatch dust threshold: balances below the secp occupied-capacity floor (~61 CKB) are not force-exitable

- **Location:** `crates/ckb-contract/src/escape.rs:166` (force_exit), `:220` (force_refund), via `has_exit_output` at `:60-83`
- **Impact:** Both escape hatches require an output paying exactly `balance`/`amount` shannons to the owner's canonical secp lock. A bare `secp256k1_blake160` cell has a ~61 CKB occupied-capacity floor; CKB consensus rejects sub-occupied output cells. So a leaf below that floor has no constructable unilateral payout while the operator is dark. The code only guards `balance > u64::MAX` and `balance == 0`, not the lower dust bound, so the failure surfaces at tx-construction/consensus time, not as a contract diagnostic. This is not theft (no one else can take it either) and is an inherent CKB cell-model constraint, documented as `THREAT-MODEL C1` / dust-egress with a cooperative in-pool HTLC dust-egress mitigation. It only bites if the operator both freezes for 180 epochs AND refuses the cooperative dust-egress path.
- **Fix:** Document the lower bound at the witness-validation site and ideally emit an early diagnostic return code (mirroring codes 60/61) when `balance < occupied floor`. For a real fix, allow the escape payout to be aggregated (batch several of an owner's dust leaves into one >=61 CKB payout, or let the payout capacity be `>= balance` with the surplus owner-funded) so dust remains rescuable unilaterally.

#### L-4. Swap timeout-margin integer overflow defeats the `fiber < pool` ordering guarantee

- **Location:** `crates/client/src/swap.rs:111` (`SwapTerms::validate`), `:297` (`decide_taker`)
- **Impact:** The swap safety invariant `fiber_timeout < pool_timeout` is enforced as `fiber_timeout + MIN_TIMEOUT_MARGIN > pool_timeout` using unchecked `u64` addition. With `fiber_timeout` near `u64::MAX` the addition wraps in release (`overflow-checks` is not set in the workspace release profile) and panics in debug, so a huge `fiber_timeout` passes the margin check against a small `pool_timeout`, inverting the ordering. Verifiers found the end-to-end fund-freeze impact **overstated**: `SwapTerms` is never on the wire (not in `wire.rs`/WASM), the only producer is `SwapTerms::propose` from local constants in a single process, and the real `FiberLeg::lock` ignores its `_timeout` argument (the on-network HTLC is bounded by the Fiber invoice expiry), with `decide_taker` independently re-checking the observed on-chain pool lock's timeout. No on-chain/STF invariant depends on `fiber_timeout`.
- **Severity note:** Filed medium; corrected to low by all three lenses (a genuine latent defensive-coding defect on a currently locally-trusted value, with no exploitable end-to-end path today, but one that becomes load-bearing if a remote maker-proposes-terms negotiation layer is later added).
- **Fix:** Use `checked_add`/`saturating_add` in both sites and treat overflow as a failed check (not a pass): `if self.fiber_timeout.checked_add(MIN_TIMEOUT_MARGIN).map_or(true, |t| t > self.pool_timeout) { return Err(...) }`. Additionally bound-check absolute timeout magnitudes so a taker never locks a payment whose refund epoch is effectively unreachable.

#### L-5 (down-rated from "high" as filed). Unbounded request body + single-threaded blocking loop = memory / liveness DoS on the sequencer service

- **Location:** `crates/sequencer-service/src/bin/lc-sequencer-service.rs:65-70`
- **Impact:** The server processes requests one at a time and reads the entire body with `read_to_string` with no Content-Length cap, no max-body limit, and no read timeout; there is no mempool size cap, and validation is deferred to seal. Three vectors: (1) a multi-GB body OOM-kills the process; (2) a slow-loris dribble wedges the single loop and denies all other clients; (3) a flood of well-formed junk grows the mempool unbounded until OOM. All three are real as written. **But the impact is bounded to liveness of one off-chain demo process:** it breaks no safety/trust invariant (no theft, no forged roots, no debit-without-sig), the sequencer is already untrusted by design, and liveness is double-backstopped (force-exit lets users exit against the last committed root without the sequencer; permissionless lock-continuity lets anyone else advance the root). The crate explicitly documents itself as single-threaded "all a local/demo sequencer needs".
- **Severity note:** Filed high; corrected to low by two of three lenses (the third said medium). The "chain-halt" framing in the title is misleading: the CKB chain does not halt and funds are not frozen. Low/medium; we record it as low given the trust-path independence and the built-in escape-hatch backstop, while flagging it as a **must-fix before any public exposure** (it binds 0.0.0.0).
- **Fix:** Cap the body (`take(MAX_BODY)`, 413 on overflow), set a per-request read timeout, bound the mempool (429 once `pending()` exceeds a limit), move request handling off the accept loop (a small worker pool), and front the service with a reverse proxy enforcing body-size and timeout limits.

---

### INFO (confirmed real, no present exploit / pure hardening)

#### I-1. Anchor checkpoint continuity + accounting reviewed end-to-end: sound, no exploitable theft/inflation/forge/freeze

- **Location:** `crates/ckb-contract/src/main.rs:330-416`, `crates/ckb-contract/src/cells.rs:30-140`
- **Assessment:** A full review of the checkpoint/escape accounting path against the in-circuit STF and the Groth16 verifier confirmed every in-scope safety invariant is enforced and cross-checked: anchor binding both ways; sequence monotonicity (`new == prev+1` via `checked_add`, input anchor a consumed UTXO so no replay/skip); `pool_id` binding to baked `POOL_ID` or a genesis-unique type-id; value conservation AND independent capacity solvency (both order-independent); fee accounting with overflow guards; reward split bounded by `sum_reward <= fee_wd` and excluded from solvency; DA commitment (including the `output_type=None` empty case); deposit/withdrawal commitments recomputed from real cells; Groth16 verify pinning `VKEY_HASH`, `VK_ROOT`, and `exit_code==0`. The escape-hatch SMT walk is byte-identical to the in-circuit `verify_proof` (including empty-leaf and bit-ordering), so force-exit/refund proofs from L1 DA verify on-chain. The epoch clock cannot be pushed forward or backward. All witness slicing is length-validated by exact mode length before fixed-offset reads, so no reachable panic on attacker data. No exploit found.
- **Note:** This is the single most important positive result in the assessment. One verifier voted "not-a-bug" (it is an info-level "no-bug" assessment, not a defect); two affirmed info. Carry into external audit scope: BN254 field-arithmetic soundness of the verifier (out of scope here), the force-exit epoch cap's reliance on CKB consensus rejecting an absolute-epoch `since`, and the legacy empty-args shared anchor hash (L-1/L-2).

#### I-2. Contract release profile sets `overflow-checks = false`; safety relies entirely on explicit `checked_*` / `i128` widening

- **Location:** `crates/ckb-contract/Cargo.toml:44`; `crates/ckb-contract/src/main.rs:385-413`; `crates/ckb-contract/src/cells.rs:45-72`
- **Assessment:** The deployed contract is compiled with `overflow-checks=false`. The accounting fold uses unguarded `i128 +=` on `u64` capacities; this is physically unreachable to overflow today (i128 sums of u64 capacities under CKB block limits stay ~38 orders below `i128::MAX`), and the totals are proof-bound (the STF uses `checked_*` throughout and binds deposit amounts to real u64 cell capacities). The risk is purely latent: a future raw-`u128` add or fee multiply on attacker-influenced public values would wrap silently instead of aborting. Two lenses corrected low to info (no present or near-realizable exploit). **Corrected severity: info.**
- **Fix:** Keep all accounting in the widened `i128` form and prefer `overflow-checks=true` in the contract release profile (the cycle cost is negligible relative to the BN254 pairing), or add an invariant test that every op on public-value-derived quantities is `checked_*`/`i128`-widened.

#### I-3. Guest input decoder pre-allocates Vec capacity from an unvalidated u32 length prefix (prover-local only)

- **Location:** `crates/stf/src/codec.rs:113-124,198-254`
- **Assessment:** `decode_input`/`dec_witness`/`dec_batch` read a u32 count and immediately `Vec::with_capacity(count)` before consuming any element bytes; `MAX_LEAVES_PER_BATCH=1024` is enforced only later in `transition_inner`. A near-`u32::MAX` count requests a multi-GB allocation that can abort before the bounds check. The mechanism is real, but verifiers found the threat surface overstated: this decoder runs only in the SP1 guest (self-supplied input, crashes only that prover's own process; the anchor verifies the proof, not the input) and in the operator's own local journal replay. The claimed "sequencer-service network path" does **not** use this codec (the HTTP front parses JSON via `wire::intent_from_json`, not the binary codec). **Corrected severity: info** (a robustness nit with no attacker-reachable consequence).
- **Fix:** Optional hardening: cap the count against `MAX_LEAVES_PER_BATCH * small_factor` (or use `Vec::new()` + push) before allocating.

#### I-4. Deposit confirmation-depth gate cannot retract already-promoted deposits on a deep reorg (operational boundary)

- **Location:** `crates/sequencer/src/pending.rs:70-92`
- **Assessment:** `take_ready` removes a deposit from the pending set once it reaches `depth` confirmations, after which `prune_above` can no longer touch it. A reorg deeper than `depth` that orphans an already-promoted deposit leaves the local sequencer crediting a deposit absent from canonical L1; it can no longer produce a matching checkpoint (the on-chain `deposits_commitment` recomputed from real cells will not match) and must fall back to the heavier `Sequencer::resume` from L1 DA. The on-chain commitment check is the hard safety boundary: no phantom deposit can ever be proven, so there is no inflation or theft, only an interrupted-liveness recovery. Filed low; verifiers split low/low/info.
- **Fix:** Set `depth` conservatively above any plausible CKB reorg depth (already intended). Optionally have the durable/resilient path detect a commitment-vs-cell mismatch and trigger `resume` automatically. Keep the on-chain deposits-commitment check as the hard boundary it already is.

---

## 3. Area-by-Area Readiness Table

| Area | Readiness | Key findings | Notes |
|---|---|---|---|
| **Groth16 verifier (BN254)** | Audit-ready for engagement; field-arithmetic soundness NOT independently verified here | I-1 (verify pins `VKEY_HASH`/`VK_ROOT`/`exit_code==0`) | The proof-binding logic is correct. BN254 pairing/field-arithmetic soundness and the precomputed `e(alpha,beta)` optimization are explicitly **out of scope** for this assessment and must be a primary external-audit focus. |
| **Checkpoint accounting / continuity** | Audit-ready | I-1 (sound), I-2 (overflow-checks hardening, info) | Every in-scope invariant enforced and cross-checked. Re-enable `overflow-checks` as defense-in-depth. |
| **Escape hatches (force-exit / force-refund)** | NOT ready: one high, one medium, one low | **H-2** (deposit theft), **M-2** (no input/output bound), **L-3** (dust floor) | The SMT walk itself is byte-identical to the in-circuit verifier and sound; the **transaction-shape** constraints are the gap. Fix M-2/H-2 (canonical shape) before audit. |
| **STF invariants (proven program)** | NOT ready: one high | **H-1** (HTLC escrow freeze via keyspace collision) | Core custody invariants (no-debit-without-sig, value conservation) hold; the defect is keyspace separation between accounts and escrows. Fix before audit. |
| **Permissionless / deposit-lock** | Mostly ready; legacy residuals | **H-2** (via deposit lock), **L-1**, **L-2** | Lock-continuity capture-resistance is sound. The loose sweep predicate is safe **only** under checkpoint mode (see H-2) and only fully isolated under type-id'd pools (see L-1/L-2). |
| **Off-chain: Fiber / WASM / wire / service / coordinator** | NOT ready for public exposure: medium + lows | **M-1** (unauth deposit mint), **M-3/low** (zero-fee), **L-4** (swap overflow), **L-5** (DoS) | None break the on-chain trust model, but the service binds 0.0.0.0 with no auth, body cap, or mempool bound. Harden before any networked deployment. Note these are explicitly demo/local-grade today. |
| **Economic / incentive / liveness** | Hardening needed; no safety impact | **M-3/low** (zero-fee griefing), I-4 (reorg boundary) | Fee economics hold only if a non-zero floor is actually enforced live. Ship a default `FeePolicy`. |
| **Crypto / supply chain** | NOT ready for mainnet: one critical | **C-1** (upgrade key, no timelock), I-2, I-3 | The single largest fund-loss vector. SP1 trusted setup and BN254 hardness are irreducible (see Section 5). |

---

## 4. Audit-Ready vs Fix-First: Prioritized Pre-Audit Punch List

### What is already audit-ready

- The **checkpoint-continuity and accounting core** (I-1): anchor binding, sequence monotonicity, value conservation + solvency, fee/reward bounding, DA commitment, and Groth16 proof-binding to the in-circuit STF. This is the strongest part of the system and can be handed to an auditor as-is (with the BN254 soundness caveat flagged for them).
- The **escape-hatch SMT walk** itself (byte-identical to the in-circuit verifier). The cryptographic reconstruction is sound; only the surrounding transaction-shape constraints need work (M-2/H-2).
- **Lock-continuity / permissionless capture-resistance** (sound; demonstrated unsigned on Pudge).
- The **red-team suite** is substantial and a genuine asset for the audit, with two known coverage gaps to add (see below).

### Fix BEFORE engaging an external auditor (prioritized)

1. **(High) H-1: domain-separate the HTLC escrow keyspace** from the account keyspace and add the regression test (lock escrow, transfer 1 unit, assert claim+refund still succeed). This is a proven-path fund-freeze and should not reach an auditor unfixed. Note this touches the proven program, so it requires a coordinated vkey re-bake.
2. **(High + Medium) H-2 / M-2: constrain escape-mode transaction shape.** Make `force_exit`/`force_refund` reject non-anchor inputs (canonical `{anchor_in} -> {anchor_out, payout}` or `Σ` capacity equalities), and as defense-in-depth gate the deposit-lock sweep on checkpoint mode. Add the red-team test (extra deposit-lock input on a valid force-exit asserts rejection). One fix resolves both findings.
3. **(Medium) M-1: remove `Deposit` from the public `/submit` endpoint** and route deposits only through the confirmed-L1 ingestion path with the existing confirmation-depth gate.
4. **(Low, but blocks public exposure) L-5: harden the sequencer-service** (body cap + 413, read timeout, mempool bound + 429, worker pool / reverse proxy). The service binds 0.0.0.0; do not expose it networked until this lands.
5. **(Low) M-3: ship a non-zero default `FeePolicy`** (or refuse to seal without one) so the live economics actually enforce a floor.
6. **(Low) L-4: use `checked_add`/`saturating_add` in `SwapTerms::validate`/`decide_taker`** and bound-check absolute timeout magnitudes. Cheap, and it removes a latent footgun before the swap-negotiation layer is built.

### Worth doing, but acceptable to carry into the audit as known items

- **L-1 / L-2:** require type-id'd pools for any non-test deployment; reject empty-args `pool_type_hash` in the deposit lock or document the requirement prominently.
- **L-3:** document the ~61 CKB dust floor at the witness-validation site (and ideally emit a diagnostic code); consider aggregated dust payout for a real fix.
- **I-2:** set `overflow-checks=true` in the contract release profile.
- **I-3:** clamp decoder pre-allocation.
- **I-4:** set `depth` conservatively and optionally auto-trigger `resume` on a commitment mismatch.

### Must be resolved before MAINNET (not a precondition to start the audit, but the mainnet gate)

- **C-1: lock down the upgrade key.** Migrate the live anchor code cell to `liquid-cells-upgrade-lock` with `delay_epochs > 180` AND a multisig `governance_lock_hash`. This is sequenced last by design (locking blocks further iteration), but it is the single largest fund-loss vector and **no value may be placed at risk until it is done.**

---

## 5. Known / Accepted Residuals and Irreducible Trust Assumptions

### Irreducible trust assumptions (cannot be code-fixed; carry into audit scope explicitly)

- **SP1 trusted setup:** the system inherits the soundness of SP1's Groth16 trusted setup ceremony. A compromised setup would let an attacker forge proofs. This is foundational and out of scope for code review; it must be acknowledged in the audit and addressed operationally (ceremony provenance, transcript publication).
- **Cryptographic hardness:** BN254 pairing security and keccak/SMT collision resistance are assumed. BN254 field-arithmetic **soundness of the on-chain verifier** (including the vendored/patched `bn` and the precomputed `e(alpha,beta)` optimization used to fit CKB's cycle budget) was explicitly out of scope here and should be a primary external-audit target.
- **CKB L1 consensus:** several guarantees rely on CKB behaving correctly, notably (a) the force-exit epoch cap relies on consensus rejecting an absolute-epoch `since` before its epoch (standard CKB pattern), and (b) the dust floor (L-3) and capacity conservation are CKB cell-model properties. A reorg deeper than the deposit confirmation depth (I-4) is an L1-driven operational boundary.

### Documented / accepted residuals

- **Upgrade key not yet locked (C-1):** explicitly the team's "single largest trust caveat", with the mitigation built (`upgrade_lock.rs`) but deliberately mainnet-last. Accepted on testnet only; **not** acceptable for value.
- **Sub-61-CKB dust egress (L-3):** an inherent CKB cell-occupancy constraint; the unilateral escape hatch cannot rescue dust below the secp floor, mitigated cooperatively by the in-pool HTLC dust-egress leg. Documented as `THREAT-MODEL C1`.
- **Legacy empty-args pool isolation (L-1/L-2):** shared `POOL_ID`/anchor hash and possible `htlc_id` collisions; no third-party theft, fully closed by type-id'd pools, which the live deployments use.
- **Zero-fee griefing (M-3):** an operator-sustainability concern with a one-line operator mitigation and a staged in-proof floor (`min_fee`) deferred to the post-audit vkey re-bake; documented as `THREAT-MODEL` L2b / `FEES.md`.
- **Deep-reorg deposit boundary (I-4):** handled by `resume`-from-DA; the on-chain commitment check is the hard safety backstop, so the worst case is interrupted liveness, never inflation.
- **Off-chain demo-grade components (M-1, L-4, L-5):** the sequencer-service, swap coordinator, and Fiber adapter are explicitly local/demo grade; the sequencer is already untrusted in the trust model, and liveness is backstopped by force-exit and permissionless sequencing. These must be hardened before any networked/public deployment but do not affect on-chain fund safety.

### Honest residual the team already documents

- **HTLC force-claim:** the receiver-side "force-claim" is not expressible under a single anchor (the silence gate cannot open inside a short HTLC timeout), an architectural residual deferred to Phase 6. This is separate from H-1 (which is a fixable keyspace-separation defect, not an architectural limit).

---

## 6. v2-bundle follow-up audit (2026-06-15)

After the H-1 keyspace fix and the rest of the v2 vkey-rebake bundle were staged (the `htlc_keyspace` four halves, the `min_fee` floor, the `ecrecover` primitive, and the `compact_smt` / `reject_high_s` / `da_varint` / `htlc_sha256` representation features), that **new surface, which post-dates the report above and so was unaudited, got its own focused adversarial pass**: 5 diverse lenses (escape-hatch fund theft/freeze, STF sweep value-conservation, the four-halves cross-component coordination, vkey-neutrality discipline, and the min_fee/ecrecover code), each finding then verified by 3 independent refuters with a majority needed to confirm. 19 raw findings, 5 survived verification (deduped to 3 distinct issues), 14 refuted.

**Verdict: the new surface is sound.** No theft, inflation, double-spend, wrong-payee, or value-conservation break was found in the escape hatch, the STF sweep logic, or the contract. Specifically verified sound:

- **`htlc_keyspace` sweep-and-consume** (STF + sequencer claim/refund): the leaf is zeroed before crediting `escrow.balance`, so a hostile top-up surplus can neither freeze the claim/refund (the gate is `>=`, not `==`) nor be double-drained (a second op finds an empty leaf); the surplus reaches only the `htlc_id`-fixed counterparty and value is conserved. The earlier double-claim extraction bug does not recur.
- **On-chain `force_refund`** (`escape.rs`): the widened witness (`actual_balance` u128 at offset 129, siblings at 145, `FORCE_REFUND_LEN` 8337) binds the witnessed payout to the committed root by the SMT inclusion check, so a balance lie cannot verify; `actual < amount`, `amount == 0`, and `payout > u64::MAX` are all rejected; nullification to `{0,0}` prevents double-refund; anchor continuity debits `total` by exactly `payout`. Payout is forced to the sender's own secp lock.
- **`min_fee`** (Phase A): the floor is enforced in-proof only under the feature, the `MIN_FEE_PER_LEAF` const is dead-code-eliminated when off (vkey-neutral), `sponsor_fee` pays the floor, and the deferred zero-fee client legs are honestly documented as activation-time work.
- **`ecrecover`** (Phase B): `sign_recoverable` returns the low-S signature with the matching recovery id (no malleability window), `recover` validates the recovery id and returns `None` on malformed input, and authentication is correctly deferred to the caller deriving the SMT key from the recovered pubkey. No recovery-id or malleability flaw.

### Confirmed findings (all fixed, all vkey-neutral)

| ID | Severity | Area | Issue | Status |
|----|----------|------|-------|--------|
| V2-1 | Medium | sequencer mirror / feature coordination | The resilient-seal mirror (`resilient.rs`) hard-coded `keccak(preimage)` for the HTLC-claim hashlock check with no `#[cfg]`, and the sequencer crate had no `htlc_sha256` feature at all. The proven STF switches that exact check to `sha256` under `htlc_sha256`. Once the re-bake bundle (which flips `htlc_sha256` and `htlc_keyspace` on together) is the deployed guest, the resilient cadence would compute the wrong hash and silently DROP every valid SHA-256 HTLC claim, the Fiber dust-egress leg the feature exists to enable, as `BadPreimage` before it reached `seal_batch`. Liveness/censorship gap, not a safety break (the atomic `seal_batch` and the contract are unaffected), but it defeats the headline feature on the recovery path. The existing parity test masked it (keccak hashlock only). | **Fixed:** `crates/sequencer/Cargo.toml` forwards `htlc_sha256 = ["liquid-cells-stf/htlc_sha256"]`; `resilient.rs` gates the claim hashlock check with the same statement-level keccak/sha256 `#[cfg]` as the STF; added a `resilient_seal_settles_a_sha256_locked_claim` regression test and made the H-1 recovery test's hashlock feature-aware (it had latently hard-coded keccak). Green under default, `htlc_keyspace`, `htlc_sha256`, and the bundle combo. Off-chain only, vkey untouched. |
| V2-2 | Low | vkey-neutrality guard | `verify-vkey.sh` extracted only the single Cargo.toml line matching `liquid-cells-stf` then grepped it for vkey-affecting feature names. A `features = [...]` list spanning TOML continuation lines would not appear in that one line, so the cheap guard could pass while the guest compiled the feature in (the heavy full-rebuild check would still catch it, hence low). | **Fixed:** the guard now captures the whole inline-table dependency declaration (awk from the `liquid-cells-stf` line through its closing `}`) before grepping, so a multi-line `features` list is still scanned. `verify-vkey.sh` stays green. |
| V2-3 | Info | client ergonomics | `force_refund_witness` only checked `leaf.balance < amount` and returned a witness for any surplus, but the contract rejects a payout `> u64::MAX` (code 81), so the SDK could hand the user an unminable witness. No fund loss (the single-cell-capacity limit is correctly the contract's). | **Fixed:** the `htlc_keyspace` arm returns `None` when `leaf.balance > u64::MAX`, signalling "amount too large to escape as one cell" instead of emitting a witness that always fails on-chain. |

**Net:** the v2-bundle new surface adds no fund-safety regression; the one liveness defect (V2-1) that would have bricked the Fiber egress on the resilient cadence at the re-bake is fixed and regression-tested, and the two minor hardening gaps are closed. All three fixes are off-chain or tooling, so the deployed guest and its vkey are untouched. This does not change the C-1 mainnet gate or the external-audit requirement; it removes a must-fix item from the re-bake punch list.

**Bottom line:** Liquid Cells has a genuinely sound cryptographic and accounting core and a credible escape-hatch design. The path to an external audit is short and concrete: fix the two high-severity proven-path/escape-mode defects (H-1, H-2/M-2), close the unauthenticated deposit ingest (M-1), and harden the off-chain service surface (L-5), then the system is in good shape to engage an auditor. The upgrade-key lockdown (C-1) is the non-negotiable gate to mainnet value. Nothing in the confirmed-findings set indicates a flaw in the core validity-proof trust model; the open issues are escape-mode transaction-shape constraints, one keyspace-separation bug, off-chain hardening, and operational key management.