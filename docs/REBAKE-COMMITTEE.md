# Re-bake + lockdown readiness committee (verdict + punch list)

An internal multi-seat readiness review (2026-06-17) of executing, on the live CKB deployment, the two
hard-to-reverse actions, **WITHOUT** waiting for the external audit:

- **#3 the v2 re-bake** (rebuild the SP1 guest with the staged bundle ON, recompute + re-pin the vkey,
  regenerate proofs, redeploy the anchor, re-verify on-chain), and
- **#2 the C-1 upgrade-key lockdown** (migrate the live code-cell lock to the timelocked
  `liquid-cells-upgrade-lock` + a multisig governance lock).

Seven independent seats assessed in parallel; a chair consolidated. **Tally: 6 go-with-conditions,
1 no-go (the dedicated dissent seat).** This doc is the durable record + the live status of the punch
list. The point-in-time security assessment is [AUDIT-READINESS.md](AUDIT-READINESS.md); the running
checklist is [COMPLETION.md](COMPLETION.md); the runbook is [V2-REBAKE.md](V2-REBAKE.md).

## 1. Verdict

- **Testnet dry-run (no value): GO WITH CONDITIONS.** The re-bake on Pudge is the correct rehearsal to
  flush out the real failure modes (vkey re-pin drift, a missed coordinated feature half, the cycle
  budget) before any value is at stake; worst case is wasted time.
- **Mainnet value: NO-GO without the external audit.** Unanimous in substance across all seven seats.
  An internal committee raises confidence and catches issues (this review caught a load-bearing
  doc-vs-code gap, below), but it cannot self-certify the novel money-holding crypto: the SP1 Groth16
  trusted-setup provenance, the BN254 pairing-verifier soundness, and the new compact-SMT / escape-hatch
  reconstruction. A forged-but-valid proof verifies; no in-repo test can catch a compromised setup.

## 2. Required execution order (binding)

**AUDIT (for value) -> RE-BAKE (#3) -> LOCKDOWN (#2).** The re-bake MUST precede the lockdown: a
`>180`-epoch timelock makes any later upgrade ~30 days delayed, so locking first would force the
re-bake itself (and any fix found during it) through that delay. Lockdown is the deliberately
irreversible LAST step, applied only after the re-baked code is live and validated. For mainnet value,
the external audit gates the whole sequence.

## 3. Must-fix-before-execute punch list (with status after the 2026-06-17 remediation batch)

| Item | Severity | Issue | Status now |
|---|---|---|---|
| A. Reduce the bundle | Blocker | `ecrecover` integration + `min_fee` activation are un-pre-staged code authored AT the bake, never on green main, never audited. | **DONE.** Dropped both from this re-bake (V2-REBAKE "Bundle scope"); ship only the 5 security features. Deferred to a later reviewed re-bake. |
| B. H-2/M-2 doc-vs-code gap | Blocker | Docs claimed a "STAGED canonical-shape escape fix" that is absent from `escape.rs`. | **DONE (reconciled).** H-2 is fixed by the deposit-lock checkpoint-mode gate (deployed in code); the canonical-shape bound is a documented residual, deliberately not added (it would force a 0-fee, un-relayable escape tx). See COMPLETION M-2 note + AUDIT-READINESS reconciliation. |
| C. verify-vkey misses pin sites | Blocker (liveness) | The guard checked 3 of 9 vkey pin sites; a missed re-pin bricks the prover/sequencer. | **DONE.** `verify-vkey.sh` now asserts all 9 (contract VKEY_HASH + 4 host bins + 4 fixture files); CI step renamed; green. |
| D. Governance multisig undefined | Blocker (mainnet) | `upgrade_lock.rs` consumes a `governance_lock_hash`; no signer set / threshold / custody / ceremony. | **OPEN (operator).** Stand up a concrete m-of-n multisig with custody + a rehearsed announce->wait->execute; in external-audit scope. Not codeable here. |
| E. No composed-bundle CI artifact | Major | Composition evidence was a documented run, not a committed reproduced gate. | **DONE.** CI now runs the whole reduced bundle composed (fuzz + red-team under all 5) + the anchor under `htlc_keyspace compact_smt`; verified green locally. |
| F. Toolchain pin inconsistent | Major | 1.94.0 vs 1.96.0, sp1 6.2.3 vs 6.2.4 across docs. | **DONE.** Reconciled to: succinct rustc 1.94.0 (the `sp1:v6.2.4` cargo-prove image) + `sp1-zkvm`/`sp1-sdk` 6.2.3 crate (the two are distinct; both stated). |
| G. No rollback / cycle re-measure | Major | No abort path for a wrong-verifying in-place upgrade; cycle margin assumed. | **DONE.** V2-REBAKE adds a rollback/abort section (archive prior code cell, pre-flight on a throwaway pool against the REAL ~3.50B consensus limit via ckb-debugger, recovery = second in-place upgrade). |
| H. Constant drift + deposit-lock redeploy | Major | `644` discriminator duplicated (anchor vs deposit lock); the live deposit lock predates the H-2 fix. | **DONE.** Shared `protocol.rs` const + a compile-time `assert!(WITNESS_LEN == CHECKPOINT_WITNESS_LEN)`; runbook step 7 now redeploys the deposit-lock cell. |
| delay > force-exit window | Condition | The upgrade lock accepted any delay; its tests used DELAY=100 (< 180), so the safety property was unexercised. | **DONE.** `upgrade_lock.rs` rejects `delay <= FORCE_EXIT_TIMEOUT_EPOCHS` (code 89); tests raised to 200 + boundary/negative cases added (8 green). |

## 4. Conditions to attach to the (testnet) conditional go

- Restrict execution to TESTNET until the external audit clears the re-baked artifact and the C-1
  multisig is stood up. The testnet run is the rehearsal, not a security sign-off.
- Validate all four anchor modes (genesis / checkpoint / force-exit / force-refund under the
  deployed-format features) on a throwaway pool first, and re-measure verifier cycles on a live Pudge
  checkpoint against the real consensus limit.
- Set `delay_epochs` comfortably above 180 (the lock enforces `> 180`; pick e.g. 200 for margin).
- Do NOT leave the testnet cell permanently locked (it only slows your own iteration).

## 5. External-audit residual (blunt)

Skipping the external audit means the operator personally accepts four classes of risk this committee
**cannot** discharge: (1) SP1 Groth16 trusted-setup provenance (a compromised ceremony forges proofs
that verify, invisible to every in-repo test); (2) BN254 field-arithmetic soundness of the deployed
ark-bn254 verifier (the differential test proves two ports AGREE, not that either rejects an
adaptively crafted proof); (3) the novel re-bake constructions (compact-SMT pass-through hashing, the
proof-less sparse escape-hatch reconstruction that is itself the only recovery path); (4) the
governance-multisig design the lock makes permanent. The committee's legitimate value is process
hygiene and confidence (it surfaced the doc-vs-code escape-fix gap that nearly passed): a complement
to, not a replacement for, independent review of novel money-holding crypto. **Testnet dry-run:
go-with-conditions. Mainnet value: no-go until the external audit clears the exact re-baked artifact,
and a real multisig timelock is applied last.**
