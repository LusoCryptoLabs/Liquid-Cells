# Completion tracker (path to mainnet)

> One living status doc for everything between "live on testnet" and "usable with real value." The
> point-in-time security assessment is [AUDIT-READINESS.md](AUDIT-READINESS.md); this is the running
> checklist. Liquid Cells is testnet-only and unaudited today.

**Status legend**
- **DONE**: shipped and on the live testnet deployment.
- **STAGED**: built and tested behind a feature flag, but OFF in the deployed guest (the pinned
  vkey); goes live only at the coordinated v2 re-bake.
- **OPEN**: closeable now without an on-chain redeploy.
- **GATED**: needs an external party (audit) or an on-chain redeploy/proving step.

## 0. The two non-negotiable mainnet gates

| Item | Status | Who can close |
|---|---|---|
| **External security audit** | GATED | third-party firm + budget (out of our hands) |
| **C-1: upgrade-key lockdown** (adopt the built `liquid-cells-upgrade-lock` with `delay_epochs > 180` + a multisig governance lock) | GATED | operator-authorized redeploy of the live code cell's lock on-chain. The lock is **built + tested**; only adoption remains. See [UPGRADE-TIMELOCK.md](UPGRADE-TIMELOCK.md). |

Nothing below makes the system value-ready until these two land.

## 1. Audit findings (current status vs the assessment)

| # | Sev | Finding | Status |
|---|---|---|---|
| C-1 | Critical | Single-key upgrade, no timelock | **GATED** (lock built; adopt on-chain before value) |
| H-1 | High | HTLC escrow keyspace-freeze | **STAGED** (`htlc_keyspace` fix, behind flag, tested) |
| H-2 | High | Escape modes steal unswept deposits | **DONE in code** (deposit-lock checkpoint-mode gate: an escape-mode anchor input cannot release a deposit cell). NOTE: the LIVE Pudge deposit lock predates the fix, so it must be redeployed at the re-bake (V2-REBAKE step 7). |
| M-1 | Medium | Unauth `/submit` deposit mint | **DONE** (deposits off `/submit`; operator-only ingest) |
| M-2 | Medium | Escape-mode no input/output bound | **Residual, documented** (see note). `escape.rs` bounds the anchor in/out + the payout but does NOT bound non-anchor inputs; the only concrete vector (the deposit lock) is closed by the H-2 gate. |
| M-3 | Medium | Zero-fee floor disabled by default | **DONE** off-chain (production binary defaults `--min-fee 1`, enforced at `/submit`); provable backstop is the staged `min_fee` (re-bake) |
| L-1/L-2 | Low | Legacy empty-args pool isolation | accepted residual; type-id pools (live) mitigate |
| L-3 | Low | Sub-61-CKB dust not unilaterally exitable | inherent cell-model limit; cooperative Fiber egress mitigates |
| L-4 | Low | Swap timeout overflow | **DONE** (`saturating_add` reject-on-overflow) |
| L-5 | Low | Service DoS (body/mempool/loop) | **DONE** (body cap + 413 + Content-Length pre-check; mempool bound -> 429); per-connection slow-loris read = production async front, not this demo |
| I-1..I-4 | Info | Sound-core review + hardening notes | accepted / defense-in-depth |

> The assessment's "short path to audit" = H-1 (staged, goes live at the re-bake), H-2 (done in code,
> deposit-lock gate; redeploy the live lock at the re-bake), M-1 + L-5 + M-3 (done), M-2 (documented
> residual below).

> **M-2 residual (escape-mode non-anchor-input bound), and why it is NOT a hard bound.** `escape.rs`
> `force_exit`/`force_refund` validate the anchor's own capacity delta (`in_cap - balance == out_cap`)
> and force the payout to the owner's secp lock, but place no constraint on EXTRA non-anchor inputs.
> The concrete theft vector (siphoning a deposit cell during the silence window) is closed by the
> deposit-lock checkpoint-mode gate (H-2): a deposit lock will not release into an escape-mode tx, and
> a normal secp-locked cell needs its owner's signature, so neither can be siphoned. A strict
> "reject any non-anchor input" bound was considered and deliberately NOT added: an escape tx needs a
> non-anchor input to pay the CKB miner fee (the anchor cannot fund it without breaking solvency), so a
> strict bound would force a 0-fee escape tx that default CKB nodes will not relay, crippling the very
> escape hatch it aims to harden. The residual is therefore: any FUTURE anchor-keyed lock must
> self-gate on checkpoint mode exactly as the deposit lock does. Carried as an explicit external-audit
> item.

## 2. v2 re-bake bundle (STAGED, ships as one coordinated, audited redeploy)

All built and tested behind feature flags, all OFF in the deployed guest (vkey `0x00213af5...`). None
affect the live contract until the re-bake. See [V2-REBAKE.md](V2-REBAKE.md).

This re-bake ships the FIVE security/representation features (committee finding A); `ecrecover` and
`min_fee` are deferred to a later, separately-reviewed re-bake.

| Feature | Purpose | In this re-bake? |
|---|---|---|
| `htlc_keyspace` | H-1 fix (escrow/account keyspace separation) | YES, STAGED |
| `htlc_sha256` | Fiber-compatible hashlock (unlocks live mainnet dust egress) | YES, STAGED |
| `compact_smt` | ~35x fewer proving keccaks; + escape-hatch correctness arm + sparse witness (~8KB -> a few hundred bytes) | YES, STAGED (all 3 halves: guest tree + on-chain `escape::smt_root` + client) |
| `da_varint` | ~36% smaller DA footprint | YES, STAGED |
| `reject_high_s` | close THREAT-MODEL L3 malleability | YES, STAGED |
| `ecrecover` | wire optimization (drop pubkey from witness, -32 B/intent); NOT a security fix | NO, DEFERRED (integration un-pre-staged + un-audited) |
| `min_fee` | in-proof fee floor; M-3 already held operationally by the sequencer `FeePolicy` | NO, DEFERRED (placeholder floor + unresolved zero-fee client legs) |

(H-2 is NOT a bundle feature: it is the deployed deposit-lock checkpoint-mode gate; redeploy the live
deposit-lock cell at the re-bake, V2-REBAKE step 7. The composed five-feature bundle is a green CI gate.)

**To close:** the coordinated re-bake (rebuild guest, regenerate vkey, regenerate proofs, redeploy
code cell, re-verify on-chain) is GATED on proving + on-chain deploy, and best done with the audit.
Two bundle items are staged-but-deliberately-finished-at-the-re-bake (the re-bake re-bakes the vkey
anyway): the `ecrecover` INTEGRATION (the primitive is staged; the pubkey-free `*_msg` rewiring lands
at re-bake) and the `min_fee` ACTIVATION (finalize the floor value + apply it to the remaining
zero-fee client APIs). See [V2-REBAKE.md](V2-REBAKE.md).

**v2-bundle internal audit (2026-06):** a focused adversarial pass over the staged surface confirmed
the core sound and fixed 3 findings (all vkey-neutral, see [AUDIT-READINESS.md](AUDIT-READINESS.md) §6):
V2-1 the sequencer resilient-seal mirror hashed HTLC claims with keccak under `htlc_sha256` (would
drop valid sha256 claims at the re-bake) -> gated to match the STF; V2-2 the verify-vkey guard was
line-oriented; V2-3 a client force-refund-witness ergonomics gap. It also surfaced and closed a real
gap: `compact_smt` had been staged only in the guest, so the on-chain escape hatch would have bricked
at the re-bake -> the `escape::smt_root` compact arm + client forwarding now close it.

## 3. Off-chain hardening (no re-bake)

| Item | Status | Note |
|---|---|---|
| M-1 deposit ingest | DONE | operator-only path + opt-in faucet |
| L-4 swap overflow | DONE | saturating_add |
| L-5 body cap / 413 | DONE | giant-body OOM closed; + a Content-Length pre-check rejects an over-cap declared body before reading it |
| L-5 mempool bound (429) | DONE | `Service::submit` caps pending intents at `MAX_PENDING` (10k); spam past it returns 429. Per-connection slow-loris read is `tiny_http`'s connection layer (a production async front, not this demo); the controllable surface (body + mempool) is now bounded |
| M-3 default fee floor | DONE | the production binary defaults to a non-zero fee-admission floor (`--min-fee`, default 1), enforced at `/submit` admission (underpayer rejected with 402); `genesis()` stays at 0 for tests. Matches the staged provable `min_fee`. Operator raises it to cover real per-leaf cost |

## 4. Roadmap remainder (improvements, not gates)

- **Tier A (no re-bake):** soft-confirmation receipts, adaptive cadence, hybrid fee schedule = **DONE**;
  `.eh_frame` strip = lands at next code-cell redeploy.
- **Tier D (scale, when volume demands):** operationalize sharding, GPU/prover-network (~7min to ~1min),
  per-shard HA/failover, incremental SMT = roadmap.
- **Fiber egress:** built + live-validated on testnet; mainnet via `htlc_sha256` in the re-bake
  (section 2). Receiver-side force-claim = deliberate Phase-6 residual.

## 5. Documentation completeness

| Doc | State |
|---|---|
| SPEC.md | final (consolidated index; deep detail in linked docs) |
| COMPARISON-FIBER.md | final |
| OPERATING.md | final |
| FEES.md | working draft (owned by the protocol docs) |
| V2-REBAKE.md | working draft (owned by the protocol docs) |

## 6. Critical path to mainnet (the short version)

1. **Land the v2 re-bake** (section 2): closes H-1, H-2/M-2 on-chain and unlocks live Fiber dust egress.
2. **External audit** (gate 0) of the re-baked contract + STF + verifier.
3. **C-1 upgrade-key lockdown** (gate 0): adopt the timelock + multisig before any value.
4. ~~Close the OPEN off-chain items (M-3 default floor, L-5 mempool bound)~~ **DONE** (section 3).
5. Operationalize HA; then value-ready.

Everything else (Tier D scale, ~1-min proving) is post-launch optimization and does not gate mainnet.

**Net: with M-3 and L-5 closed, there is no remaining off-chain engineering closeable without the
audit or an on-chain redeploy. The path to value is now exactly the two gates (external audit + C-1
lockdown) plus the one coordinated v2 re-bake, none of which can be done locally.**
