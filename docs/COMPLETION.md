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
| H-2 | High | Escape modes steal unswept deposits | **STAGED** (canonical-shape escape fix + force-refund co-fix) |
| M-1 | Medium | Unauth `/submit` deposit mint | **DONE** (deposits off `/submit`; operator-only ingest) |
| M-2 | Medium | Escape-mode no input/output bound | **STAGED** (same canonical-shape fix as H-2) |
| M-3 | Medium | Zero-fee floor disabled by default | **OPEN** (needs a calibrated default `FeePolicy`; economic call) |
| L-1/L-2 | Low | Legacy empty-args pool isolation | accepted residual; type-id pools (live) mitigate |
| L-3 | Low | Sub-61-CKB dust not unilaterally exitable | inherent cell-model limit; cooperative Fiber egress mitigates |
| L-4 | Low | Swap timeout overflow | **DONE** (`saturating_add` reject-on-overflow) |
| L-5 | Low | Service DoS (body/mempool/loop) | **partly DONE** (body cap + 413); mempool bound + read timeout **OPEN** (demo-grade) |
| I-1..I-4 | Info | Sound-core review + hardening notes | accepted / defense-in-depth |

> The assessment's "short path to audit" = land H-1 and H-2/M-2 (staged), M-1 (done), L-5 service
> hardening (partly done). Those fixes exist; H-1/H-2/M-2 go live with the re-bake (section 2).

## 2. v2 re-bake bundle (STAGED, ships as one coordinated, audited redeploy)

All built and tested behind feature flags, all OFF in the deployed guest (vkey `0x00213af5...`). None
affect the live contract until the re-bake. See [V2-REBAKE.md](V2-REBAKE.md).

| Feature | Purpose | Status |
|---|---|---|
| `htlc_keyspace` | H-1 fix (escrow/account keyspace separation) | STAGED |
| canonical escape shape | H-2/M-2 fix (no input/output siphon) | STAGED |
| `htlc_sha256` | Fiber-compatible hashlock (unlocks live mainnet dust egress) | STAGED |
| `compact_smt` | ~35x fewer proving keccaks | STAGED |
| `ecrecover` | cycle save + drop pubkey from witness | STAGED |
| `min_fee` | in-proof fee floor (provable M-3 backstop) | STAGED |
| `da_varint` | ~36% smaller DA footprint | STAGED |
| `reject_high_s` | close THREAT-MODEL L3 malleability | STAGED |

**To close:** the coordinated re-bake (rebuild guest, regenerate vkey, regenerate proofs, redeploy
code cell, re-verify on-chain) is GATED on proving + on-chain deploy, and best done with the audit.

## 3. Off-chain hardening (no re-bake)

| Item | Status | Note |
|---|---|---|
| M-1 deposit ingest | DONE | operator-only path + opt-in faucet |
| L-4 swap overflow | DONE | saturating_add |
| L-5 body cap / 413 | DONE | giant-body OOM closed |
| L-5 mempool bound (429) + read timeout | OPEN | small, safe; the service is demo-grade and single-threaded by design |
| M-3 default fee floor | OPEN | set a calibrated `FeePolicy` in the production driver (not in `genesis()`, which tests rely on); document the floor |

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
4. **Close the OPEN off-chain items** (M-3 default floor, L-5 mempool bound) before networked exposure.
5. Operationalize HA + a default fee floor; then value-ready.

Everything else (Tier D scale, ~1-min proving) is post-launch optimization and does not gate mainnet.
