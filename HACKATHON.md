# Liquid Cells — Break-It Hackathon & Bug Bounty

> **Status: testnet-only, unaudited, no real value.** This program invites you to *try to break* a
> CKB rollup that is live on the Nervos **Pudge** testnet. Everything below is disclosed in full and
> up front — the trust assumptions, what is proven vs. unproven, the known issues, and the rules.
> Nothing here is production-ready or safe to use with real assets. Read this entire document and
> [SECURITY.md](SECURITY.md) before participating.

**Enrollment platform: to be announced.** Participation requires enrolling on a platform that will be
announced separately; this document is the rules and scope, not the registration. Dates, the prize
pool, and the exact reward figures will be published with the platform. Until then, treat this as the
canonical statement of *what we are asking you to break and how findings are judged*.

---

## 1. The challenge

Liquid Cells claims a specific, narrow trust model: an operator can sequence a pool of off-chain
balances, but **cannot steal, mint, censor-without-recourse, or withhold data**, because every state
transition is a zk proof verified on-chain and users can exit unilaterally. **Your job is to falsify
that claim** — make the live contract accept something it shouldn't, or make a guaranteed user action
(like a unilateral exit) fail.

We have already run an internal adversarial red-team (55 test cases, no break found — see
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)). This program is the external, adversarial follow-up.

## 2. Trust assumptions (disclosed in full)

What you are asked to assume as sound (out of scope to attack here):
- **Cryptographic soundness** of secp256k1, keccak-256, BN254 pairings, and the SP1/Groth16 proof
  system. The *field arithmetic* of the verifier is upstream and belongs to formal review.
- **Nervos CKB Layer-1** liveness and consensus (including absolute-epoch `since` semantics, which the
  force-exit timeout relies on).

What you should **not** assume — i.e. the protocol's *current* trust caveats, which are real:
- **A single upgrade key controls the contract.** The anchor code cell is deployed via type-id and is
  **upgradable in place** by one `secp256k1_blake160` key. Until that key is locked down (governance
  multisig + timelock, deliberately sequenced *last*, after audit), you are trusting the operator not
  to upgrade the contract maliciously. This is the single largest trust assumption and it is **not**
  what this hackathon is about — it is a known, disclosed property, not a bug.
- **Unaudited.** No external audit has been performed.
- **Known issues** (Section 7) are documented and **not** eligible for rewards.

What is *proven on-chain* (and therefore the interesting thing to try to break):
- Validity: each checkpoint's Groth16 proof is verified in CKB-VM against the baked vkey.
- Data availability: the proof commits `keccak(da_blob)`; the root cannot advance while withholding
  the diff.
- Unilateral exit: force-exit / force-refund against the last committed root, no operator cooperation.
- Deposit safety: a sweep-or-refund lock closes the always-success theft window.

## 3. What we want broken (targets)

A valid finding makes the **live contract** (or the proven STF) violate one of these invariants:

1. **Value conservation** — mint or burn value across a checkpoint; break `prev_total + Σdep − Σwd −
   fee_withdrawal == new_total` or the capacity solvency relation.
2. **No debit without authorization** — move value out of a leaf without a valid owner signature;
   replay a transfer/withdrawal; defeat nonce/expiry/domain (pool_id, chain_id) binding.
3. **Honest exit** — exit more than your balance, exit a leaf you don't own, forge SMT membership,
   exit against a stale root, or replay an exit; defeat a force-refund's receiver/timeout binding.
4. **Fee safety** — draw an L1 fee from a user balance instead of accrued fee revenue.
5. **Data availability** — advance the root while withholding or altering the published DA blob.
6. **Capture-proofness** — a checkpoint (or exit) that re-locks a permissionless anchor to seize
   sequencing (defeat lock continuity).
7. **Pool isolation** — sweep a deposit bound to a **type-id'd** pool into a different pool (note the
   legacy empty-args caveat in Section 7 is *known* and excluded).
8. **Proof binding** — get the contract to accept a proof for a different program/public-inputs, or a
   public value left unpinned to a real on-chain fact.

The strongest submissions come as a **failing/passing test** against `crates/ckb-contract-tests/` or
`crates/stf/` (mirror the existing `redteam_*.rs` files), or a **live testnet transaction** that the
contract accepts but shouldn't.

## 4. Severity & rewards (tiers — amounts TBA)

Rewards are tiered by impact; **figures will be published with the enrollment platform.** Indicative
rubric:

| Severity | Definition | Reward (placeholder) |
|---|---|---|
| **Critical** | Steal/mint funds, or block a user's guaranteed unilateral exit, on the live contract | `TBD — top tier` |
| **High** | Break value conservation / proof binding / capture-proofness without direct theft | `TBD` |
| **Medium** | Break an invariant only under non-default config, or DA/fee edge with limited impact | `TBD` |
| **Low / informational** | Spec/code mismatch, hardening gap, no fund-safety impact | `TBD — recognition / small` |

Duplicate, out-of-scope, or already-known (Section 7) reports are ineligible. The first valid report
of a given root cause wins it. Final severity and reward are at the program's discretion, explained to
the reporter.

## 5. Rules & eligibility

- **Testnet only.** All testing on Pudge. Never target another participant's cells, real assets, or
  shared infrastructure (RPC/explorers). DoS of public infra is out of scope and prohibited.
- **Enroll** on the TBA platform and agree to its terms; rewards require enrollment.
- **Report privately** per [SECURITY.md](SECURITY.md). Do not disclose publicly before coordinated
  disclosure. Public disclosure of an unfixed in-scope bug forfeits the reward.
- **Original work**, good-faith research only. No leaking of others' submissions.
- Standard exclusions: employees/contributors directly involved in the protocol are ineligible for
  rewards (but encouraged to test).

## 6. Scope

**In scope:** `crates/ckb-contract` (anchor type script + deposit lock), `crates/stf` (proven STF),
and the on-chain proof-binding plumbing, as deployed on Pudge (see [DEPLOY.md](DEPLOY.md) for live
addresses and code-cell outpoints).

**Out of scope:** BN254/Groth16/SP1 cryptographic soundness; CKB L1 itself; DoS of public
infrastructure; key compromise / social engineering; the off-chain demo UI / SDK ergonomics; and the
**known issues** below.

## 7. Known issues (not eligible)

Disclosed up front so nobody wastes effort or claims them:
1. **ECDSA high-S signature malleability** (`crates/stf/src/sig.rs`) — txid-only malleability, no
   debit/replay/mint. Fix re-bakes the guest vkey, deferred to a coordinated upgrade. (THREAT-MODEL L3.)
2. **Legacy empty-args pools are not isolated** — two empty-args pools share one anchor type hash, so a
   deposit can be swept into a different *legacy* pool (depositor still credited, force-exit
   recoverable). **Type-id'd pools fix this** and are the recommended configuration.
3. **The deposit lock's sweep predicate is intentionally loose** — it unlocks on any input bearing the
   pool type hash and relies on the anchor type script's solvency/commitment checks to enforce
   destination safety (confirmed to backstop it). Documented coupling, not a bug.
4. **Single upgrade key** (Section 2) — a disclosed trust property, not a vulnerability.

Finding a *new* way around any mitigation in 2–3 (e.g. an actual third-party theft, or a real
cross-pool sweep of a **type-id'd** pool) **is** in scope and rewardable.

## 8. How to participate

1. Read this document, [SECURITY.md](SECURITY.md), and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
2. Clone the repo; build and run the existing + red-team test suites (`crates/ckb-contract-tests`,
   `crates/stf`) to learn the harness.
3. Try to break an invariant in Section 3. Reproduce it as a test or a live Pudge transaction.
4. **Enroll on the (TBA) platform** and submit privately per [SECURITY.md](SECURITY.md).

Honest, in good faith, fully disclosed. Come break it.
