# Security Policy

> **Liquid Cells is testnet-only, unaudited software with no real value at stake.** It is deployed
> on the Nervos **Pudge** testnet. Do not use it with mainnet assets. See
> [DEPLOY.md](DEPLOY.md), [HARDENING.md](HARDENING.md), and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Reporting a vulnerability

**Please report privately, do not open a public issue or PR for a suspected vulnerability.**

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability" under the
  repository's *Security* tab) so the report is not public.
- Include: the affected component, a description, and ideally a proof-of-concept (a failing/passing
  test against the `ckb-testtool` or STF harness is ideal, see `crates/ckb-contract-tests/tests/`
  and `crates/stf/tests/`).

We aim to acknowledge a report within **3 business days** and to agree a disclosure timeline with
the reporter. Default coordinated-disclosure window: **90 days** or until a fix ships, whichever is
sooner. Credit is given unless you prefer to remain anonymous.

## Scope

**In scope** (testnet deployment and this source):
- The anchor type script (`crates/ckb-contract`), checkpoint verification, public-value pinning,
  value conservation / fee / solvency, the force-exit / force-refund escape hatches, anchor lock
  continuity, type-id pool identity, and DA-blob binding.
- The deposit lock (`crates/ckb-contract/src/deposit_lock.rs`), sweep-or-refund safety.
- The state-transition function (`crates/stf`), the proven semantics, signature checks, SMT witness
  handling, value conservation.
- The Groth16 verifier integration as it binds the proof to chain facts (the on-chain plumbing).

**Out of scope:**
- BN254 field-arithmetic *soundness* of the Groth16 verifier and the SP1 proof system itself, these
  are upstream/cryptographic and belong to formal review, not this program.
- Denial-of-service against public testnet infrastructure (RPC nodes, explorers).
- Anything requiring compromise of a user's keys, social engineering, or off-protocol systems.
- Known issues already documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and
  [HARDENING.md](HARDENING.md) (e.g. ECDSA high-S txid malleability, legacy empty-args pool
  non-isolation), these are out of scope.

## Safe harbor

Testing must use **testnet only**, must not target other people's cells or funds, and must not
degrade shared infrastructure. Good-faith research conducted within this scope and the safe-harbor
terms above will not be pursued.
