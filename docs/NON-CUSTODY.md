# Non-custody & censorship-resistance (for integrators, LPs, and reviewers)

The substance most relevant to anyone touching real value, an exchange, a liquidity provider, a
platform replacing a custodial ledger (e.g. scryve), is: **what can the operator do to user funds?**
The answer is *nothing an honest base chain wouldn't allow*. This doc states that plainly and maps it
to the mechanism, so the non-custody and censorship-resistance properties can be evaluated without
re-reading the whole protocol.

## The operator is provably non-custodial

A Liquid Cells operator (the "sequencer") **never has spending authority over user balances.** It
orders intents and posts proofs; it cannot move, seize, or invent a balance. Concretely:

| Claim | Why it holds (mechanism) | Where |
|---|---|---|
| Operator **cannot steal** a balance | "No debit without a signature": a leaf only decreases via a `Transfer`/`Withdrawal` carrying the owner's secp256k1 signature, enforced inside the proven STF and re-checked on-chain | `crates/stf/src/transition.rs`, contract `cells::bind` |
| Operator **cannot mint / inflate** | Value conservation `Σ balances + fee_acc == total`, with `total` changed only by real deposit/withdrawal cells the checkpoint consumes/creates; proven and re-summed on-chain | accounting code 57 / solvency code 58 |
| Operator **cannot trap funds** (go dark) | After `T` epochs of silence, any user **force-exits** unilaterally against the last committed root, proven live and runnable via `lc-exit` (see [DEPLOY.md](../DEPLOY.md)) | `crates/ckb-contract/src/escape.rs`, `crates/client/src/bin/lc-exit.rs` |
| Operator **cannot withhold the data** users need to exit | Each checkpoint's proof commits `keccak(da_blob)`; the root can't advance without publishing the diff on L1 | DA binding code 59 |

So a user's funds are recoverable **without the operator's cooperation**, at all times, from L1 data
alone. That is the technical definition of non-custodial, made enforceable rather than promised.

## Censorship-resistance is the *permissionless sequencing* property

Liveness/censorship is handled by **permissionless, capture-proof sequencing**, not just by the
escape hatch:

- **Anchor lock continuity** (`output anchor lock == input anchor lock`) makes the genesis lock a
  permanent policy for *who may sequence*. With an always-success genesis lock, **anyone** who can
  produce a valid proof may advance the root, demonstrated live (a checkpoint advanced the root
  **unsigned**, [DEPLOY.md](../DEPLOY.md)).
- A checkpoint can never re-lock the anchor to seize sequencing (capture-proofness, red-team-tested).
- So a censoring or stalled operator is not a single point of liveness failure: a competitor can
  sequence, and absent that, the force-exit hatch is the floor. This is the protocol's answer to
  censorship/MEV, and it is a *feature*, not merely a throughput knob.

## The residual trust (stated honestly)

What you *are* trusting, today:
1. **Cryptographic hardness**, secp256k1, keccak-256, BN254/Groth16, SP1.
2. **CKB Layer-1** liveness and consensus (incl. absolute-epoch `since` semantics).
3. **The single upgrade key.** The anchor code cell is upgradable in place by one key; until that is
   locked down (governance multisig + timelock, deliberately sequenced last, see HARDENING/ROADMAP),
   you are trusting the operator not to upgrade the contract maliciously. **This is the one custody-
   relevant residual** and it is disclosed up front, it is the gating item before real value, not a
   hidden caveat.
4. **Unaudited, testnet-only** today.

For an integrator: items 1–2 are the same base any on-chain system trusts; item 3 is the concrete
thing to track (and the timelocked-upgrade work is what removes the "instant malicious upgrade" risk
even before a multisig). Pillars 1–4 above are what make everything else the operator might have been
trusted for *not* a trust assumption.
