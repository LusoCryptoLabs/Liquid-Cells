# Fees: the per-intent floor, in two honest layers

A checkpoint's on-chain cost grows with the number of leaves it touches: each touched leaf is DA
bytes published on L1 plus SP1 cycles proven (~0.62M cycles/leaf, see
`MAX_LEAVES_PER_BATCH`). The proven STF charges whatever `fee` an intent carries and has **no
minimum**, so a flood of correctly-signed, fully-funded, **zero-fee** transfers is perfectly valid:
each one costs the operator a leaf's worth of work while contributing nothing to the `fee_acc` that
funds the checkpoint's miner fee. That is a griefing / sustainability gap, not a safety gap (no user
funds are ever at risk, `fee_withdrawal` is still capped at fee revenue, so an L1 fee can never be
skimmed from a balance). This note explains how the floor that closes it is delivered in two layers,
and is deliberately honest about which is a *guarantee* and which is *policy*.

## Layer 1: sequencer admission policy (live now, `main`)

`liquid_cells_sequencer::FeePolicy { min_fee_per_intent }` is the operator's self-protection: a
configurable per-intent floor the sequencer refuses to seal below.

- **Strict path**, `Sequencer::seal_batch` calls `FeePolicy::check`: if *any* fee-paying intent
  (transfer or HTLC-lock; deposits/withdrawals/claims/refunds carry no `fee`) underpays, the whole
  batch is rejected (`InsufficientFees`) and the mempool is left intact to drop/retry.
- **Resilient path**, `Sequencer::seal_resilient` passes the policy into `validate_batch`, which
  **drops just the underpayers** (transitively deferring anything that depended on them, exactly like
  any other dropped intent) and seals the rest. The authoritative atomic `seal_batch` then re-applies
  the survivors, so dropping is always safe.
- **Off by default.** `FeePolicy::disabled()` (floor 0) is a no-op; a sequencer left at the default
  behaves exactly as before. Set one with `Sequencer::with_fee_policy` / `set_fee_policy`.

This is **policy, not proof**: it is what an *honest* operator enforces to stay solvent. It does not,
by itself, stop a *dishonest* operator from sealing zero-fee intents (they would only be harming
themselves). It needs no deploy and changes no on-chain surface, so it ships to `main` today.

## Layer 2: the in-proof floor (staged, `min_fee` feature, OFF in the deployed guest)

The matching **provable** floor lives in the STF itself: `liquid_cells_stf::MIN_FEE_PER_LEAF`, enforced
inside `apply_ops` for every transfer and HTLC-lock. With it on, "every fee-paying intent contributed
≥ the floor" becomes an **unforgeable invariant the on-chain verifier checks**, true even against a
dishonest operator, because the proof simply won't verify otherwise.

It is gated behind the `min_fee` Cargo feature and **OFF by default**, for the same reason as
`journal`: compiling it in changes the guest ELF and therefore **re-bakes the verifying key** (away
from the deployed `0x00213af5…`). Turning it on is a *coordinated upgrade*, not a silent change:

- The code and its adversarial tests are in-tree now (`cargo test -p liquid-cells-stf --features
  min_fee --test min_fee`), so the design is real and reviewed, not vapour.
- `scripts/verify-vkey.sh` **asserts the guest builds with `min_fee` OFF**, so it can never leak into
  the deployed vkey by accident.
- At a future upgrade (bundled with the other vkey-affecting hardening, SMT compression, ecrecover,
  DA varint, high-S; see HARDENING / ROADMAP Tier C), the feature flips on, the new guest is proven,
  and the new vkey is deployed behind the [timelocked upgrade lock](UPGRADE-TIMELOCK.md). Set
  `FeePolicy::min_fee_per_intent == MIN_FEE_PER_LEAF` so the two layers agree.

## Why two layers instead of one

The provable floor is the real guarantee, but it is **deploy-gated** (vkey re-bake). Shipping *only*
it would mean the griefing gap stays open until the next mainnet upgrade. Shipping the sequencer
policy now closes it **operationally today**, while the staged in-proof version makes it
**unforgeable later**, and pinning them to the same constant means the upgrade is a tightening of an
already-live rule, not a behaviour change users have to reason about fresh.

## Calibration (audit-time)

`MIN_FEE_PER_LEAF` is a placeholder unit (`1`). The production figure is an audit-time choice
calibrated to the marginal per-leaf checkpoint cost (DA byte cost + amortised proving/L1 fee per
leaf), and whether the floor should be per-intent (as implemented) or aggregate per touched-leaf.
That economic calibration is deliberately left to the audited Tier C work rather than guessed here.
