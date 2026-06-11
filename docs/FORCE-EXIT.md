# Force-Exit / Escape Hatch (Phase 3)

The fourth and final trust primitive: **the operator cannot freeze funds by going dark.**
Validity proofs stop theft, DA stops withholding — but if the sequencer simply *stops*,
users still need a way out without it. Force-exit is that way: a unilateral, on-chain
withdrawal of your leaf against the *last committed root*, requiring no proof and no
cooperation from anyone.

## How it works

Force-exit is a second mode of the anchor type script (selected by the witness
`input_type` length: 644 = checkpoint, 8249 = force-exit). The exiter submits a tx whose
input-group witness carries:

```
pubkey(33) ‖ balance(16 BE) ‖ nonce(8 BE) ‖ siblings(256 · 32)
```

and the script enforces, with **no Groth16 proof** (just keccak over the SMT path):

1. **Inclusion** — `smt_root(keccak(pubkey), leaf_hash(balance, nonce), siblings)` equals
   the input anchor's `root`. So the claimed `{balance, nonce}` really is in the committed
   state. (`balance` and the path come from the published DA blobs — see [DA.md](DA.md).)
2. **Nullification** — recompute the root with the leaf emptied (balance→0, nonce kept for
   replay safety) using the *same* siblings; it must equal the output anchor's `root`. The
   leaf is now spent, so it can't be exited twice.
3. **Payout to the owner, only** — there must be an output paying exactly `balance` to the
   owner's canonical `secp256k1_blake160_sighash_all` lock with `args = blake160(pubkey)`.
   Since the SMT key is `keccak(pubkey)`, the funds can land **only** at the address the
   leaf owner controls. No in-contract signature is needed, and an attacker who triggers
   someone's exit merely sends them their own money.
4. **Accounting** — `total` and the anchor capacity each drop by exactly `balance`
   (`fee_acc`/`seq`/`last_epoch` unchanged).
5. **Timeout** — the input's `since` (absolute epoch) must be ≥ `last_epoch + TIMEOUT`
   (180 epochs, ~30 days). CKB consensus refuses to mine the tx any earlier.

## The timeout clock

The hatch must only open when the operator is *actually* silent, so the anchor records a
`last_epoch` (its data grew 72→80 bytes). Each **checkpoint** sets `last_epoch =
current_epoch` and proves it isn't future-dated by requiring the checkpoint tx's input
`since` ≥ `current_epoch` (consensus won't mine it before that epoch, so `last_epoch ≤`
real chain time). While the operator keeps checkpointing, `last_epoch` advances and the
window never opens. The moment it stops, the clock is frozen and after `TIMEOUT` epochs any
holder can exit. The operator can't push the deadline out by lying about the epoch (the
`since` floor caps it) and can't pull it in to grief (that only helps users).

## Reconciliation when the operator returns

A force-exit changes `root` without a proof. If the operator comes back and tries to
checkpoint against the *old* root, the contract rejects it (`prev_root` is pinned to the
input anchor, which now holds the post-exit root). So the operator is forced to build on the
exited state — forced inclusion, enforced for free by the existing checkpoint binding.

## Scope

* **≥ 61 CKB only.** The payout is a single L1 cell, which needs ~61 CKB of capacity. This
  is the documented *whale escape hatch*; sub-61-CKB balances get a trustless exit via the
  Phase 5 atomic-swap / Fiber egress (no 61-CKB cell). The contract doesn't enforce the
  floor — CKB consensus does.
* **`TIMEOUT = 180` epochs** is a baked constant, tunable per deployment.
* Tested in [`crates/ckb-contract-tests/tests/forceexit.rs`](../crates/ckb-contract-tests/tests/forceexit.rs):
  the scenario is built natively with `liquid-cells-stf` (real tree + inclusion proof, no
  SP1), with the positive case plus six negatives — before-timeout, wrong balance, wrong /
  missing payout lock, un-nullified root (double-exit), and bad total.
