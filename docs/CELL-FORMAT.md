# On-Chain Cell Format (v1 — implicit)

How deposits and withdrawals are represented in a checkpoint transaction, and how the
anchor type script binds them to the proof. v1 uses the **implicit** format: deposit
and withdrawal cells are identified by *position* (anything that isn't the anchor),
not by a marker script.

## Checkpoint transaction shape

```
inputs:                                   outputs:
  [0] anchor cell (state n)                 [0] anchor cell (state n+1)
        type = THIS script                        type = THIS script
        data = root‖seq‖total‖fee_acc             data = root‖seq‖total‖fee_acc
        witness[0].input_type  = proof ‖ pv
        witness[0].output_type = da_blob
  [1..] deposit cells                       [1..] withdrawal cells
        data = to_key (32)                        lock = the recipient's lock
        capacity = deposit amount                 capacity = withdrawal amount
        (any lock; no type)
cell_deps: [ this contract, ... ]
```

* **Anchor** = the (single) input and (single) output carrying this type script.
* **Deposit** = any *other* input. Credits `data[0..32]` (= `to_key`) by its capacity.
  The depositor creates this cell, choosing `to_key` and funding it with real CKB, so
  the recipient mapping is not operator-controlled.
* **Withdrawal** = any *other* output. Pays its `lock_hash` its capacity.

Trade-off (accepted for v1): a checkpoint tx may contain **only** the anchor + deposit
/ withdrawal cells — no unrelated inputs/outputs — because position is the classifier.
A later version can switch to an explicit marker type if composability is needed.

## Anchor cell data (72 bytes)

```
root(32) ‖ seq(8 BE) ‖ total(16 BE) ‖ fee_acc(16 BE)
```

Invariant the script maintains: **anchor capacity == pool total** (the anchor holds the
pool's funds), so capacity deltas track accounting deltas. `total = Σ balances + fee_acc`:
`fee_acc` is the sequencer's accumulated in-pool fee revenue, held inside the anchor until
drawn (see *L1 fee* below).

## What the type script enforces (in order)

1. **Anchor continuity** (cheap): exactly one anchor in / out; `pool_id`/`chain_id`
   baked; `new_seq == prev_seq + 1`; input anchor data `== prev_*`, output `== new_*`;
   `new.fee_acc == prev.fee_acc + fee_delta − fee_withdrawal`, with
   `fee_withdrawal ≤ prev.fee_acc + fee_delta`.
2. **Commitments from real cells** (cheap, keccak): recompute
   `deposits_commitment = fold(non-anchor inputs: to_key, capacity)` and
   `withdrawals_commitment = fold(non-anchor outputs: lock_hash, capacity)` (same
   keccak fold as `liquid_cells_stf::transition::fold_commit`), and require they equal
   the proof's commitments. ⇒ the proof can only credit/debit recipients that
   correspond to real cells, with the amounts those cells carry.
3. **Data availability** (cheap, keccak): `keccak(witness[0].output_type) ==
   da_commitment`. Forces the checkpoint to publish the touched leaves' post-state so any
   user can reconstruct their leaf and force-exit ([docs/DA.md](DA.md)).
4. **Conservation** (cheap):
   * accounting: `prev_total + Σdeposits − Σwithdrawals − fee_withdrawal == new_total`;
   * solvency: `anchor_out.capacity − anchor_in.capacity == Σdeposits − Σwithdrawals −
     fee_withdrawal`.
5. **Validity** (expensive, last): the SP1 Groth16 proof of the public values verifies.

## L1 fee

A CKB checkpoint transaction must leave a positive miner fee (`Σinputs − Σoutputs > 0`).
The pool funds it with a proven **`fee_withdrawal`** — CKB the sequencer draws from its
own accumulated fee revenue:

* The in-circuit STF caps `fee_withdrawal ≤ prev.fee_acc + fee_delta` (this batch's fee
  revenue plus what was banked before). Because `total = Σ balances + fee_acc` and the
  draw reduces `total` and `fee_acc` by the same amount, **`Σ balances` is invariant** —
  an L1 fee can never be skimmed from a user deposit. That bound is *proven*, and the
  anchor re-checks it (step 1) before trusting the cell.
* Since the only inputs are the anchor + deposit cells and the only outputs are the
  anchor + withdrawal cells, the solvency identity (step 3) forces
  `Σinputs − Σoutputs == fee_withdrawal`: the checkpoint's miner fee is **exactly** the
  proven draw, no more. The sequencer cannot over-skim and pocket the difference (any
  surplus would have to be a withdrawal output, which is counted).

So the fee is the sequencer's own revenue, bounded and pinned on-chain; a checkpoint with
no fee revenue available simply sets `fee_withdrawal = 0` and must be fee-bumped some
other way (e.g. a future explicit sequencer-funded input).

## Open items

* **DA** is now bound: the proof commits `da_commitment` and the script enforces it equals
  `keccak(witness output_type)` (step 3 above; [docs/DA.md](DA.md)). Remaining: a polished
  standalone reconstruction CLI, and Phase 3 force-exit which consumes the reconstructed
  proof.

Both the deposit and withdrawal paths are covered by integration tests. The withdrawal
test uses a fixed, deterministic target lock (`crates/ckb-contract-tests` `withdraw_lock`)
shared by the `wd_target` helper (which the proof commits) and the test (which builds the
output) — `Context::build_script` can't be used for this because its hash varies per
`Context`.
