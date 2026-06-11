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
        witness[0].input_type = proof ‖ pv
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
pool's funds), so capacity deltas track accounting deltas.

## What the type script enforces (in order)

1. **Anchor continuity** (cheap): exactly one anchor in / out; `pool_id`/`chain_id`
   baked; `new_seq == prev_seq + 1`; input anchor data `== prev_*`, output `== new_*`;
   `new.fee_acc == prev.fee_acc + fee_delta`.
2. **Commitments from real cells** (cheap, keccak): recompute
   `deposits_commitment = fold(non-anchor inputs: to_key, capacity)` and
   `withdrawals_commitment = fold(non-anchor outputs: lock_hash, capacity)` (same
   keccak fold as `liquid_cells_stf::transition::fold_commit`), and require they equal
   the proof's commitments. ⇒ the proof can only credit/debit recipients that
   correspond to real cells, with the amounts those cells carry.
3. **Conservation** (cheap):
   * accounting: `prev_total + Σdeposits − Σwithdrawals == new_total`;
   * solvency: `anchor_out.capacity − anchor_in.capacity == Σdeposits − Σwithdrawals`.
4. **Validity** (expensive, last): the SP1 Groth16 proof of the public values verifies.

## Open items

* **L1 tx fee.** v1 assumes the anchor capacity delta is exactly `Σdep − Σwd` (no fee
  skimmed from the pool). A fee mechanism (operator funds fee from `fee_acc`, or a
  dedicated fee output) is a refinement.
* **DA** (`da_commitment`) is not in the public values yet — Phase 4 adds it to the STF
  and binds `keccak(diff_blob)` here.
* **Withdrawal test coverage.** The deposit path is covered by integration tests; the
  withdrawal path is symmetric in the contract but its test needs lock-hash
  coordination (the proof must commit the exact lock hash the test builds) — added next.
