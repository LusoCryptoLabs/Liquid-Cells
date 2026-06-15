# Data Availability (Phase 4)

The third pillar of the trust model: **the operator cannot advance the pool root while
withholding what changed.** Validity proofs alone don't give you this, a proof says "the
transition was correct," not "you can see the new state." Without DA, a hostile sequencer
could publish valid roots whose leaf data only it knows, and users would be unable to
construct the inclusion proof a force-exit needs. So funds would be *frozen* even though
they provably can't be *stolen*. DA closes that gap.

## What gets published

Every checkpoint commits, in its public values, a **`da_commitment`** computed
**in-circuit** over the post-state of the leaves the batch touched:

```
da_blob = for each touched leaf, sorted ascending by key:
            key(32) ‖ balance(16 BE) ‖ nonce(8 BE)          (56 bytes each)
da_commitment = keccak(da_blob)
```

The checkpoint transaction must carry that **exact** `da_blob` in the anchor input
witness's `output_type` field (witnesses are fee-priced by tx weight, not locked as cell
capacity, the right place for bulk data). The anchor type script recomputes
`keccak(output_type)` and requires it to equal `da_commitment` (reject **code 59**).

Because `da_commitment` is proven from the real post-states and keccak is collision
resistant, the published blob is forced to be the true diff: the operator cannot
substitute, shrink, or omit it and still produce an accepting checkpoint.

## Why post-state, and why it's sufficient

The blob carries the **post-state** (not the delta) of every touched leaf. Replaying every
checkpoint's blob from genesis, in order, overwriting each key with its latest value,
reproduces the **exact** tree, untouched keys stay empty, touched keys end at their last
published value. A leaf that ends empty (`{0,0}`) hashes to `EMPTY_LEAF`, matching the
on-chain SMT. So from the L1 blobs alone, anyone can:

1. rebuild the full tree and check `root == ` the latest on-chain anchor root, then
2. extract any leaf's `(balance, nonce)` and its sibling path, 
3. which is exactly the inclusion proof a single-leaf **force-exit** (Phase 3) submits.

No cooperation from the sequencer is required at any step. This is implemented as
[`liquid_cells_stf::reconstruct`](../crates/stf/src/da.rs) and proven end-to-end in
[`crates/stf/tests/da.rs`](../crates/stf/tests/da.rs) (`da_blobs_reconstruct_tree_and_prove_leaf`):
a three-checkpoint history is rebuilt from blobs alone, its root matches, and a membership
proof for a leaf verifies against that root.

## Cost

The blob is `56 · (touched leaves)` bytes, for the `MAX_LEAVES_PER_BATCH = 1024` ceiling,
~57 KB, paid as tx fee, once per checkpoint. The contract's extra work is a single keccak
over the blob, negligible beside the ~3.6B-cycle BN254 pairing.

## Reconstruction cost (and the snapshot path)

The *per-checkpoint* cost above is fixed and small. The cost that grows is **reconstruction**:
rebuilding the tree by folding every checkpoint blob from genesis is `O(history)`, so it gets
heavier as a pool ages. Two things bound this in practice, and a third is honest roadmap:

* **When it actually bites.** Full genesis replay is the *trustless cold-recovery and force-exit*
  path, not something an everyday tip pays. In normal use balances are served by the operator and a
  wallet need only track its own; the heavy replay matters when a user recovers or exits with no
  cooperation from the operator, which is exactly the case we want to keep cheap.
* **The snapshot path bounds it to `O(snapshot + tail)`.** `Sequencer::snapshot_blob` dumps the full
  current state as one DA blob (sized by *active leaves*, not history), and
  [`reconstruct_from_snapshot(snapshot, snapshot_root, tail)`](../crates/client/src/lib.rs) restores
  from it plus only the checkpoints *after* it. It carries **no new trust**: the snapshot is accepted
  only if `reconstruct([snapshot]).root()` equals the on-chain anchor root at that seq, so a snapshot
  from any source (the operator, a third party, or your own earlier run) that omits or forges a leaf
  is rejected. Covered by `crates/client/tests/snapshot.rs` (equivalence to full replay + rejection
  of a tampered snapshot). Full genesis replay remains the zero-dependency backstop.
* **Honest status.** The snapshot is **advisory** today: integrators should not treat it as the
  source of truth until the checkpoint-compaction work lands (Tier D / B4). Making verifiable
  snapshots routinely available, and shrinking per-checkpoint and proof size (SMT compression), is
  the roadmap line that makes ordinary-user reconstruction cheap as pools scale.

## Scope / open

* The DA commitment + binding + independent reconstruction are done, and the standalone CLI wrapper
  around `reconstruct` (read a node's checkpoint txs → emit a user's leaf + proof) is **shipped** as
  [`lc-exit`](../crates/client/src/bin/lc-exit.rs). It enumerates the pool's checkpoints from a CKB
  node's indexer, folds the published blobs, and checks the rebuilt root equals the live anchor. See
  **[REPRODUCE-EXIT.md](REPRODUCE-EXIT.md)** to run it yourself against the live pool.
* DA is the prerequisite for **Phase 3 force-exit**: the on-chain SMT-inclusion verifier
  that lets a user spend against the last committed root after an operator-silence
  timeout. The reconstruction here produces exactly the proof that verifier consumes.
