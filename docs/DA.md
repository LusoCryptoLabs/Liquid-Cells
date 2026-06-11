# Data Availability (Phase 4)

The third pillar of the trust model: **the operator cannot advance the pool root while
withholding what changed.** Validity proofs alone don't give you this — a proof says "the
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
capacity — the right place for bulk data). The anchor type script recomputes
`keccak(output_type)` and requires it to equal `da_commitment` (reject **code 59**).

Because `da_commitment` is proven from the real post-states and keccak is collision
resistant, the published blob is forced to be the true diff: the operator cannot
substitute, shrink, or omit it and still produce an accepting checkpoint.

## Why post-state, and why it's sufficient

The blob carries the **post-state** (not the delta) of every touched leaf. Replaying every
checkpoint's blob from genesis, in order, overwriting each key with its latest value,
reproduces the **exact** tree — untouched keys stay empty, touched keys end at their last
published value. A leaf that ends empty (`{0,0}`) hashes to `EMPTY_LEAF`, matching the
on-chain SMT. So from the L1 blobs alone, anyone can:

1. rebuild the full tree and check `root == ` the latest on-chain anchor root, then
2. extract any leaf's `(balance, nonce)` and its sibling path —
3. which is exactly the inclusion proof a single-leaf **force-exit** (Phase 3) submits.

No cooperation from the sequencer is required at any step. This is implemented as
[`liquid_cells_stf::reconstruct`](../crates/stf/src/da.rs) and proven end-to-end in
[`crates/stf/tests/da.rs`](../crates/stf/tests/da.rs) (`da_blobs_reconstruct_tree_and_prove_leaf`):
a three-checkpoint history is rebuilt from blobs alone, its root matches, and a membership
proof for a leaf verifies against that root.

## Cost

The blob is `56 · (touched leaves)` bytes — for the `MAX_LEAVES_PER_BATCH = 1024` ceiling,
~57 KB, paid as tx fee, once per checkpoint. The contract's extra work is a single keccak
over the blob — negligible beside the ~3.6B-cycle BN254 pairing.

## Scope / open

* The DA commitment + binding + independent reconstruction are done. A polished
  standalone CLI wrapper around `reconstruct` (read a node's checkpoint txs → emit a
  user's leaf + proof) is a thin follow-up over the library primitive.
* DA is the prerequisite for **Phase 3 force-exit**: the on-chain SMT-inclusion verifier
  that lets a user spend against the last committed root after an operator-silence
  timeout. The reconstruction here produces exactly the proof that verifier consumes.
