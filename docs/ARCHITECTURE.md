# Liquid Cells, Architecture

This document describes the fully trustless design. It is the contract that the
sequencer, the SP1 guest, the on-chain anchor type script, and client SDKs must all
agree on. Where it says **MUST**, a divergence is a consensus bug.

---

## 1. Trust model in one paragraph

Liquid Cells is a **zk-rollup**: off-chain state, on-chain validity proofs, on-chain
data availability. The operator is a *sequencer* with no privileged power. It cannot
debit a user without that user's signature (enforced in-circuit), cannot inflate the
money supply (conservation enforced in-circuit), cannot settle a stale or invalid
root (the type script rejects any checkpoint without a valid proof), cannot withhold
the data users need to exit (each checkpoint posts the state diff on-chain), and
cannot freeze funds by going offline (a permissionless escape hatch lets anyone exit
against the last committed root). Residual trust = secp256k1 + keccak + Groth16
soundness + CKB L1. Nothing else.

---

## 2. State model

### Account leaf

```
Leaf { balance: u128 (shannons), nonce: u64 }
```

* The owner identity is **not** stored in the leaf. The SMT **key** is the identity:
  `key = keccak256(compressed_secp256k1_pubkey)`. Ownership is proven only when
  *spending* (the spender supplies the pubkey; the STF checks `keccak(pubkey) == key`
  and verifies the signature). This means **receiving needs no registration**, a
  transfer can credit a key that has never been seen.
* Keying by `keccak(pubkey)` randomizes placement, so an attacker cannot grind a
  chosen `participant_id` to occupy a victim's sibling path.
* `{balance: 0, nonce: 0}` is the canonical **empty** leaf (== absent). A leaf with
  `balance 0, nonce > 0` is **retained** because its nonce is live replay protection.

### Pool state (anchor cell data)

```
PoolState { pool_id: 32B, chain_id: u64, seq: u64, root: 32B, total: u128, fee_acc: u128 }
```

Invariant, maintained by every transition:

```
Σ leaf.balance  +  fee_acc  ==  total
new_total       ==  prev_total + Σ deposits − Σ withdrawals
```

### Sparse Merkle tree

* Depth 256, keyed by the 256-bit account key.
* Node hash = `keccak(left || right)`. Empty leaf hashes to 32 zero bytes; default
  subtree hashes are derived bottom-up from that.
* **Keccak, not blake2b.** SP1 has a keccak precompile, so the in-circuit SMT is
  cheap. The on-chain force-exit verifier MUST use this exact keccak SMT so an
  off-chain proof verifies on-chain unchanged. (Reference implementation:
  [`crates/stf/src/smt.rs`](../crates/stf/src/smt.rs).)

---

## 3. Canonical serialization & domain separation

Everything hashed or signed uses an explicit fixed-width big-endian layout, no
serde, no molecule, so all implementations recompute byte-identical digests. This is
the defence against "divergent root" disputes.

Signed message digests are domain-separated and bound to chain + pool + version:

```
transfer_msg = keccak( DOM_TRANSFER ‖ chain_id ‖ pool_id ‖ from_key ‖ to_key
                       ‖ amount ‖ fee ‖ nonce ‖ expiry )
withdraw_msg = keccak( DOM_WITHDRAW ‖ chain_id ‖ pool_id ‖ from_key
                       ‖ target_lock_hash ‖ amount ‖ nonce ‖ expiry )
```

where `DOM_* = keccak("LIQUIDCELLS/v1/<purpose>")`. Distinct domains prevent a
transfer signature being replayed as a withdrawal, or a Pool-A intent on Pool B.

---

## 4. The state-transition function

`apply(state, batch)` advances the pool by exactly one sequence number. Any error
invalidates the whole batch (no partial application). Order within a batch:
**deposits → transfers → withdrawals.**

**Deposit** (`{to_key, amount}`), authority is the on-chain deposit cell, bound via
the deposits commitment; **no signature**. Credits the leaf, increases `total`.

**Transfer** (`{from_pubkey, to_key, amount, fee, nonce, expiry, sig}`):
1. `from_key = keccak(from_pubkey)`, reject `from_key == to_key`.
2. `nonce == from.nonce` (else `BadNonce`, replay protection).
3. `expiry >= current_epoch` (else `Expired`).
4. **Verify `sig` over `transfer_msg`**, the sole debit authority.
5. `from.balance >= amount + fee` (else `InsufficientBalance`).
6. `from -= amount+fee; from.nonce += 1; to += amount; fee_acc += fee`.
   `total` is unchanged (the fee stays in the pool).

**Withdrawal** (`{from_pubkey, target_lock_hash, amount, nonce, expiry, sig}`): same
checks; debits the owner, decreases `total`, and folds `(target_lock_hash, amount)`
into the withdrawals commitment so the checkpoint tx MUST create a matching output.

**Finalize:** recompute `new_root`, `new_seq = prev_seq+1`, assert the conservation
invariant, emit `PublicValues`.

---

## 5. Public values & on-chain binding

The guest commits:

```
PublicValues {
  pool_id, chain_id,
  prev_root, prev_seq, new_root, new_seq,
  deposits_commitment, withdrawals_commitment,
  prev_total, new_total, fee_delta, current_epoch
}
```

The anchor **type script** accepts a checkpoint tx iff **all** hold:

1. Groth16 proof verifies against the baked verification key (the "baked policy").
2. `prev_root/prev_seq/prev_total` == old anchor cell data; `new_root/new_seq/new_total`
   == new anchor cell data; `new_seq == prev_seq + 1`.
3. `deposits_commitment` == keccak-fold over the deposit cells **consumed** by this tx
   (binds both ways: no phantom deposits, no dropped real ones).
4. `withdrawals_commitment` == keccak-fold over the output cells **created** (each
   output's `(lock_hash, capacity)` must match what the proof authorized).
5. `da_commitment` == `keccak(diff_blob)` where `diff_blob` is in this tx's witness.
6. `current_epoch` consistent with the tx `since` (epoch-based).
7. Capacity conservation at the CKB level as a backstop.

This is the entire trust core, and it mirrors the existing Groth16-verifier-gates-a-
root-toggle pattern already deployed on CKB in related work.

---

## 6. Data availability

Each checkpoint posts a **diff blob** in the tx witnesses: the `(key, new_leaf)`
pairs for every touched leaf this batch. Witnesses are priced as tx **fee by size**,
not locked **capacity**, which is what makes on-chain DA affordable on CKB.

* Minimum for trustless exit: the leaf diffs (a verifier folds all diffs from genesis
  to reconstruct the current tree and any user's proof).
* Optional richer tier: the full ordered transfer log, for independent re-proving.

Because DA is on-chain, **no honest-watcher assumption is needed anywhere**.

---

## 7. Exit paths

### 7.1 Single-leaf force-exit (no proving)

An individual exit is a plain **SMT inclusion proof** of one leaf against the last
committed `new_root`, verified natively in the type script, cheap, no zk. The user
reconstructs their proof from on-chain DA, so it works even if the operator is gone.

### 7.2 Escape hatch

If no checkpoint lands for `T` epochs, the anchor enters force-exit mode and anyone
may submit single-leaf force-exits against the last committed root. The operator
cannot freeze funds.

### 7.3 Atomic-swap / Fiber egress (any denomination)

The 61-CKB cell floor means small balances cannot self-exit. The trustless answer is
a hash-locked swap:

```
in-pool:  user signs a transfer of B to the LP, finalizable only on preimage P (hash H)
L1/Fiber: LP sends B−fee locked by the same H, with a timeout
          user reveals P to claim the L1/Fiber funds → LP uses P to finalize in-pool
          (no reveal → both legs time out → no harm)
```

This needs one extra transfer variant (hashlock + timeout) in the STF, Phase 5.

---

## 8. Throughput (deferred, not trust-critical)

* **Single anchor cell** serializes checkpoints (CKB hot-cell contention). Mitigation:
  shard into N anchors keyed by account-key prefix; cross-shard transfers use a
  two-phase lock-in-A / credit-in-B. Phase 6.
* **Batch cycle/proving budget** bounds leaves-per-checkpoint. Fixed after Phase 1
  measures real SP1 cycle cost (secp256k1 verification dominates).

With the escape hatch live, both are performance knobs, not safety assumptions.

---

## 9. Why SP1

* The STF is plain Rust → it is *both* the sequencer and the guest, so determinism is
  free and the divergent-root class of bugs cannot occur.
* SP1 precompiles for **secp256k1** and **keccak** make the two dominant in-circuit
  costs (signature checks, SMT hashing) tractable, and let in-pool signatures stay
  native secp256k1, no SNARK-friendly scheme required.
* The STARK is wrapped to **Groth16**, which CKB can already verify on-chain in a
  type script, reusing existing tooling.
