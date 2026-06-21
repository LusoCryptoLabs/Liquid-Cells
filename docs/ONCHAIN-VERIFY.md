# On-Chain Verification Recipe (Phase 2)

What the CKB **anchor type script** must do to accept a checkpoint transaction. It
has two jobs: (1) verify the SP1 Groth16 proof, and (2) pin the proof's public
values to on-chain facts. Reference artifacts for the verifier live in
[`../fixtures/reference/`](../fixtures/reference/); a real proof + inputs triple
lives in [`../fixtures/`](../fixtures/) (regenerate with `scripts/groth16.sh`).

> Live constants: vkey `0x00213af5...c1e8`, PublicValues 288 bytes. See DEPLOY.md / SPEC.md for every deployed hash.

SP1 circuit version: **SP1 crate 6.2.3 (build image v6.2.4)**. Program vkey (baked policy):
`0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8`.

---

## 1. Verify the SP1 Groth16 proof

This mirrors `SP1VerifierGroth16.sol` / `Groth16Verifier.sol` (vendored under
`fixtures/reference/`). The CKB script reuses an on-chain BN254 Groth16 verifier
(the same primitive already deployed in the cardano-ckb-isomorphic bridge / g16ckb).

**Proof layout** (356 bytes, in a witness):

```
proof[0..4]      selector   = bytes4(VERIFIER_HASH) = 0x4388a21c   (must match)
proof[4..36]     exitCode   (u256 BE)               must == 0
proof[36..68]    vkRoot     (u256 BE)               must == VK_ROOT
proof[68..100]   nonce      (u256 BE)
proof[100..356]  groth16    = 8 × u256  (A.x A.y B.x0 B.x1 ... the BN254 proof)
```

Constants (circuit v6.1.0):
* `VERIFIER_HASH = 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`
* `VK_ROOT       = 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352`

**Public-values digest**, note **SHA-256**, not keccak, for *this* digest:

```
publicValuesDigest = sha256(publicValues) & ((1 << 253) - 1)     // mask the top 3 bits
```

**Groth16 public inputs** (5 field elements, in order):

```
inputs[0] = programVKey         // the baked vkey above, as a BN254 scalar
inputs[1] = publicValuesDigest
inputs[2] = exitCode            // 0
inputs[3] = vkRoot              // VK_ROOT
inputs[4] = nonce
```

The BN254 verifying key (alpha/beta/gamma/delta + 6 IC points, since 5 inputs) is
embedded in `Groth16Verifier.sol` / `groth16_vk.bin`. The script runs the standard
pairing check `e(A,B) == e(alpha,beta) · e(vk_x, gamma) · e(C, delta)` where
`vk_x = IC[0] + Σ inputs[i]·IC[i+1]`.

> `publicValues` here is exactly our `PublicValues::encode()` (288 bytes). The proof
> binds it via the SHA-256 digest, so any change to a single public value invalidates
> the proof.

## 2. Pin the public values to chain facts

After the proof verifies, decode `publicValues` (288 bytes, see `codec::PublicValues`)
and enforce, this is the part that makes the rollup *mean* something:

| Public value | Pinned to |
|---|---|
| `pool_id`, `chain_id` | constants baked into the type script |
| `prev_root`, `prev_seq`, `prev_total` | the **input** anchor cell's data |
| `new_root`, `new_seq`, `new_total` | the **output** anchor cell's data |
| `new_seq == prev_seq + 1` | monotonic sequence |
| `deposits_commitment` | keccak-fold over the deposit cells **consumed** by this tx |
| `withdrawals_commitment` | keccak-fold over the output cells **created** (lock hash + amount) |
| `current_epoch` | consistent with the tx `since` (epoch-based) |
| DA: `keccak(diff_blob)` | the diff blob present in this tx's witness |
| capacity | `anchor_out + Σ withdrawals == anchor_in + Σ deposits − fee` (CKB-level backstop) |

`deposits_commitment` / `withdrawals_commitment` are the `keccak`-folds defined in
`transition::fold_commit` (`acc = keccak(acc ‖ key/lock ‖ amount_be)`, seeded with the
domain tag). The script recomputes them from the real cells and checks equality, so
the proof cannot claim deposits/withdrawals that the transaction does not actually
move.

## 3. Phase 2b (done, shipped + live on Pudge)

* DONE: g16ckb BN254 verifier re-ported into the `ckb-contract` type script.
* DONE: `sha256` (for the digest) and `keccak` (for the commitments) wired in CKB-VM.
* DONE: BN254 field-element endianness confirmed between SP1's encoding and the CKB verifier.
* DONE: tested against `fixtures/` (real proof + public values + vkey).
