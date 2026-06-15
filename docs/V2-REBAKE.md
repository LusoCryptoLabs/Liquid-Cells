# v2 re-bake bundle: runbook + verification status

The v2 bundle is a set of improvements staged behind cargo features, OFF by default so the deployed
SP1 guest stays byte-identical (vkey `0x00213af5...c1e8`) and the deployed anchor unchanged. Most
change the proven program, hence the vkey, so they cannot ship piecemeal: they all flip ON together
in one coordinated re-bake (rebuild the guest, recompute the vkey, re-pin it, redeploy the anchor).
This doc is the checklist for that re-bake, plus the result of verifying the bundle as a whole.

## The staged features

| Feature | Crate(s) | Changes the vkey? | What it does |
|---|---|---|---|
| `compact_smt` | stf | yes (SMT node-hash rules) | pass-through compact SMT, ~35x fewer reconstruct keccaks |
| `reject_high_s` | stf | yes (sig verify) | reject high-S (malleable) ECDSA sigs (THREAT-MODEL L3) |
| `da_varint` | stf | yes (DA blob bytes) | LEB128 balance/nonce in DA records, ~30-40% smaller blobs |
| `htlc_sha256` | stf | yes (HTLC hashlock) | sha256 (not keccak) HTLC hashlock, Fiber-compatible egress |
| `htlc_keyspace` | stf + sequencer + ckb-contract + client | yes (guest); the contract/client halves are a deployed-format change | audit H-1: lock accumulates, claim/refund sweep-and-consume; force-refund reconstructs/sweeps the real committed balance via a 16-byte-widened witness (FORCEREFUND_LEN 8321 -> 8337) |
| `min_fee` | stf | yes (in-proof fee floor) | reject intents with `fee < MIN_FEE_PER_LEAF` (anti zero-fee griefing) |

`htlc_keyspace` is itself a 4-part bundle (guest + sequencer + contract + client) gated by the SAME
feature name in each crate; see `crates/stf/Cargo.toml`. The contract/client halves do not touch the
vkey (force-refund is not the guest), but they ARE a deployed witness-format change, so they redeploy
with the anchor at the re-bake.

## NOT yet staged (do at the re-bake itself)

- **`ecrecover`**: recover the signer pubkey from the signature instead of carrying it, dropping 33
  bytes from each `Transfer`/`Withdrawal`/`HtlcLock` and the force-exit witness. This is a struct
  change that ripples through `codec` / `touched_keys` / the client / tests, so it is not cleanly
  pre-stageable behind a `#[cfg]`; implement it AT the re-bake (it re-bakes the vkey anyway).

## Verification: does the bundle compose?

Run the STF suite with the representation/logic features all ON together:

```
cargo test -p liquid-cells-stf --features "compact_smt reject_high_s da_varint htlc_sha256 htlc_keyspace"
```

Result: **GREEN, the five compose cleanly** (no interaction failures). They are independent
representation/logic changes (SMT hashing, sig rule, DA layout, HTLC hash, HTLC keyspace) and do not
collide.

`min_fee` is the outlier. With it added:

```
cargo test -p liquid-cells-stf --features "compact_smt reject_high_s da_varint htlc_sha256 htlc_keyspace min_fee"
```

fails ~11 tests. `MIN_FEE_PER_LEAF = 1` rejects **fee == 0** intents, and many fixtures (and one real
API) build zero-fee intents. This is not a feature-interaction bug; `min_fee` simply was never run
against the full suite. So **activating `min_fee` is a coordinated task, not a flag flip** (below).

## `min_fee` activation checklist (do before flipping it on)

1. **Finalize the floor.** `MIN_FEE_PER_LEAF` (crates/stf/src/transition.rs) is a placeholder `1`.
   Set it to cover the real per-leaf proving + DA + L1 cost.
2. **Sponsored fees.** `Account::sponsor_fee` (crates/client/src/lib.rs) builds a `transfer(.., fee=0)`
   on the sponsor's leg, which `min_fee` rejects. Rework it so the sponsor's transfer pays >= the
   floor (the sponsor absorbs one floor on top of the sponsored amount), or document that sponsorship
   requires a non-zero sponsor-leg fee under `min_fee`.
3. **Test fixtures.** Raise the zero-fee intents these tests build to >= the floor (the value is
   incidental to each: adversarial tests still fail on their intended error, accounting tests are
   unaffected because the fee is the payer's). One already done: `tests/da.rs` (fee 0 -> 1).
   Remaining: `htlc_lock_removes_funds_from_spendable_balance`, `insufficient_balance_is_rejected`,
   `no_debit_without_valid_signature`, `replay_is_rejected_by_nonce`,
   `smt_proof_membership_and_nonmembership`, `tampering_amount_after_signing_is_rejected`,
   `attack_intra_batch_double_spend`, `attack_cross_pool_replay`, `attack_keyset_stability_all_ops`,
   `attack_htlc_claim_and_refund_same_batch`, `attack_htlc_claim_then_refund_double_credit`.

## Re-bake execution steps

1. Implement `ecrecover` (the only unstaged item) and confirm the STF suite is green with it on.
2. Complete the `min_fee` activation checklist above.
3. Build the guest with ALL bundle features ON (the re-bake config), in the pinned toolchain
   (rustc 1.96.0 / SP1 6.2.x, build path `$HOME/liquid-cells`), and recompute the vkey.
4. Re-pin the new vkey in all three sites (scripts/verify-vkey.sh checks they agree):
   `crates/ckb-contract/src/main.rs` `VKEY_HASH`, `fixtures/vkey.txt`,
   `crates/sp1-host/src/bin/prove_one.rs` `EXPECTED_VKEY` (and the other host bins that bake it).
5. Re-generate the Groth16 fixtures against the new guest.
6. Build the anchor with `--features htlc_keyspace` (the widened force-refund witness) and run the
   contract suite with the matching feature:
   `cd crates/ckb-contract && cargo build --release --features htlc_keyspace` then
   `cd ../ckb-contract-tests && cargo test --release --features htlc_keyspace`.
7. Redeploy the anchor code cell (new code hash) under the timelocked upgrade lock; refresh the
   deposit-lock binding (`pool_type_hash`) and any genesis/anchor references.
8. Update DEPLOY.md with the new vkey, code hash, and dep outpoints.

## Notes

- The whole bundle is OFF in `main`, so nothing here affects the live deployment; this is staged work
  that activates only at a deliberate re-bake (which is itself gated on the external audit per
  HARDENING.md / AUDIT-READINESS.md).
- `verify-vkey.sh` asserts every bundle feature is OFF in the deployed guest, so an accidental leak
  (which would silently invalidate the deployed vkey) fails CI.
