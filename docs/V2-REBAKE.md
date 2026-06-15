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
| `ecrecover` | stf (primitive); integration is re-bake-time | yes (sig scheme + `*_msg` digests) | recover the signer pubkey from the signature, drop the 33-byte `from_pubkey` from each signed intent (net -32 bytes/intent) |

`htlc_keyspace` is itself a 4-part bundle (guest + sequencer + contract + client) gated by the SAME
feature name in each crate; see `crates/stf/Cargo.toml`. The contract/client halves do not touch the
vkey (force-refund is not the guest), but they ARE a deployed witness-format change, so they redeploy
with the anchor at the re-bake.

## `ecrecover`: primitive staged, integration is a re-bake-time change

The reusable crypto is staged and tested behind the `ecrecover` feature (`crates/stf/src/sig.rs`:
`sign_recoverable` produces `r‖s‖recovery_id` (65 bytes); `recover` returns the signer pubkey;
`crates/stf/tests/ecrecover.rs` proves the round-trip, the message/signature authentication, and the
32-byte saving). The verifier derives the SMT key as `keccak(recovered_pubkey)`, so a signed intent
need not carry `from_pubkey`: `(33 pubkey + 64 sig) -> 65` is **-32 bytes per signed transfer /
withdrawal / htlc_lock** on the wire (DA + witness).

The FULL integration is deliberately NOT pre-staged behind `#[cfg]`, because it ripples destructively:
- the signed message must be **independent of the pubkey** (recovery is circular otherwise), so the
  `transfer_msg` / `withdraw_msg` / `htlc_lock_msg` digests must omit the sender key, changing every
  call site;
- the intent structs drop `from_pubkey` and widen `sig` to 65 bytes, changing `codec`,
  `touched_keys`, `apply`, the client builders, and every test fixture that constructs an intent.

So `ecrecover` is implemented AT the re-bake (which re-bakes the vkey regardless): swap the `*_msg`
digests to the pubkey-free form, drop the field and use `sig::recover` in `apply`/`touched_keys`/
`codec`, and have the client sign with `sign_recoverable`. The primitive here is the load-bearing
crypto; the rest is mechanical wiring done once, unconditionally, at that point.

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

`MIN_FEE_PER_LEAF = 1` rejects **fee == 0** intents, and `min_fee` was never run against the full
suite. The implication runs deeper than fixtures: **every leaf must pay the floor**, so any API or
test that builds a zero-fee intent breaks. So **activating `min_fee` is a coordinated task, not a
flag flip**.

### Done (the STF, the vkey-bearing core, is min_fee-clean and the bundle composes green)

- The STF passes the FULL bundle (all six features) together: `cargo test -p liquid-cells-stf
  --features "compact_smt reject_high_s da_varint htlc_sha256 htlc_keyspace min_fee"` is GREEN. The
  zero-fee fixtures across `tests/da.rs`, `properties.rs`, `htlc.rs`, `redteam.rs` were raised to a
  non-zero fee (the value is incidental to each: adversarial tests still fail on their intended
  error, conservation/witness-consistency tests are unaffected since the fee is the payer's).
- `Account::sponsor_fee` reworked to pay `MIN_FEE_PER_LEAF` on its sponsor leg (the const is now
  always-defined, single source of truth), so a sponsored micro-tip is valid under `min_fee`. The
  const ungating is vkey-neutral (an unused const is dead-code-eliminated from the guest).

### Remaining (do at activation, with the final floor)

1. **Finalize the floor.** `MIN_FEE_PER_LEAF` is a placeholder `1`. Set it to cover the real per-leaf
   proving + DA + L1 cost. NOTE: a larger floor re-breaks any fixture using a fee below it, so do the
   fixture pass (below) AFTER fixing the value.
2. **The other zero-fee client APIs** must pay the floor like `sponsor_fee`, or document a non-zero
   fee requirement: `Account::split_payment` (both legs fee 0) and `Account::batch_transfer` (per-leg
   fee defaults 0). This is an API/economics decision (the legs absorbing a floor changes the exact
   `cut + recipient == gross` relation), so it is deliberately deferred, not rushed at the placeholder
   floor.
3. **Off-chain fixtures.** The sequencer and client run the same STF, so once they forward `min_fee`
   (a one-line feature each) their fee-0 test fixtures need the same raise the STF suite got (the STF
   pass is the template). Failing sets recorded at the time: sequencer `all_valid_batch...`,
   `disabled_policy_is_a_no_op`, `plain_seal_batch...`, `poison_intent...`, `sealing_after_recovery...`;
   client `split_payment` / `batch_transfer` / `snapshot` / `fan_tips` (which also need item 2).

## Re-bake execution steps

1. Wire in `ecrecover` (the primitive is staged + tested in `sig.rs`; the re-bake does the
   integration: pubkey-free `*_msg` digests, drop `from_pubkey` and use `sig::recover` in
   `apply`/`codec`/`touched_keys`, client signs with `sign_recoverable`) and confirm the suite is
   green with it on.
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
