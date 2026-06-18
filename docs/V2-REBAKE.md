# v2 re-bake bundle: runbook + verification status

The v2 bundle is a set of improvements staged behind cargo features, OFF by default so the deployed
SP1 guest stays byte-identical (vkey `0x00213af5...c1e8`) and the deployed anchor unchanged. Most
change the proven program, hence the vkey, so they cannot ship piecemeal: they all flip ON together
in one coordinated re-bake (rebuild the guest, recompute the vkey, re-pin it, redeploy the anchor).
This doc is the checklist for that re-bake, plus the result of verifying the bundle as a whole.

## Bundle scope for THIS re-bake (committee finding A)

The re-bake-readiness committee ruled that **`ecrecover` and `min_fee` are DROPPED from this re-bake**
and deferred to a later, separately-reviewed one. Both are documented below as "integration is
re-bake-time" / "activation is re-bake-time", i.e. they are *un-pre-staged code that would be first
written AT the bake* and so would bake an irreversible vkey over a program that never sat on a green,
twice-audited `main`. `ecrecover` is a pure wire-size optimization (-32 bytes/intent, not a security
fix) and `min_fee` is audit M-3 (LOW, already enforced operationally by the sequencer `FeePolicy`),
so neither is load-bearing for this re-bake's security goals.

**This re-bake ships exactly the five features whose every byte has been on green `main` and through
both internal audits:** `compact_smt + reject_high_s + da_varint + htlc_sha256 + htlc_keyspace`
(carrying H-1, the Fiber-compatible egress, and the compact representation). They compose green
together (CI gate "re-bake go-evidence", `scripts`/`.github/workflows/ci.yml`). If `ecrecover` or
`min_fee` must ship later, land each as a normal reviewed PR with the FULL integration on green main,
re-run both internal audit passes on the integrated form, then bake, never authored at bake time.

## The staged features

| Feature | Crate(s) | Changes the vkey? | What it does |
|---|---|---|---|
| `compact_smt` | stf + ckb-contract + client | yes (guest SMT node-hash rules); the contract/client halves are an off-chain-verifier + witness change | pass-through compact SMT, ~35x fewer reconstruct keccaks |
| `reject_high_s` | stf | yes (sig verify) | reject high-S (malleable) ECDSA sigs (THREAT-MODEL L3) |
| `da_varint` | stf | yes (DA blob bytes) | LEB128 balance/nonce in DA records, ~30-40% smaller blobs |
| `htlc_sha256` | stf + sequencer | yes (guest HTLC hashlock); the sequencer mirror half is off-chain | sha256 (not keccak) HTLC hashlock, Fiber-compatible egress |
| `htlc_keyspace` | stf + sequencer + ckb-contract + client | yes (guest); the contract/client halves are a deployed-format change | audit H-1: lock accumulates, claim/refund sweep-and-consume; force-refund reconstructs/sweeps the real committed balance via a 16-byte-widened witness (FORCEREFUND_LEN 8321 -> 8337) |
| `min_fee` | stf | yes (in-proof fee floor) | reject intents with `fee < MIN_FEE_PER_LEAF` (anti zero-fee griefing). **DEFERRED from this re-bake** (placeholder floor + unresolved zero-fee client legs; M-3 already held by the sequencer `FeePolicy`) |
| `ecrecover` | stf (primitive); integration is re-bake-time | yes (sig scheme + `*_msg` digests) | recover the signer pubkey from the signature, drop the 33-byte `from_pubkey` (net -32 bytes/intent). **DEFERRED from this re-bake** (integration un-pre-staged + un-audited; a wire optimization, not a security fix) |

`htlc_keyspace` is itself a 4-part bundle (guest + sequencer + contract + client) gated by the SAME
feature name in each crate; see `crates/stf/Cargo.toml`. The contract/client halves do not touch the
vkey (force-refund is not the guest), but they ARE a deployed witness-format change, so they redeploy
with the anchor at the re-bake.

`htlc_sha256` ALSO has a sequencer half (found by the v2-bundle internal audit, finding A-1). The
resilient-seal mirror (`crates/sequencer/src/resilient.rs`) re-validates each intent and hashes the
HTLC-claim preimage; it must use the SAME hash the guest STF uses on that axis (keccak by default,
sha256 under `htlc_sha256`), or it silently drops every valid sha256 claim, the Fiber dust-egress leg
this feature exists to enable, as `BadPreimage` on the resilient cadence. So `crates/sequencer` now
forwards `htlc_sha256 = ["liquid-cells-stf/htlc_sha256"]` and gates that check statement-level. At the
re-bake the sequencer build must enable `htlc_sha256` WHENEVER it enables `htlc_keyspace` (the bundle
flips both on together). The sequencer mirror is off-chain, so this is vkey-neutral.

`compact_smt` ALSO has a contract + client half (staged after the v2-bundle internal audit surfaced
that they were missing, the same class of gap as `htlc_sha256`'s sequencer half). The compact tree
changes the SMT node-hashing rules, so the committed-root *scheme* changes. The on-chain escape hatch
(`crates/ckb-contract/src/escape.rs` `force_exit` / `force_refund`) reconstructs the inclusion path
with NO SP1 proof, just keccak SMT walking, so it MUST hash with the same scheme that produced the
committed root, or every valid escape proof would be rejected and the escape hatch would brick under
the compact re-bake. So `escape::smt_root` now has a `#[cfg(feature = "compact_smt")]` arm matching
`smt_compact::{leaf_node, combine}` (key-binding bottom node + pass-through internal nodes), and
`crates/ckb-contract` + `crates/client` both forward `compact_smt` to the STF (the client's
`proof_from_da` then builds compact siblings via the `lib.rs` redirect, so the witnesses it emits
verify against the compact `smt_root`). These halves are off-chain-verifier + witness, NOT the guest,
so they are **vkey-neutral**; they redeploy with the anchor at the re-bake. Validated by running the
force-exit/force-refund suites under `--features compact_smt` (the test tree builds compact too) and
under `--features "htlc_keyspace compact_smt"` (both deployed-format changes compose).

The single-leaf escape witness is also SIZE-compacted under `compact_smt` (v2 witness-size
compaction): instead of 256 full siblings (~8 KB, almost all `EMPTY_LEAF` zeros under the compact
tree) it carries a 32-byte bitmap + ONLY the non-empty siblings (~log2(pool) of them, so ~a few
hundred bytes, roughly 25-35x smaller). Because that makes the escape witnesses variable-length, they
are dispatched by a leading 1-byte mode tag (`FORCE_EXIT_TAG` 0x01 / `FORCE_REFUND_TAG` 0x02) instead
of by length; a checkpoint stays the fixed 644-byte SP1 proof (no sparse escape witness is 644 bytes).
The sparse format is shared via `smt_compact::sparse_encode_proof` / `sparse_decode_proof` (client +
ckb-contract-tests) and decoded independently on-chain by `escape::smt_root_sparse`; the
forceexit/forcerefund suites (under `compact_smt`) plus an stf `sparse_proof_round_trips_and_rejects_malformed`
unit test pin the encode/decode to agree, and the deployed length-dispatch red-team (ATTACK H) is
gated to the deployed build (tag-dispatch replaces it). The client/tests/contract all hardcode the
same two tag bytes (validated end-to-end by the escape suites).

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

0. **Confirm bundle scope.** This re-bake ships exactly `compact_smt + reject_high_s + da_varint +
   htlc_sha256 + htlc_keyspace` (see "Bundle scope for THIS re-bake" above). `ecrecover` and `min_fee`
   are NOT in it. Confirm the CI "re-bake go-evidence" jobs are green on the exact commit being baked
   (the composed STF bundle + the anchor under `htlc_keyspace compact_smt`).
1. **Build the guest** with those five features ON, in the EXACT pinned toolchain that reproduced the
   feature-OFF vkey: **succinct rustc 1.94.0** (cargo-prove's toolchain, == the
   `ghcr.io/succinctlabs/sp1:v6.2.4` image) with the **`sp1-zkvm` / `sp1-sdk` 6.2.3 crate** version
   committed in the guest/host crates (the image tag v6.2.4 and the crate dep 6.2.3 are distinct and
   both matter), from build path `$HOME/liquid-cells` with `HOME=/root` (SP1 bakes the absolute source
   path into the ELF). Recompute the vkey.
2. **Confirm the NEW vkey reproduces:** re-run the guest-ELF rebuild a second time (clean) and confirm
   it yields the same vkey byte-for-byte before trusting it. A non-reproducing vkey means the build
   environment is not actually pinned and MUST be fixed before deploying.
3. **Re-pin the new vkey in ALL nine sites** and run `scripts/verify-vkey.sh` (it now checks every
   one): `crates/ckb-contract/src/main.rs` `VKEY_HASH`; the four host bins `prove_one.rs` /
   `prove_typeid.rs` / `vkeycheck.rs` / `sequence.rs` `EXPECTED_VKEY`; and the four fixture files
   `fixtures/vkey.txt` + `fixtures/{genesis,wd,dw}/vkey.txt`. A missed host-bin re-pin passes the old
   guard but panics the prover / the live sequencer loop on the first post-rebake checkpoint.
4. **Regenerate the Groth16 fixtures** against the new guest.
5. **Build + test each crate under its matching features** as the pre-deploy gate:
   anchor `cargo build --release --features "htlc_keyspace compact_smt"` then ckb-contract-tests
   `cargo test --release --features "htlc_keyspace compact_smt"`; sequencer
   `--features "htlc_keyspace htlc_sha256"`; client `--features "htlc_keyspace compact_smt"`.
   (Forgetting `compact_smt` on the anchor deploys an escape hatch that reconstructs depth-256 roots
   while the guest commits compact roots, bricking force-exit/force-refund.)
6. **Pre-flight the new anchor binary against the REAL consensus cycle limit** (~3.50B), not
   ckb-testtool's 5B self-limit, via `ckb-debugger`, AND verify a checkpoint + a force-exit + a
   force-refund on a THROWAWAY type-id'd test pool before touching a real pool (the cycle overrun at
   3.81B > 3.50B already happened once and was hidden by the testtool limit).
7. **Redeploy the anchor** code cell (new code hash, in-place type-id upgrade). Refresh the
   deposit-lock binding (`pool_type_hash`) and any genesis/anchor references. **Also rebuild + redeploy
   the deposit-lock code cell:** the LIVE Pudge deposit lock predates the H-2 checkpoint-mode-gate fix,
   so until it is redeployed (and `sweep_in_force_exit_mode_rejected` re-verified live) the live lock
   can still be siphoned by an escape-mode tx.
8. **Update DEPLOY.md** with the new vkey, code hashes, and dep outpoints.

## Dry-run results (executed 2026-06-17, testnet)

A full testnet dry-run of this re-bake was run end-to-end: build the bundle guest, regenerate the
Groth16 fixtures, re-pin the vkey, rebuild the anchor, run the whole `ckb-contract-tests` suite. It
validated the chain and surfaced five concrete corrections to the steps above. With the corrections
applied the bundle works end-to-end.

- **New (dry-run) vkey: `0x005ecccf7ccec70d25badc97aa62812f208997f15b3ca9db0f8f56c3c76dfae6`**,
  reproduced byte-for-byte across a clean rebuild (step 2 satisfied).
- The anchor suite is GREEN under `--features "htlc_keyspace compact_smt"` (106 tests; all four
  modes: genesis / checkpoint / deposit+withdrawal binding / force-exit + force-refund).
- Checkpoint verified on CKB-VM at **80,352,804 cycles** (~2.3% of the 3.50B consensus limit).

Corrections to fold into the steps:

1. **The prover host is feature-coupled to the guest (corrects steps 4-5; most important finding).**
   The guest input/output codec changes with the bundle (`compact_smt` makes the witness siblings
   sparse, `da_varint` changes the DA blob), so the prover that ENCODES the guest input and DECODES
   its committed output, `crates/sp1-host` (`liquid-cells-host`, `prove_one`, `prove_typeid`,
   `lc-sequence`), must be built with the SAME five features as the guest. A default-feature host
   feeds the re-baked guest input it cannot parse: the guest commits EMPTY public values, and every
   downstream check fails confusingly (the in-process SP1 verify panics `UnexpectedExitCode(1)`;
   `decode pv` hits `Eof`). The same holds for every off-chain STF consumer that builds guest input
   or reconstructs leaves/witnesses from L1 DA: `crates/sequencer`, `crates/sequencer-service`,
   `crates/client`, `crates/wasm`. Build ALL of them with the bundle, not just the guest.

2. **`htlc_sha256` needs the SP1 `sha2` patch in EVERY standalone workspace that enables it (corrects
   step 1).** `htlc_sha256` pulls `sha2`; the STF pins `sha2 = "=0.10.8"` while `sp1-zkvm` 6.2.4
   transitively wants `0.10.9`, an unresolvable conflict until you add the SP1 `sha2` fork to that
   crate's `[patch.crates-io]` and re-resolve the lock. Each standalone `[workspace]` (guest, host,
   sequencer-service, client, wasm) has its OWN lockfile and needs:
   `sha2 = { git = "https://github.com/sp1-patches/RustCrypto-hashes", package = "sha2", tag = "patch-sha2-0.10.8-sp1-6.2.0" }`
   plus `cargo update -p sha2 --precise 0.10.8`. The fork is native-safe (its precompile is gated to
   the zkvm target).

3. **Derive the contract `VKEY_HASH` array programmatically; do not hand-split the hex (corrects step
   3).** Hand-splitting the 64-hex vkey into the `[u8; 32]` array silently corrupted it (a one-nibble
   shift from byte 11). The symptom is subtle: every POSITIVE checkpoint proof fails to verify
   on-chain while every tamper/negative test still passes, so a partial run looks fine. Generate the
   array from `fixtures/vkey.txt` (`python3 -c "print(', '.join('0x%02x'%x for x in bytes.fromhex(open('fixtures/vkey.txt').read().strip()[2:])))"`)
   and run `scripts/verify-vkey.sh`: its array-reconstruction check compares the contract bytes to
   `fixtures/vkey.txt` and catches this before any build.

4. **The cycle-margin worry is obsolete (corrects step 6).** The anchor verifier migrated to
   `ark-bn254` (`crates/groth16`); the measured checkpoint cost is ~80M cycles, not the old
   substrate-bn ~3.47B that needed the `e(alpha,beta)` precompute to fit. The 3.81B-over-3.50B
   overrun cannot recur with this verifier. Still pre-flight on a throwaway pool, but the margin is
   now ~98%, not ~1%.

5. **Test-helper fix (already on main, bundle-OFF-safe).** `tests/redteam_escape2.rs` `build_refund`
   was missing the `#[cfg(feature = "htlc_keyspace")]` `actual_balance` field that `forcerefund.rs`
   carries, so `sanity_valid_refund_passes` failed under the composed bundle (the refund witness was
   16 bytes short). Fixed to append the escrow balance; the fix is cfg-gated, so it is invisible when
   the bundle is OFF.

6. **The contract `EMPTY_ROOT` is not `compact_smt`-aware: genesis of a compact pool is bricked
   (corrects step 7; found by attempting the live deploy).** Under `compact_smt` the STF's empty
   tree roots to `EMPTY_LEAF` = `[0u8; 32]` (`smt_compact::Smt::root`), NOT the depth-256 keccak
   fold `0xa7ff9e28`. But the anchor baked `EMPTY_ROOT` (which `genesis()` pins the new anchor root
   to, code 70) had no `compact_smt` variant, so a real compact-pool genesis would be rejected
   on-chain (or its first checkpoint's `prev_root` would not match a `0xa7ff9e28` genesis anchor).
   The off-chain genesis test did NOT catch this: `tests/genesis.rs` hardcoded the same `0xa7ff9e28`
   with no feature variant, so it mirrored the wrong contract constant and stayed green. Fixed both
   to bake `[0u8; 32]` under `compact_smt` (cfg-gated, so the deployed feature-off contract is
   unchanged); the genesis test now actually exercises the compact empty root. `lc-genesis.mjs`
   (the live deploy script) likewise hardcodes `0xa7ff9e28` and must use the zero root for a compact
   pool.

### Live deploy DONE (Pudge throwaway pool, 2026-06-18)

The full live throwaway-pool deploy was executed end to end on Pudge with the bundle build (guest +
host + anchor under the 5 features, vkey `0x005ecccf…dfae6`), validating the whole re-bake chain on
the real CKB-VM, including finding 6's fix on-chain:

| Live artifact (throwaway, testnet only) | Value |
|---|---|
| Bundle anchor `codeHash` (fresh type-id) | `0x3a8f90a18b29def27880a4474ec109b062d598677d14d45808be29674bc16610` |
| Bundle anchor code-dep | `0xed70ebff37c19ef532d9f94573556d293945c266e77a3dc1cbfaca131c720c2c:0` |
| Bundle program vkey | `0x005ecccf7ccec70d25badc97aa62812f208997f15b3ca9db0f8f56c3c76dfae6` |
| Genesis anchor (compact empty root `0x00..00`, seq 0) | `0xe0b534a810f15697552c82ec9c833a8eaa3aa09389590c6efa34ad00c9c67ed1:0` |
| Bootstrap deposit cell | `0xe0b534a8…:1` (100 CKB, to_key `0xaa61b794…`) |
| **Checkpoint tx (seq 0 -> 1), bundle proof verified on live CKB-VM** | `0x19c5c340aee362ca0c90f30693828355c92695607ca9fadccd50d30d1c0d7a21` (committed, block 21460500) |
| Anchor after checkpoint (live) | `0x19c5c340…:0` (root `0x2aac2b52…`, seq 1, total 9999900000) |

What this proves on-chain: (a) the genesis branch accepts the compact `[0;32]` root (finding 6 fix;
before it, code 70), and (b) the live CKB-VM's ark-bn254 verifier accepts a real bundle Groth16 proof
(5 features ON, new vkey) and advances a compact pool. The deploy scripts used live on the Windows
side at `D:\cellswap\cellswap-complete`: `lc-bundle-deploy.mjs` / `lc-bundle-genesis.mjs` /
`lc-bundle-checkpoint.mjs` (the demo `lc-anchor.bin` + live pools were untouched; this is a separate
throwaway type-id). The real re-bake is audit-gated; this dry-run only validated the mechanics.

### Escape hatch + off-chain consumers validated under the bundle (2026-06-18)

After the checkpoint, the trustless escape hatch and every off-chain STF consumer were validated under
the bundle, closing finding 1 (codec coupling) end to end.

- **Force-exit LIVE on-chain.** The bundle `lc-exit` (client built with `compact_smt` + `da_varint`)
  scraped the pool's checkpoint chain, folded the L1 DA, and rebuilt the leaf trustlessly
  (reconstructed root == on-chain `0x2aac2b52…`, balance 99.99899 CKB), then emitted the SPARSE compact
  force-exit witness (122 bytes). A force-exit tx (`0x71415c46c7c354d934a034b1978176bcbe4487fa00a5c8881a7947127890834a`,
  committed block 21460701) spent the checkpoint anchor with that witness as `witness[0].input_type`:
  the live CKB-VM verified the compact-SMT inclusion + the operator-silence gate (no proof), nullified
  the leaf (new anchor root `0x0691e05e…`), and forced the 99.99899 CKB payout to the owner's secp lock
  (`args=blake160(pubkey)`). The escape hatch works on a bundle pool, no operator, no proof, L1 + key.
- **client / sequencer / wasm build green under the bundle, with gaps fixed.** Each is a separate STF
  consumer that must build with the codec-affecting features, and the runbook's earlier per-crate
  feature lists were INCOMPLETE (this extends finding 1). Gaps found + fixed (all OFF by default, the
  deployed stack is unchanged): the **client** had no `da_varint` forward (added; without it it cannot
  parse a bundle pool's varint DA); the **sequencer** forwarded only `htlc_keyspace`+`htlc_sha256`,
  missing `compact_smt`+`da_varint`+`reject_high_s` (added; 45 tests green under all five); the **wasm**
  SDK got a `bundle` feature forwarding `compact_smt`+`da_varint` to client+stf (node smoke test green;
  the in-browser empty root now reconstructs as the compact `0x00..00`). `lc-exit`'s
  force-exit-witness length assert was also made compact-aware (the sparse witness is variable-length).

**Corrected per-crate build matrix for the re-bake (supersedes step 5's list).** Every STF consumer
needs the FULL set of codec-affecting features it touches:
- guest = all five;
- prover host (`crates/sp1-host`) + sequencer = all five (they produce the guest input / DA blob);
- client + wasm = `compact_smt` + `da_varint` for reconstruction (plus `htlc_sha256` + `htlc_keyspace`
  if they build/claim HTLCs);
- anchor = `htlc_keyspace` + `compact_smt`.

Each standalone workspace that enables `htlc_sha256` also needs the SP1 `sha2` patch + lock pin
(finding 2). NOT exercised live: force-refund (needs an HTLC-lock checkpoint then a refund after a
short htlc_timeout; the silence gate is already open on this pool since `last_epoch=0`).

## Rollback / abort (committee finding G)

The anchor upgrade is an in-place type-id spend that consumes the old code cell, so there is no
implicit undo. Before executing:
- **Archive** the current code-cell bytes + outpoint (anchor AND deposit-lock) so a recovery upgrade
  can redeploy the known-good prior binary.
- **Pre-flight** (step 6) on a throwaway pool against the real consensus cycle limit and all four
  anchor modes (genesis / checkpoint / force-exit / force-refund) under the deployed-format features.
- If the redeployed binary verifies wrong on-chain (a forgotten feature bricks the escape hatch, or a
  cycle overrun), **recovery is a second in-place upgrade** back to the archived binary. This is
  exactly why the C-1 upgrade-key lockdown MUST come AFTER the re-bake is live and validated: locking
  first would force the recovery upgrade through the ~30-day timelock.

## Notes

- The whole bundle is OFF in `main`, so nothing here affects the live deployment; this is staged work
  that activates only at a deliberate re-bake (which is itself gated on the external audit per
  HARDENING.md / AUDIT-READINESS.md).
- `verify-vkey.sh` asserts every bundle feature is OFF in the deployed guest, so an accidental leak
  (which would silently invalidate the deployed vkey) fails CI.
