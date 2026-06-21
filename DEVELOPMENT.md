# Development Log

A running record of what was built each working session, newest first. Every entry
should be committed and pushed to `main`. Keep it factual: what landed, what was
decided, what is next.

> Convention: commit straight to `main`, no AI/co-author attribution on commits.

---

## 2026-06-21, deposit-lock H-2 hardening live on Pudge; repo tidy-up

**Deposit-lock H-2 hardening (live).** The live Pudge deposit lock predated the H-2
checkpoint-mode-gate fix (V2-REBAKE step 7), so until now an escape-mode tx could still siphon a
deposit cell. Rebuilt `liquid-cells-deposit-lock` from the current source (19,864-byte ELF, sha256
`fc0d8082…`, distinct from the Jun-12 binary), validated it offline (23 deposit-lock tests green,
including `sweep_in_force_exit_mode_rejected`, `sweep_in_force_refund_mode_rejected`,
`e2e_sweep_diverted_to_attacker_must_reject`), then deployed it as an in-place type-id upgrade: tx
`0x02f6f52e…`, same codeHash `0x0d610c61…`, data_hash `0xb9bdbfc4…` to `0x977db97a…`, old code cell
consumed. DEPLOY.md updated (current dep `0x02f6f52e…:0`). This is independent of the audit-gated
vkey re-bake, since the deposit lock is a lock script, not the proven circuit.

**Repo tidy-up.** Removed all long dashes from project-authored files (the lone em dash plus en
dashes across README, ROADMAP, four docs, and one test comment became hyphens; the vendored `bn`
crate is left untouched). Removed the last Claude reference in tracked files by rewording the
`.gitignore` comment, and deleted the local `backup/pre-attribution-scrub` tag, the only remaining
carrier of old `claude.ai` commit footers (the main history was already clean). Added
`node_modules/` to `.gitignore`. The `.bin` files under `fixtures/` are intentional test fixtures
and stay tracked.

**Next.** Mainnet still gated on the external audit and the C-1 upgrade-key lockdown; the v2 vkey
re-bake remains audit-gated.

## 2026-06-13, deposit lock: cross-pool isolation now test-proven

The deposit lock's sweep path matches a deposit against ONE `pool_type_hash`, and the source has
long claimed that binding a deposit to a *type-id'd* anchor closes the cross-pool sweep caveat
(`crates/ckb-contract/src/deposit_lock.rs`). That was prose, not a test: the suite covered the
matching-pool sweep, refund, and third-party-theft cases, but never the negative that a deposit
bound to pool A is refused by a *different* pool B's checkpoint.

**What landed.** A `SweepWithForeignPool` case in `crates/ckb-contract-tests/tests/deposit_lock.rs`:
a second always-success stand-in with different args (a distinct type hash, exactly as two
type-id'd anchors differ) stands in for pool B; a deposit bound to pool A's hash is spent alongside
B's checkpoint and the lock rejects it. The arm is identical to the passing `SweepWithPoolInput`
except for the input's type hash, so the rejection is attributable solely to the cross-pool
mismatch. `sweep_into_a_foreign_pool_rejected` asserts the failure. Contract integration suite now
51 (was 50), 7 deposit-lock (was 6); full STF/sequencer/client/demo-ui suites unchanged and green.

**Environment note.** This session ran in a fresh cloud container: Rust + the RISC-V target build
the contract and run the full ckb-testtool suite, but SP1 (`cargo-prove`) is not installed and the
live submit driver (`lc-demo-checkpoint.mjs`) lives outside the repo on the operator machine. So no
proof could be generated and no Pudge tx was sent from here; this change is contract-test-only.

**Open (operator machine, unchanged scope).** The HARDENING line-65 item still stands: wire the
demo's deposit-cell creation (`crates/demo-ui/src/index.html` + `main.rs:511`, today an
always-success lock) to the sweep-or-refund deposit lock bound to the pool's type hash, update the
operator's checkpoint builder to add the deposit-lock code dep on the sweep input, and prove one
checkpoint on the type-id'd pool. The contract capability and now its cross-pool guarantee are in
place and tested; what remains is off-chain wiring + a live proved checkpoint.

## 2026-06-12, Phase 6b: sequencer reward + anti-griefing + sharding

The three pieces that make permissionless operation self-sustaining, efficient, and scalable.
None is a new trust primitive; the system was already trustless and safe.

**6b-1 sequencer reward (contract-only, no proof change).** The operator may pay itself out of
the proven `fee_withdrawal`. A non-anchor output whose data starts with `LIQUIDCELLS/v1/fee-reward`
is a reward cell: excluded from the withdrawals commitment, summed separately, and bounded by
`fee_withdrawal` (code 47). Since the STF already caps `fee_withdrawal` at accrued fee revenue, a
reward can never come from a user balance, and the miner fee works out to `fee_withdrawal -
sum_reward`. Key realization: no STF or proof change is needed, the sequencer just splits an
already-proven draw, so the vkey is unchanged and the fixtures verify as-is. The marking is
self-enforcing (mismarking breaks the withdrawals-commitment match). `anchor.rs` 11 tests.
**Live on Pudge** (code-cell upgrade tx `0x4ea3eb48…`).

**6b-2 anti-griefing (off-chain leader election).** Racing sequencers waste proofs, an efficiency
problem, not a trust one (the system is safe via force-exit and rational via the reward). For each
root, every sequencer computes the same priority order (`keccak(id | root)`, lowest leads) over the
gossiped active set, so only the leader proves, with ranked failover. The heavy on-chain
commit-reveal alternative is deliberately deferred as over-engineering for a non-trust concern.
`crates/sequencer/src/coordinator.rs`, 4 tests.

**6b-3 anchor sharding.** No contract change: the type script already supports any number of
independent pools. `ShardedSequencer` runs K of them in parallel (distinct deterministic pool ids)
for K-fold throughput. No cross-shard atomicity needed, a user holds a leaf in whatever shards they
transact in, and the client aggregates. 2 tests.

**Open.** A live demo of a sequencer earning a fee (the reward cell must clear the 61-CKB floor, so
it needs a fee-accrued checkpoint), the L1/Fiber egress leg, a TS/WASM SDK wrapper, and the
external audit that gates mainnet.

---

## 2026-06-12, Phase 6a: permissionless sequencing (lock continuity)

Make the operator non-privileged. The type script already guaranteed correctness regardless of who
submits, so the only thing making sequencing permissioned was the anchor's lock. The fix is **anchor
lock continuity**: the contract requires `output anchor lock == input anchor lock`, before mode
dispatch, so the genesis lock is a permanent, unforgeable policy for who may sequence. A permissive
(always-success) genesis lock then yields a permanently **permissionless**, capture-proof pool (no
checkpoint can re-lock the anchor to seize sequencing); a specific lock pins it forever. One small
check, backward-compatible (the original deployer-locked pool is unaffected). `anchor.rs` gains a
capture-rejection test.

**Live on Pudge.** Upgraded the code cell (also carrying force-refund) and created a second pool
with an always-success lock: a deployer-funded cp1 set it up, then **cp2 advanced the root with no
signature at all** (`0x3145a2d8…`), gated only by the BN254 proof and lock continuity. This is the
on-chain demonstration that sequencing is permissionless. The pool reuses the original pool's proofs
(same baked `pool_id`, so the same batch reaches the identical state).

---

## 2026-06-12, sequencer loop + successive checkpoints + client SDK

**Sequencer loop (`crates/sequencer`).** The off-chain half of the keystone: an in-memory state, a
mempool of signed intents, and `seal_batch()` that emits a `CheckpointJob` (the SP1 guest input,
both anchor-cell byte images, the DA blob, and the deposit/withdrawal cell specs) and advances the
in-memory root, so successive checkpoints chain. STF-only dependency (no SP1), so its loop logic
tests in milliseconds.

**Successive checkpoints, live.** A prove-and-submit driver (`crates/sp1-host/src/bin/sequence.rs`)
seeded the sequencer to the live seq-1 state (asserting the reproduced root matches the on-chain
root before proving) and landed two more checkpoints, advancing the deployed pool seq 1 to 2 to 3,
each consuming the prior anchor, each a BN254 proof verified on a live CKB block. Proving lesson:
prove one checkpoint per process, the SP1 native-gnark FFI does not reliably survive a second
Groth16 proof in the same process.

**Client SDK (`crates/client`).** Build and sign Transfer/Withdrawal/HTLC intents, track the account
nonce, and recover the account's `{balance, nonce}` plus an SMT inclusion proof from L1 DA alone,
then assemble the exact force-exit / force-refund witness bytes. All on the same `liquid-cells-stf`
the sequencer and guest run, so a client can never diverge from them. 6 tests prove the intents are
accepted by the canonical STF and the witnesses verify against the committed root.

---

## 2026-06-11, Phase 5b: on-chain force-refund (HTLC escape hatch, sender side)

Close the sender's exposure from Phase 5's documented liveness limitation. A third anchor mode
(witness length 8321): the sender of a pending in-pool HTLC unilaterally reclaims a timed-out escrow
against the committed root. The contract re-derives `htlc_id` from the supplied lock terms, proves
the `{amount, 0}` escrow leaf's SMT inclusion, nullifies it, drops `total` by `amount`, and forces
the payout to the sender's own secp lock. Gated by both `since >= timeout` (so a live receiver claim
is never robbed) and operator silence (so it is an escape hatch, not a routine race). No proof or STF
change, so the vkey is unchanged. `forcerefund.rs`, 9 tests.

**Honest scope.** This closes the sender side only. The symmetric receiver "force-claim" is not
expressible under a single anchor (it would need to fire inside the short HTLC timeout, but any
escape hatch must be silence-gated or it griefs live checkpoints), an architectural residual.
[docs/EGRESS.md](docs/EGRESS.md) was rewritten to state this precisely, correcting an earlier draft
that overclaimed force-refund "removes the limitation entirely."

---

## 2026-06-11, Phase 2b-6: deployed to Pudge, BN254 proof verified on a live CKB block

The anchor type script is live on Pudge, and a real SP1 Groth16 BN254 proof was verified inside a
live CKB block, as far as we are aware a first for CKB.

**The deploy lesson.** The first checkpoint was rejected: `ExceededMaximumCycles`. The 4-pairing
BN254 verifier cost ~3.81B cycles, over a CKB block's ~3.50B budget, and the local ckb-testtool
suite had hidden it by running at its own 5B limit. Fix: precompute the constant `e(alpha, beta)` so
the verifier does **3 pairings instead of 4** (~3.47B cycles, under the limit, with a regression
assertion guarding the margin). Baking that constant needed a vendored + patched `bn`
(`crates/ckb-contract/vendor/bn`, adding `Gt::to_bytes`/`from_bytes`, since the library exposed no
way to serialize a `Gt`). Also added a genesis branch (creating an anchor runs the type script on an
output with no input anchor, which the original code rejected). Every live hash is in
[DEPLOY.md](DEPLOY.md).

---

## 2026-06-11, Phase 5: in-pool HTLC for atomic-swap dust egress

**Why.** Force-exit produces a single L1 cell (~61-CKB floor), so dust can't self-exit. The
*normal* dust exit is a hash-locked atomic swap: the dust stays in-pool (moves to an LP) and
the LP pays the user on L1/Fiber, atomically via a shared preimage. This adds the **in-pool
leg**: a hash-time-locked escrow in the pool state. ([docs/EGRESS.md](docs/EGRESS.md))

**The trap, and the design.** A naive non-escrow "hash-locked transfer" is unsafe: a
malicious dust-holder could claim the L1 leg (revealing the preimage) and then keep / force-
exit the in-pool balance if the operator stalls, a double-spend. Trustless egress needs
**escrow**. The elegant representation: the escrow is an ordinary `{balance, nonce}` account
leaf placed at a key that commits to *every* lock term, 

```
htlc_id = keccak(DOMAIN ‖ pool_id ‖ sender_key ‖ receiver_key ‖ amount ‖ hashlock ‖ timeout ‖ lock_nonce)
```

so `claim`/`refund` can only resolve to the agreed parties (a wrong receiver → a different
key → no funds). Because the leaf keeps the existing shape, the **SMT, partial witness, DA
blob, and the on-chain contract are all unchanged**, HTLCs are pure pool state, ride inside
the normal checkpoint proof + DA, and conserve value (`total` never moves; the lock fee →
`fee_acc`). Escrow leaves the sender's spendable balance immediately ⇒ no double-spend.

**Landed**
- STF: `HtlcLock`/`HtlcClaim`/`HtlcRefund` ops on `Batch`; `htlc_id` + `htlc_lock_msg` +
  domains; `apply_ops` lock (signed debit → escrow), claim (preimage before timeout → pays
  the fixed receiver), refund (after timeout → sender); `touched_keys` now takes `pool_id`
  (HTLC ids are pool-bound); codec for the 3 op lists; `StfError::{HtlcExists, HtlcMissing,
  BadPreimage, HtlcExpired, HtlcNotExpired}`.
- `tests/htlc.rs` (7): swap completion (lock→claim), refund-after-timeout, wrong preimage,
  claim-after-timeout, refund-before-timeout, receiver binding, escrow-removes-spendable
  (no double-spend). **31 STF native tests.**
- Guest ELF changed (new ops) → **vkey re-derived `0x00213af5…c1e8`**; the 3 Groth16 fixtures
  regenerated (same content, new proof) and `VKEY_HASH` re-baked. Contract unchanged otherwise.
  **24/24 ckb-testtool** still green.

**Honest limitation.** An HTLC leaf can't be force-exited (its key isn't `keccak(pubkey)`),
so escrow pending when the operator dies is stuck until checkpoints resume (not lost). A
future **force-refund** (force-exit a *timed-out* HTLC by proving the lock terms) removes it;
account balances stay force-exitable regardless.

**Open (2b-6 / 6 / follow-ups).** L1 HTLC counterparty lock + Fiber leg; force-refund; Pudge
deploy + sequencer; permissionless sequencing (Phase 6). Still local-only, unaudited.

---

## 2026-06-11, Phase 3: force-exit / escape hatch (operator can't freeze funds)

**The last trust primitive.** Proofs stop theft, DA stops withholding, but if the
sequencer just *stops*, users still need out. Force-exit is a unilateral, on-chain
withdrawal of your leaf against the last committed root, no proof, no cooperation.
With this, all four trust pillars are in place. (Reused the checkpoint fixtures, **no SP1
re-proving**; force-exit has no Groth16 proof.)

**Mechanism (second anchor mode, selected by witness `input_type` length: 644 checkpoint /
8249 force-exit).** Witness = `pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings(256·32)`. The
script checks, with only keccak over the SMT path:
- **inclusion**: `smt_root(keccak(pubkey), leaf_hash(balance,nonce), siblings) == anchor_in.root`;
- **nullification**: recompute with the leaf emptied (balance→0, nonce kept) → `anchor_out.root`
  (prevents double-exit);
- **payout to the owner only**: an output paying exactly `balance` to the canonical
  `secp256k1_blake160` lock with `args = blake160(pubkey)`, since the key is
  `keccak(pubkey)`, funds can only reach the owner's own address. **No in-contract signature**
  (avoids k256 on CKB-VM); an attacker triggering an exit just sends the owner their money;
- **accounting**: `total` and anchor capacity each drop by `balance` (`seq`/`fee_acc`/`last_epoch` unchanged);
- **timeout**: input `since` (abs epoch) ≥ `last_epoch + 180`.

**Timeout clock.** Anchor data grew **72→80 B** (`last_epoch`). Each checkpoint sets
`last_epoch = current_epoch` and proves it isn't future-dated by requiring the input `since`
(abs epoch) ≥ `current_epoch`, so `last_epoch ≤` real chain time and the operator can't push
the deadline out. While it keeps checkpointing the window never opens; the moment it stops,
the clock freezes and after 180 epochs anyone can exit. A force-exit changes `root` without a
proof, so a returning operator must checkpoint on the post-exit root (the existing `prev_root`
pin enforces forced inclusion for free). ([docs/FORCE-EXIT.md](docs/FORCE-EXIT.md))

**Landed**
- Contract: two-mode `program_entry` dispatch; new `force_exit` (SMT verify + nullify +
  owner-secp payout + timeout); `checkpoint` gains the epoch/`since` binding. New deps:
  `blake2b-ref` (for `blake160`). Helpers `smt_root`/`leaf_hash`/`blake160`/`abs_epoch`/
  `has_exit_output` mirror the STF exactly. **No STF change → checkpoint fixtures reused, no
  re-proving.**
- Tests: `tests/forceexit.rs` builds the tree + inclusion proof natively with
  `liquid-cells-stf` (no SP1), valid exit + 6 negatives (before-timeout, wrong balance,
  wrong/missing payout lock, un-nullified root, bad total). Checkpoint tests updated for the
  80-B anchor + input `since`. **24/24 ckb-testtool** (8 anchor + 5 deposit + 7 force-exit +
  4 withdrawal); force-exit suite runs in 0.01 s (no pairing).

**Trust status.** All four pillars now implemented: validity proofs, DA, **escape hatch**,
(+ proven L1 fee). Theft, inflation, data-withholding, **and freezing** are eliminated.
Remaining: dust egress for sub-61-CKB balances (Phase 5; force-exit is the ≥61-CKB whale
hatch), a Pudge deployment, and, before any real value, an external audit. Still local-only.

**Open (Phase 5 / 2b-6)**
- Atomic-swap / Fiber egress (hash-locked transfer variant) so dust balances exit without a
  61-CKB cell. Pudge deploy + sequencer. Standalone DA reconstruction CLI.

---

## 2026-06-11, Phase 4: data availability (the diff cannot be withheld)

**Why now (trust ordering).** Validity proofs stop theft/inflation but not *data
withholding*: a proof says "the transition was correct," not "you can see the new state."
Without DA a hostile sequencer could publish valid roots whose leaf data only it knows, so
users couldn't build the inclusion proof a force-exit needs, funds *frozen*, not stolen.
DA closes that, and it's the prerequisite for Phase 3 force-exit. Reordered ahead of the
Pudge deploy on purpose.

**Mechanism.** Each checkpoint commits `da_commitment = keccak(da_blob)` in its public
values, computed **in-circuit** over the touched leaves' post-state
(`key ‖ balance ‖ nonce`, 56 B each, sorted by key). The checkpoint tx must carry that
exact blob in the anchor witness `output_type`; the anchor recomputes `keccak(blob)` and
binds it (code 59). keccak collision-resistance ⇒ the operator can't substitute/shrink/omit
the diff and still get an accepting checkpoint.

**Sufficiency (the actual trust property).** Replaying every checkpoint's blob from genesis
rebuilds the *exact* tree, so any user recovers their leaf + sibling path, the force-exit
proof, from L1 alone, no sequencer cooperation. Implemented as
`liquid_cells_stf::reconstruct` and proven in `crates/stf/tests/da.rs`: a 3-checkpoint
history is rebuilt from blobs only, root matches, and a membership proof verifies against
the on-chain root. ([docs/DA.md](docs/DA.md))

**Landed**
- STF: new `da` module (`encode_da_blob`/`parse_da_blob`/`reconstruct`), `da_commitment`
  on `PublicValues` (**PV 256→288 B**, appended), in-circuit computation in
  `transition_inner`, `State::da_blob`, codec decode. **24 STF native tests** (+2 DA).
- Contract: `PV_LEN 288`/`WITNESS_LEN 644`, `PV_DA_COMMIT` (256); reads the blob from
  witness `output_type`, binds `keccak == da_commitment` (cheap, before the pairing).
  New vkey `0x00add002…55ee9` (guest ELF changed again with the STF).
- Host: derives the published blob (clone+apply the measured batch), asserts
  `keccak == da_commitment`, writes `da_blob.bin`. Fixtures regenerated (PV 288; blob
  112/168/168 B for 2/3/3 touched leaves), Groth16-verified.
- Tests: anchor `tampered_da_blob_rejected` + `missing_da_blob_rejected` (both code 59);
  deposit/withdrawal builders now publish the blob in `output_type`. **17/17 ckb-testtool**
  (8 anchor + 5 deposit + 4 withdrawal).

**Trust status.** Theft/inflation/forged-roots (proofs), user-funds-can't-pay-L1-fee
(2b-5), and now **data withholding** are all eliminated. Remaining gap to "fully
trustless": **Phase 3 force-exit / escape hatch** (consumes the reconstructed proof), then
dust egress (Phase 5). Plus: still local-only (not on Pudge), unaudited.

**Open**
- Phase 3 force-exit (next): on-chain single-leaf SMT-inclusion spend vs the last committed
  root + operator-silence timeout (needs `current_epoch`↔tx `since` binding).
- Standalone DA reconstruction CLI (thin wrapper over `reconstruct`). Pudge deploy (2b-6).

---

## 2026-06-11, Phase 2b-5: proven L1 fee model (`fee_withdrawal`)

**Problem.** A CKB checkpoint tx must leave a positive miner fee (`Σin − Σout > 0`), but
the 2b-3 solvency rule `out_cap − in_cap == Σdep − Σwd` forced a **zero-fee** tx. The fix
has to keep "no operator theft" *provable*, not relax it.

**Decision.** Make fee extraction a first-class, in-circuit operation rather than letting
the contract silently slacken solvency. New proven field **`fee_withdrawal`**, CKB the
sequencer draws from its own accumulated fee revenue to fund the miner fee:
- STF caps `fee_withdrawal ≤ prev.fee_acc + fee_delta`, then sets
  `new_total = (prev_total + Σdep − Σwd) − fee_withdrawal` and
  `new_fee_acc = prev_fee_acc + fee_delta − fee_withdrawal`. Since `total = Σbalances +
  fee_acc` and the draw reduces both by the same amount, **`Σ balances` is invariant**, 
  an L1 fee can never come from a user deposit, and that bound is *proven*.
- The contract re-checks the cap + continuity (cheap), and the new solvency identity
  `out_cap − in_cap == Σdep − Σwd − fee_withdrawal` pins the miner fee to **exactly** the
  proven draw (only inputs are anchor+deposits, only outputs anchor+withdrawals ⇒
  `Σin − Σout == fee_withdrawal`). No over-skim possible.

**Landed**
- STF: `fee_withdrawal` on `Batch` + `PublicValues` (appended → **PV 240→256 B**),
  `StfError::InsufficientFees`, the draw in `transition_inner`, `fee_acc` bookkeeping in
  `apply`, codec enc/dec. Two new property tests (partial draw conserves + reduces
  `total`/`fee_acc`; over-draw rejected). **22 STF native tests green.**
- Contract: `PV_LEN 256` / `WITNESS_LEN 612`, `PV_FEE_WD` offset (240); fee-aware
  continuity (`fee_wd ≤ prev_fee + fee_delta`, `new_fee == prev_fee + fee_delta −
  fee_wd`), accounting and solvency.
- Host: measured batch draws `fee_withdrawal = 2` from `3·n` fee revenue (partial draw,
  `fee_acc` stays positive). All three fixtures regenerated (PV 256 B, Groth16-verified).
- Tests: new `anchor.rs` negative `ignored_fee_draw_in_capacity_rejected` (output keeps
  full capacity, ignoring the draw → solvency rejects). `deposit.rs`/`withdrawal.rs`
  absorb the fee automatically (capacities derive from `new_total`); only `new_fee`
  adjusted. **15/15 integration tests green** (6 anchor + 5 deposit + 4 withdrawal).

**Open (Phase 2b-6)**
- Deploy to Pudge: genesis anchor cell + the type script as a code cell; a minimal
  sequencer building real checkpoint txs. DA (`da_commitment`) remains a Phase-4 STF
  change.

---

## 2026-06-11, Phase 2b-4: withdrawal-path coverage (lock-hash coordination)

**Landed**
- `crates/ckb-contract-tests` `wd_target` bin + `withdraw_lock()` (a fixed,
  deterministic `Script`), the withdrawal target lock hash the proof must commit,
  shared by the helper and the test. (`Context::build_script` is **not** usable: it
  deploys with a type-id, so its script hash varies per `Context`, that bug surfaced
  first as a lock-hash mismatch.)
- Host `wd` mode: a checkpoint batch with a real **deposit + transfer + withdrawal**;
  `fixtures/wd/` regenerated (deposit `0xeab422a6…`/3e8, withdrawal target
  `0x1bf0d8bf…`/1e8), Groth16-verified.
- `tests/withdrawal.rs`, comprehensive deposit-input + withdrawal-output checkpoint:
  positive (full pairing) + adversarial (wrong withdrawal lock, wrong amount, missing
  output), plus an in-test assert that the built lock hash equals the proven target.
- **14/14 integration tests green** (5 anchor + 5 deposit + 4 withdrawal). The contract
  is unchanged, its withdrawal folding from 2b-3 is now exercised end-to-end.

**Open (Phase 2b-5)**
- L1 tx-fee handling; DA (`da_commitment`, Phase 4 STF change).
- Deploy to Pudge (genesis anchor cell + the type script as a code cell) and a minimal
  sequencer that builds real checkpoint txs.

---

## 2026-06-11, Phase 2b-3: deposit/withdrawal binding + value conservation

**Decision:** implicit cell format ([docs/CELL-FORMAT.md](docs/CELL-FORMAT.md)), a
deposit is any non-anchor **input** (`data[0..32]`=to_key, capacity=amount); a
withdrawal is any non-anchor **output** (lock_hash, capacity). No marker contract.

**Landed**
- `crates/ckb-contract` now recomputes the commitments from the real cells with keccak
  (`sha3`, same fold as `liquid_cells_stf::fold_commit`):
  `deposits_commitment` over non-anchor inputs, `withdrawals_commitment` over non-anchor
  outputs; both must equal the proof's. Plus conservation, both checked before the
  pairing: **accounting** `prev_total + Σdep − Σwd == new_total` and **solvency**
  `anchor_out.capacity − anchor_in.capacity == Σdep − Σwd`.
- Host `dw` mode + `fixtures/dw/`, a regenerated Groth16 proof of a checkpoint with a
  **real deposit** (to_key `0xeab422a6…`, amount 3e8), verified.
- `crates/ckb-contract-tests/tests/deposit.rs`, **5 deposit tests** (positive +
  tampered to_key / tampered amount / missing deposit cell / broken anchor capacity).
- **10/10 integration tests green** (the 5 transfer-only anchor tests still pass, the
  new checks are no-ops when there are no deposit/withdrawal cells).

**Open (Phase 2b-4)**
- Withdrawal-path *test* (contract logic is symmetric and already in place), needs the
  proof to commit the exact lock hash the test builds (lock-hash coordination).
- L1 tx-fee handling; DA (`da_commitment` → Phase 4 STF change). Deploy to Pudge +
  minimal sequencer building real checkpoint txs.

---

## 2026-06-11, Phase 2b-2: real type script + mock-tx integration tests

**Landed**
- `crates/ckb-contract` rewritten from baked fixtures into a real **type script**:
  reads `proof ‖ public_values` from the input group's witness, reads `prev`/`new`
  state from the **input/output anchor cell data**, and enforces full anchor
  continuity before the pairing:
  - anchor data layout `root(32) ‖ seq(8) ‖ total(16) ‖ fee_acc(16)`;
  - `pool_id`/`chain_id` baked; `new_seq == prev_seq + 1`;
  - input anchor `root/seq/total == prev_*`; output anchor `root/seq/total == new_*`;
  - `new.fee_acc == prev.fee_acc + fee_delta`.
  - **Cheap pins run first, the BN254 pairing last**, so a tampered tx is rejected
    without paying ~3.6B cycles.
- `crates/ckb-contract-tests` (ckb-testtool 0.13, mirrors the bridge's integration
  setup): builds a checkpoint tx from the Phase-2a fixtures and runs it in CKB-VM.
  **5/5 tests green in 2.8s**:
  - `valid_checkpoint_verifies`, full path incl. the real pairing → exit 0;
  - `tampered_output_root_rejected`, `wrong_new_seq_rejected`,
    `fee_acc_mismatch_rejected`, cell pins reject (fast);
  - `tampered_public_values_caught_by_proof`, bind passes, the Groth16 proof rejects.

**Next (Phase 2b-3)**
- Bind `deposits_commitment` / `withdrawals_commitment` to real deposit cells /
  withdrawal outputs (needs the deposit/withdrawal cell-format spec) + DA blob.
- Deploy to Pudge; wire a sequencer to build real checkpoint txs.

---

## 2026-06-11, Phase 2b-1: on-chain Groth16 verify of the transition

**Landed**
- `crates/ckb-contract`, the anchor type script (no_std, ckb-std 0.16,
  `riscv64imac-unknown-none-elf`, `substrate-bn-succinct-rs` + sha2, `__sync_*`
  atomics polyfill). Adapts the project's `g16-ckbvm` BN254 Groth16 verifier and adds
  the two soundness checks the Solidity reference makes (`exit_code == 0`,
  `vk_root == VK_ROOT`) that g16ckb omitted.
- Bakes our program vkey (`0x00fda595…ace165`), the SP1 v6 universal Groth16 VK
  (byte-identical to g16ckb's), `VK_ROOT`, and the pool identity / chain_id.
- Verifies the **real Phase-2a proof** + decodes the 240-byte public values and
  enforces the baked pins (program vkey via the proof, `pool_id`, `chain_id`,
  `new_seq == prev_seq + 1`). **ckb-debugger → `Run result: 0`.**

**Cycle cost (the key feasibility finding)**
- `~3.6B` cycles (`3,812,401,777`), essentially identical to the production g16ckb
  verifier (`3,810,585,066`), so it's the *inherent* cost of a BN254 Groth16 verify
  in CKB-VM, not a regression. Deployable on Pudge (bridge precedent); mainnet
  cycle-limit feasibility / a BN254-precompile path is the optimization to track.
- Crucially **constant per checkpoint** (fixed 356-byte proof) regardless of batch
  size, so larger batches amortize the on-chain cost. Reinforces wanting big batches.

**Next (Phase 2b-2)**
- Convert from baked fixtures to a real type script: read `proof`/`public_values`
  from the witness; pin `prev_*`/`new_*` to input/output anchor cell data; recompute
  `deposits_commitment`/`withdrawals_commitment` from the real deposit cells /
  withdrawal outputs; bind DA. Test with a mock tx (ckb-debugger/ckb-testtool) incl.
  adversarial cases, then deploy to Pudge.

---

## 2026-06-11, Phase 2a: Groth16 wrap + on-chain verifier spec

**Landed**
- Host `groth16` mode (sp1-sdk feature **`native-gnark`**): generates + verifies a
  Groth16-wrapped proof and dumps on-chain fixtures.
- **First real Groth16 proof of a Liquid Cells transition, verified.** n=1:
  `proof = 356 bytes`, `public_values = 240 bytes`, program
  `vkey = 0x00fda595…ace165`, circuit `v6.1.0`, `new_root = 0x3bd5018a…` (matches
  core/execute/native). Wall ~431s (mostly one-time R1CS/pk load; gnark prove ~49s).
- `fixtures/`, `groth16_proof.bin`, `public_values.bin`, `vkey.txt`,
  `circuit_version.txt`, plus `fixtures/reference/` (SP1's `Groth16Verifier.sol`,
  `SP1VerifierGroth16.sol`, `groth16_vk.bin`).
- `scripts/groth16.sh`, reproducible proof generation.
- `docs/ONCHAIN-VERIFY.md`, the full recipe the CKB type script must implement
  (proof layout, selector `0x4388a21c`, `VK_ROOT`, sha256 digest + 5 Groth16 public
  inputs, and the public-value→chain-fact pins).

**Gotchas (recorded in `scripts/groth16.sh`)**
- gnark needs `ulimit -s unlimited` or the solver dies silently (exit 253, no output).
- without `native-gnark`, SP1 shells out to Docker, which isn't wired into this distro.
- the public-values digest is **sha256** (not keccak); the commitments stay keccak.

**Next (Phase 2b)**
- `crates/ckb-contract`: anchor type script, BN254 Groth16 verify (reuse g16ckb) +
  decode public values + pin to cell data / deposit cells / withdrawal outputs / DA.
  Test against `fixtures/`. Deploy to Pudge.

---

## 2026-06-11, Phase 1b: SP1 guest, cycle measurement, precompiles

**Landed**
- `crates/sp1-guest`, SP1 zkVM program (standalone workspace). Decodes the input
  bundle, runs the identical `prove_transition`, commits `PublicValues`. Builds with
  `cargo prove build` (SP1 6.2, `riscv64im-succinct-zkvm-elf`).
- `crates/sp1-host`, driver (standalone workspace, `sp1-sdk` 6.2 blocking API).
  Builds a funded pool + batch, executes the guest, and **asserts the guest's
  committed `PublicValues` equal the native ones**, guest⇄native equivalence holds.
- Precompile patches in the guest: `k256` → `patch-k256-13.4-sp1-6.2.0`, `sha3` →
  `patch-sha3-0.10.8-sp1-6.2.0`. Pinned the stf crate's `sha3` to `=0.10.8` so the
  keccak-precompile patch actually engages (the 0.10.9 lock had silently skipped it).
- `MAX_LEAVES_PER_BATCH = 1024`, enforced in-circuit in `prove_transition`
  (`BatchTooLarge`), plus a test.
- **First real proof**: host `prove` mode generates and verifies an SP1 **core
  STARK** proof. n=1 (1.17M cycles) proved + verified in **~89s** on CPU, with the
  proven `PublicValues` matching native (`new_root=0x3bd5018a…`).

**Cycle measurements (execute mode, n payers → 1 recipient, n+1 touched leaves)**

| transfers | touched leaves | unpatched | k256 only | k256 + keccak |
|---|---|---|---|---|
| 1 | 2 | 8.59M | 7.32M | **1.17M** |
| 2 | 3 | 13.58M | 11.04M | **1.81M** |
| 4 | 5 | 23.35M | 18.26M | **3.04M** |
| 8 | 9 | 43.21M | 33.04M | **5.55M** |
| 16 | 17 | 82.60M | 62.26M | **10.53M** |

Marginal per transfer: **~0.62M cycles** with both precompiles (down from ~4.9M
unpatched, ~8×). Keccak (the SMT path hashing) was the dominant cost, not the
signature; the keccak precompile is what unlocked it. `MAX_LEAVES_PER_BATCH = 1024`
≈ 0.64B cycles worst case.

**Next (Phase 1c / Phase 2)**
- Generate + verify a real SP1 core proof locally (pipeline is execute-validated).
- Benchmark proving wall-time to turn `MAX_LEAVES_PER_BATCH` from a cycle estimate
  into a latency-based number.
- Begin the CKB anchor type script (Groth16 verify + public-input binding).

---

## 2026-06-11, Phase 1a: partial-witness refactor + guest codec

**Landed**
- `smt.rs`, multi-leaf witness: `Smt::frontier_siblings` (producer, from the full
  tree) and `root_from_witness` (consumer, no full tree). Frontier siblings are
  emitted/consumed in identical DFS order; shared path prefixes are not duplicated.
- `transition.rs`, **rewritten around `prove_transition(prev, witness, batch)`**, the
  exact function the SP1 guest will prove. It binds the witness to `prev_root`,
  applies ops over a working map of only the touched leaves, and recomputes
  `new_root` from the same siblings. Proving cost now scales with batch size, not
  pool size. The full-tree `apply`/`build_witness` remain the sequencer path and
  debug-assert that the full-tree root equals the witness-derived `new_root`.
- `codec.rs`, manual canonical encode/decode of the guest input bundle
  `(prev, witness, batch)` and of `PublicValues` (no serde; explicit big-endian).
- New errors `MalformedWitness`, `PrevRootMismatch`.
- `tests/witness.rs`, 8 tests: witness/full-tree parity, isolated-key 256-deep
  proof, tampered-leaf / missing-leaf / extra-sibling / wrong-prev-root rejection,
  codec round-trips. **All green (19 tests total across the crate).**

**Decisions**
- Guest I/O is hand-encoded bytes, not serde, sidesteps `[u8; 33]`/`[u8; 64]` serde
  friction and is cheaper to decode in-circuit.
- The global Σ-balances conservation check is sequencer-only; the guest relies on
  transitive conservation (bound `prev_root` + checked arithmetic), so it never needs
  the full tree.

**Next (Phase 1b)**
- `crates/sp1-guest`: `entrypoint` decodes the bundle, calls `prove_transition`,
  commits `PublicValues.encode()`.
- Host driver: build a witness, `execute` for cycle counts across batch sizes, fix
  `MAX_LEAVES_PER_BATCH`, attempt a local core proof.

---

## 2026-06-11, Phase 0: state-transition function

**Landed**
- Cargo workspace + `liquid-cells-stf` crate (the keystone STF, sequencer and SP1
  guest will both run this exact code).
- `hash.rs`, keccak-256 primitives (chosen for the SP1 keccak precompile).
- `smt.rs`, depth-256 sparse Merkle tree over keccak keys, with root + membership /
  non-membership proofs and a `verify_proof` matching the future on-chain check.
- `types.rs`, canonical fixed-width big-endian layouts for `Leaf`, `Transfer`,
  `Withdrawal`, `Deposit`, `Batch`, `PoolState`, `PublicValues`; domain-separated
  signing digests.
- `sig.rs`, secp256k1 ECDSA (low-S normalized); native now, SP1-precompile-patched
  in the guest later.
- `transition.rs`, `apply(state, batch)` enforcing the two safety invariants:
  *no debit without a signature* and *value conservation*.
- `tests/properties.rs`, 11 property tests: happy path, signature-required,
  tamper-after-sign, replay/nonce, insufficient balance, self-transfer, expiry,
  withdrawal conservation, mixed-batch conservation, SMT membership/non-membership,
  commitment order-sensitivity. **All green.**

**Decisions**
- Proving system: **SP1 zkVM** (reuses the existing ChiralSP1 + Groth16-on-CKB stack;
  can verify native secp256k1 in-circuit).
- SMT hash: **keccak-256** (SP1 precompile) rather than CKB-native blake2b; the
  on-chain force-exit verifier will use the same keccak SMT.
- Account model: leaf stores only `{balance, nonce}`; identity is the SMT key
  `keccak(pubkey)`, proven on spend, so receiving needs no registration.

**Next (Phase 1)**
- Wrap the STF as an SP1 guest (`crates/sp1-guest`), refactor `State` to accept a
  partial witness (touched leaves + sibling hashes) instead of the full tree.
- Prove a batch locally in WSL, measure cycles, and fix `MAX_LEAVES_PER_BATCH`.
