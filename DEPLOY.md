# Pudge Deployment (CKB testnet)

Liquid Cells is deployed on the **Pudge** testnet. **Testnet only, unaudited, no real
value.** This records the live artifacts so a checkpoint or force-exit can be reproduced.

> The **deposit lock** (`crates/ckb-contract/src/deposit_lock.rs`) is **deployed and verified live**
> on Pudge (codeHash `0x0d610c61…3d3574`, rows below). A deposit cell was created under it, a
> third-party spend was **rejected on-chain** (`Inputs[0].Lock ValidationFailure`), and a refund to
> the depositor was accepted. The demo/SDK deposit flow is not yet routed through it (the running
> demo still creates always-success deposit cells); that wiring is the remaining step
> ([HARDENING.md](HARDENING.md)).

## Live artifacts

| Artifact | Value |
|---|---|
| Network | Pudge (CKB testnet) |
| Anchor type script `codeHash` | `0x83158549bb5b2241997d1e8bb5e24b432a78e74473c8601cea276411bca99f1e` (hashType `type`) |
| Code-cell dep outpoint (current) | `0x557d705a672e59e89b72132f05c8e5f3e2970fb994a23959d8a3d20e7fcbd5ec:0` (depType `code`) |
| First deploy tx | `0x25c87b3792b7e14a5efd580ea5569e954be0e824b252ea14864a1ebf152c6330` |
| Genesis-branch upgrade tx | `0xc5b8e43d19230a1f965d95f3e1f3144f3f2f823736c92ff60f6f4b78ea7c7862` (same type-id) |
| 3-pairing upgrade tx | `0x2e1919b45e871db6bc4267674c6810d3ac1f09b4a8abd4c9fada15af16233c7f` (same type-id) |
| force-refund + lock-continuity upgrade tx | `0xf393b36780fe243ad70f20e3b026797d122719fc249b8fd84ca50253d7e58313` (same type-id) |
| sequencer-reward upgrade tx | `0x4ea3eb48056ee401076c9b26668f903f46b9ec872c1462e222c31a2ead4808fc` (same type-id) |
| ark-bn254 verifier upgrade tx | `0x68f9730a2cd9bfccb5b34e733807c28646c6b74a84980827c7ffcc6df1452767` (same type-id; verify 3.47B → ~80M cycles, binary 293KB → 112KB) |
| **type-id pool-identity upgrade tx** | `0x557d705a672e59e89b72132f05c8e5f3e2970fb994a23959d8a3d20e7fcbd5ec` (same type-id, **current**; backward-compat: empty args = legacy baked POOL_ID, 32-byte args = type-id'd pool) |
| Genesis anchor outpoint | `0xdb895bbafc29e2df3cf26cce3aac21f0132aa5f32a3edce3aac8cc60ba9ce00a:0` |
| Genesis anchor type hash | `0xf4c1baf2fda7e9a07b762387934ce6b2d275bd4e533ae558c7233907f2f6b7a1` |
| First checkpoint tx (seq 0→1) | `0xca6bfc76cbfae1b1dfedfbcab02fe84c1ab9019cb711defce65587091c373d51` |
| Anchor after checkpoint 1 | `0xca6bfc76cbfae1b1dfedfbcab02fe84c1ab9019cb711defce65587091c373d51:0` (root `0xf3283454…`, seq 1) |
| Checkpoint 2 tx (seq 1→2) | `0x599085cefc048d76d966d78cf8baa27c0242b6bc999133bcc15070af5d2236a3` |
| Anchor after checkpoint 2 | `0x599085cefc048d76d966d78cf8baa27c0242b6bc999133bcc15070af5d2236a3:0` (root `0x25045790…`, seq 2) |
| Checkpoint 3 tx (seq 2→3) | `0x80d4612489c59cb630d8dd8c32d5edc3d2ac2009ab8068eee9ae5b879052bec1` |
| Anchor after checkpoint 3 (current) | `0x80d4612489c59cb630d8dd8c32d5edc3d2ac2009ab8068eee9ae5b879052bec1:0` (root `0x60200160…`, seq 3) |
| Baked program vkey | `0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8` |
| Genesis (empty SMT) root | `0xa7ff9e28ffd3def443d324547688c2c4eb98edf7da757d6bfa22bff55b9ce24a` |
| **Deposit-lock `codeHash`** | `0x0d610c619c396b93282a1c7bbe6a89d5e5b882801baedba1ac73c6b2af3d3574` (type-id; sweep-or-refund) |
| Deposit-lock code-cell dep | `0xcb4b5a24994522084fe3c4078e02ff6550ed7b0b95d953d39d9736dcfb0babfc:0` (depType `code`) |
| Deposit-lock deploy tx | `0xcb4b5a24994522084fe3c4078e02ff6550ed7b0b95d953d39d9736dcfb0babfc` |
| Deposit-lock live test, deposit cell | `0xf05bfea8220386d25c62bacfff351f37979eea62189d612c80c89788c6bcb65e:0` (200 CKB, bound to pool type hash `0xf4c1baf2…`) |
| Deposit-lock live test, third-party spend | **rejected on-chain** (`Inputs[0].Lock ValidationFailure`) |
| Deposit-lock live test, refund to depositor | `0xcb512bc295c21576700893b6afd72822110fbce2b9648748e5aefa0febfbbd0d` (**accepted**) |
| **Type-id'd pool genesis tx** | `0x805e6252b4acf34b95f36e1b19fa3b73a06387cafb5faa39423d5899bd11a309` (anchor `:0`, empty state) |
| Type-id'd pool, `pool_id` (type-id) | `0x06865b65f867970c6d89f5e82ed530362f00e5051ea7265556646e7835b63295` (= blake2b of the genesis tx's first input) |
| Type-id'd pool, anchor type-script hash | `0xf7dfded8046462d788e34c252a2f0ba025e4f2e57fbb9454072b15e07762a55f` (**unique to this pool**, vs the legacy pool's `0xf4c1baf2…`) |
| Type-id'd genesis enforcement | **verified live**: the genesis tx committed, so the on-chain `anchor_type_id() == args` check passed (the args = blake2b(first input)) |

## What's verified on-chain

- **The anchor type script deploys and executes on Pudge CKB-VM.** Creating the genesis
  anchor ran the contract's **genesis branch** (an output anchor with no input anchor) on the
  live chain; it validated the canonical empty state and accepted.
- ✅ **First checkpoint, the SP1 Groth16 BN254 proof is VERIFIED on live Pudge CKB-VM.**
  checkpoint tx `0xca6bfc76cbfae1b1dfedfbcab02fe84c1ab9019cb711defce65587091c373d51`; new anchor
  (state 1) `0xca6bfc76…:0`, root `0xf3283454…`, seq 1, total 9,999,900,000, miner fee 100,000
  (the proven `fee_withdrawal`). This is the real on-chain validity-proof verification of a
  pooled-rollup state transition on CKB.
- ✅ **Successive checkpoints, the sequencer loop runs on-chain (seq 1 → 2 → 3).** Driven by
  `crates/sequencer` (seeded to the live seq-1 state, see `crates/sp1-host/src/bin/sequence.rs`),
  two more checkpoints landed, **each consuming the anchor the previous one created** and each
  carrying its own SP1 Groth16 BN254 proof verified on a live CKB block:
  - cp2 (seq 1→2): tx `0x599085ce…`, anchor `0x599085ce…:0`, root `0x25045790…`.
  - cp3 (seq 2→3): tx `0x80d46124…`, anchor `0x80d46124…:0`, root `0x60200160…`.
  Both are transfer-only batches, so each tx is just anchor-in → anchor-out with the miner fee
  (100,000) paid from the proven `fee_withdrawal`, the cleanest possible checkpoint shape. This
  is the loop **composing on the real chain**, not a one-shot. (Proving note: prove **one
  checkpoint per process**, the SP1 native-gnark FFI does not reliably survive a second Groth16
  proof in the same process; `lc-sequence … groth16 cp2` then `… groth16 cp3`.)

### How the cycle limit was solved

The first attempt was **rejected**, `Inputs[0].Type → ExceededMaximumCycles: expect cycles <=
3498303961`. The 4-pairing BN254 verifier cost **~3.81B cycles** vs a CKB block's **~3.50B**
budget (consensus). The local `ckb-testtool` suite passed only because it set its own 5B limit, 
the real chain enforces the lower consensus limit the tests never did. (No prior on-chain CKB
precedent: g16ckb does the same 4-pairing and was only ever run under ckb-debugger.)

**Fix (done):** precompute the constant `e(alpha, beta)` and verify **3 pairings instead of 4**
(`miller_loop_batch` of 3 → `final_exponentiation` → `lhs == ALPHA_BETA`), **~3.47B cycles**,
under the limit (a thin ~24M / ~0.7% margin, guarded by a regression assertion in
`valid_checkpoint_verifies`). Baking the `ALPHA_BETA` constant required **vendoring + patching**
substrate-bn (`crates/ckb-contract/vendor/bn`: added `Gt::to_bytes`/`from_bytes`, since the lib
exposed no way to (de)serialize a `Gt`). The constant lives in `fixtures/reference/alpha_beta.bin`
(generated by the `alphabeta` test; regenerate on any VK change). The code cell was upgraded in
place via type-id (same `codeHash`).

## Genesis & checkpoint shape

- Genesis anchor data (80 B) = `emptyRoot ‖ seq0 ‖ total0 ‖ feeAcc0 ‖ lastEpoch0`. The genesis
  branch accepts only this canonical empty state.
- Anchor lock sets the sequencing policy. The original pool uses the deployer's
  `secp256k1_blake160` lock (a single permissioned sequencer). The permissionless pool below uses
  an always-success lock, so anyone with a valid proof can advance the root. Lock continuity (see
  below) makes that choice permanent either way.
- First checkpoint = deposit 100 CKB to K, K transfers a dust amount to L with a fee, and the
  sequencer draws that fee as `fee_withdrawal` to pay the L1 miner fee (a deposit-only batch
  has no fee revenue, and CKB requires a positive fee). `current_epoch = 0`, so the anchor
  input's `since` is absolute epoch 0.

## Force-refund + lock continuity + sequencer reward, now live (Phases 5b and 6)

The current code cell (upgrade tx `0x4ea3eb48056e…`, same type-id `0x83158549…`) carries three
additions over the 3-pairing binary:

- **`force_refund`** (Phase 5b): a third anchor mode, a timed-out HTLC escrow's sender
  unilaterally reclaims it (see [docs/EGRESS.md](docs/EGRESS.md)). 9 ckb-testtool cases.
- **anchor lock continuity** (Phase 6a): the type script requires `output anchor lock == input
  anchor lock`, so the genesis lock is a permanent, unforgeable policy for who may sequence. A
  permissive (always-success) genesis lock then yields a permanently **permissionless**,
  capture-proof pool. Backward-compatible: the original deployer-locked pool keeps working.
- **sequencer reward** (Phase 6b): a non-anchor output whose data starts with
  `LIQUIDCELLS/v1/fee-reward` is a reward cell paid out of the proven `fee_withdrawal` (bounded by
  it, so never from a user balance), excluded from the withdrawals commitment. This is what makes
  permissionless sequencing profitable, hence self-sustaining. The live demo of a sequencer
  earning a fee is pending only because a reward cell must clear the 61-CKB floor, which needs a
  fee-accrued checkpoint to draw from; the mechanism is proven by ckb-testtool (anchor.rs 11).

None of these touch the STF or the guest, so the baked **vkey is unchanged** and every prior
anchor stays valid.

## Permissionless pool (Phase 6 foundational slice)

A second pool was created with an **always-success anchor lock**, so the anchor type script
(proof + lock continuity) is the only guard and anyone can advance the root. No privileged signer.

| Artifact | Value |
|---|---|
| Permissionless genesis anchor | `0xcc10c0934f5ca218703d016fc5738d57a2d9372f949d457c511f7f454469c38c:0` (always-success lock) |
| Always-success lock dep | `0x9fcec326fbc25dce302fa4d05727cb2ea43435f9d58ced246adc933fad9a7c59:0`, codeHash `0xd8c2346649752dc03e8e747ae6152fe13675be36b3c77e459d6f841988c2d06e` (hashType `type`) |
| cp1 (seq 0 to 1, deployer setup) | `0x09f23f400a42baef18c25f00f62d844695395d661c4b70d3e0f550326239cf06` |
| cp2 (seq 1 to 2, **UNSIGNED**) | `0x3145a2d86ca21c26f32bf14ac2ad86ecb7644c3bf0f21a8cfbff6638c3692767` |

- ✅ **cp2 advanced the root with no signature.** Its only input is the always-success anchor and
  the miner fee is the proven `fee_withdrawal`, so the transaction is unsigned. The BN254 proof and
  lock continuity alone gated it, verified on a live CKB block. This is the on-chain demonstration
  that the operator is not privileged: sequencing is permissionless.
- The pool reuses the original pool's genesis and cp2 proofs (same baked `pool_id`, so seeding it
  with the same batch reaches the identical state, and the existing fixtures verify unchanged).
- Honest scope: this is permissionless **safety** and **capture-proofness**. A sequencer reward
  (so sequencing is profitable) and anti-griefing (so racing sequencers do not waste proofs) are
  the next pieces, not in this slice.

## Notes

- Deployed with `offckb deploy --type-id` (upgradable; the upgrade kept the same `codeHash` by
  consuming the old code cell and recreating it). The anchor type script takes empty args;
  `pool_id`/`chain_id`/vkey are baked.
- The code cell locks ~293K CKB (the BN254-verifier binary, now with force-refund + lock
  continuity; 1 data byte = 1 CKB), the unavoidable cost of a large zk-verifier on CKB's
  capacity model.
- Deployer: a fresh, dedicated testnet key (address `ckt1qzda0cr…wyjs05`).
