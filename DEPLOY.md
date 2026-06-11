# Pudge Deployment (CKB testnet)

Liquid Cells is deployed on the **Pudge** testnet. **Testnet only, unaudited — no real
value.** This records the live artifacts so a checkpoint or force-exit can be reproduced.

## Live artifacts

| Artifact | Value |
|---|---|
| Network | Pudge (CKB testnet) |
| Anchor type script `codeHash` | `0x83158549bb5b2241997d1e8bb5e24b432a78e74473c8601cea276411bca99f1e` (hashType `type`) |
| Code-cell dep outpoint | `0xc5b8e43d19230a1f965d95f3e1f3144f3f2f823736c92ff60f6f4b78ea7c7862:0` (depType `code`) |
| First deploy tx | `0x25c87b3792b7e14a5efd580ea5569e954be0e824b252ea14864a1ebf152c6330` |
| Genesis-branch upgrade tx | `0xc5b8e43d19230a1f965d95f3e1f3144f3f2f823736c92ff60f6f4b78ea7c7862` (same type-id) |
| Genesis anchor outpoint | `0xdb895bbafc29e2df3cf26cce3aac21f0132aa5f32a3edce3aac8cc60ba9ce00a:0` |
| Genesis anchor type hash | `0xf4c1baf2fda7e9a07b762387934ce6b2d275bd4e533ae558c7233907f2f6b7a1` |
| Baked program vkey | `0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8` |
| Genesis (empty SMT) root | `0xa7ff9e28ffd3def443d324547688c2c4eb98edf7da757d6bfa22bff55b9ce24a` |

## What's verified on-chain

- **The anchor type script deploys and executes on Pudge CKB-VM.** Creating the genesis
  anchor ran the contract's **genesis branch** (an output anchor with no input anchor) on the
  live chain; it validated the canonical empty state and accepted.
- **First checkpoint (BN254 proof verified on-chain):** ❌ **BLOCKED by the CKB cycle limit.**
  Submitting the checkpoint was rejected:
  `Inputs[0].Type → ExceededMaximumCycles: expect cycles <= 3498303961`.
  The pure-software BN254 pairing costs **~3.81B cycles**, but a CKB block's cycle budget is
  **~3.50B** (consensus). So the verification cannot be included in a block as-is. The local
  `ckb-testtool` suite passed only because it sets its own 5B limit — the real chain enforces
  the lower consensus limit the tests never did. (This also means there is **no prior on-chain
  CKB precedent**: g16ckb does the same 4-pairing and was only ever run under ckb-debugger.)

### Fix path (not yet done)

Standard Groth16 optimization: **precompute the constant `e(alpha, beta)` pairing** and check 3
pairings instead of 4 (`miller_loop_batch` of 3 pairs → `final_exponentiation` → compare to the
baked `alpha_beta` Gt), removing one Miller loop (~20% → ~3.0–3.2B, likely under the limit). The
`bn` crate exposes `miller_loop_batch` + `final_exponentiation`, so it's feasible; it requires
serializing the `Fq12` constant, restructuring `verify_alg`, re-testing with a **tight** cycle
bound, and a redeploy. If that's not enough, a CKB-VM BN254 precompile would be the next lever.

## Genesis & checkpoint shape

- Genesis anchor data (80 B) = `emptyRoot ‖ seq0 ‖ total0 ‖ feeAcc0 ‖ lastEpoch0`. The genesis
  branch accepts only this canonical empty state.
- Anchor lock = the deployer's `secp256k1_blake160` lock (the sequencer signs each
  checkpoint). A *permissionless* force-exit on-chain would instead use a permissive lock —
  the type script is the real guard. (Refinement; the checkpoint demo doesn't need it.)
- First checkpoint = deposit 100 CKB to K, K transfers a dust amount to L with a fee, and the
  sequencer draws that fee as `fee_withdrawal` to pay the L1 miner fee (a deposit-only batch
  has no fee revenue, and CKB requires a positive fee). `current_epoch = 0`, so the anchor
  input's `since` is absolute epoch 0.

## Notes

- Deployed with `offckb deploy --type-id` (upgradable; the upgrade kept the same `codeHash` by
  consuming the old code cell and recreating it). The anchor type script takes empty args;
  `pool_id`/`chain_id`/vkey are baked.
- The code cell locks ~278K CKB (the 271 KB BN254-verifier binary; 1 data byte = 1 CKB) — the
  unavoidable cost of a large zk-verifier on CKB's capacity model.
- Deployer: a fresh, dedicated testnet key (address `ckt1qzda0cr…wyjs05`).
