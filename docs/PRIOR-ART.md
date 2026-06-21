# Prior art, and what differs (honest comparison)

A candid positioning of Liquid Cells against the closest prior work, written to survive a
skeptical reviewer. **Short version: Liquid Cells is an implementation, not an invention.** Every
major ingredient has prior art, and the closest cousin (sec-bit's Clover) is a zkRollup on the
same CKB cell model. This document states exactly what overlaps, what differs, and where the
design can be optimized.

## The closest cousins

- **Clover Protocol** (sec-bit), a zkRollup *on Nervos CKB*, design + runnable demo.
  `github.com/sec-bit/clover-protocol`. The single most overlapping piece of prior art.
- **Intmax2** (Ethereum), a stateless, payment-focused zk-rollup with client-side balance
  proofs. eprint 2023/1082, `intmax.io`. The closest cousin on *model and use case*.
- Supporting prior art on CKB: **ckb-zkp** (sec-bit, on-chain Groth16/SNARK verifier toolkit,
  ~77M cycles for a BN254 Groth16 verify), **Godwoken** (CKB's L2; optimistic, with a zk-rollup
  *template* on its roadmap), **Fiber** (CKB's Lightning, live on mainnet, already serves
  micropayments/tipping), and an active **"Optimized SP1 Verifier for ckb-vm"** effort
  (`talk.nervos.org/t/.../10144`).

## Side by side

| Dimension | Liquid Cells (ours) | Clover (sec-bit, CKB) | Intmax2 (Ethereum) |
|---|---|---|---|
| Settlement L1 | Nervos CKB, cell model | Nervos CKB, cell model | Ethereum |
| State commitment | keccak SMT (depth 256), leaf `(balance,nonce)` | aSVC / KZG10 vector commitment | client-held state + Merkle inclusion |
| Who generates proofs | the **sequencer** (it *is* the zkVM guest) | the **operator** aggregates aSVC position proofs | the **client** (each user proves own balance) |
| Proof system | SP1 zkVM (RISC-V STARK) → **Groth16 BN254** wrap (356 B proof) | KZG10 aSVC position proofs (BN256/BLS12-381) | recursive client-side ZK |
| Trusted setup | yes (Groth16) | yes (KZG CRS) | minimised (client-side) |
| Data availability | **full touched-leaf diffs** posted on-chain, keccak-bound | ~13 bytes/tx in the witness field + new commitment | ~4-5 byte **nullifiers** on-chain; bulk pushed to client |
| On-chain cost / batch | **~80M CKB-VM cycles** (about 2.3% of the 3.5B limit; ark-bn254 4-pairing) | ~160-230M cycles per op | Ethereum gas (aggregated) |
| Privacy | none (diffs are public) | none | **yes** (client-side proofs) |
| Permissionless deposit/withdraw | deposit cell + checkpoint; **force-exit** after operator silence | **direct lock-script** commitment update, no operator, no proof | client-driven |
| Permissionless block production | yes (always-success lock + lock continuity) | multi-operator via type script | yes (stateless) |
| Status | **live on CKB Pudge testnet**, successive + one unsigned checkpoint; unaudited | runnable demo, not deployed; relied on (then-unfinished) ckb-zkp | live / launching on Ethereum |

## What actually differs (our honest delta)

1. **Versus Clover (same chain, same goal):** Clover hand-builds aSVC circuits; we run the
   payment state machine as **plain Rust inside a zkVM (SP1) and prove it verbatim**, so the
   off-chain sequencer and the proved program are byte-identical ("the sequencer is the guest").
   That is a *developer-ergonomics and logic-transparency* difference, not a capability one. With
   the ark-bn254 verifier (~80M cycles per checkpoint) the on-chain cost is now **roughly on par
   with Clover's aSVC verify** (~160-230M cycles per op), where the old 3-pairing build cost an
   order of magnitude more. We are **deployed and
   running on a public testnet**; Clover was a local demo. Clover's deposit/withdraw are arguably
   *better* than ours: a direct lock-script commitment update needs **no operator and no proof**,
   whereas we currently spend a full checkpoint (and a ~7-min proof) to credit a deposit.
2. **Versus Intmax2 (same model, different chain):** Intmax pushes proving and state to the
   **client** (stateless, private, ~5-byte nullifiers, highly scalable). We keep proving on the
   **sequencer** and post **full DA on-chain** (simpler trust story, public, heavier, no privacy).
   These are different points in the design space; Intmax is the more advanced/scalable one.
3. **The only defensible "firsts," all narrow and hedged:** possibly the first **zkVM-based
   (SP1) validity rollup running live on CKB** with on-chain DA + force-exit + permissionless
   sequencing wired into one loop. On-chain Groth16 on CKB itself is *not* a first (ckb-zkp), and
   SP1-on-CKB-VM verification is *already* being worked on by others (Plonk variant).

## Where it can be optimized (concrete, research-grounded)

Ordered by leverage:

1. **Swap the BN254 library, DONE and LIVE.** The verifier was ported to `ark-bn254` (the
   `crates/groth16` lib, imported by `crates/ckb-contract`), removing the 3-pairing `e(alpha,beta)`
   precompute hack (now a plain 4-pairing check), with the **same SP1 proofs verifying and all 40
   contract tests green** (good proof accepted, every tampered proof/root/accounting case still
   rejected). Speed-optimized, the port measured (not projected) **3,474,607,239 → 53,308,780
   cycles** at a ~420KB binary, but that binary was too big for the code cell, so the **deployed**
   build is optimized for *size* (`opt-level="z"` + LTO + strip), trading speed for capacity:
   **~112KB binary at ~80M cycles** (still a **~43x reduction**, ~2.3% of the block limit). This
   landed on Pudge via upgrade tx `0x68f9730a` (see DEPLOY.md live-artifacts table). Details below
   record the investigation that led here.

   The verify *was* **3,474,607,239 cycles** (`valid_checkpoint_verifies`, historical state), only
   **0.66% under** the 3.498B block limit, using the unoptimized vendored `substrate-bn`, which
   forced the 4→3-pairing hack to fit. That figure is now history; the live verifier measures
   **~80M cycles**.
   Two independent CKB-VM data points predicted a tuned BN254 verify **~45-55x lower**: ckb-zkp does
   a Groth16 BN254 verify at **~77.5M cycles** (pure Rust), and the "Optimized SP1 Verifier for
   ckb-vm" cut Plonk **6,000M → 63M** using `ckb-alt-bn128`. The ark-bn254 port confirmed this: the
   live verify is **~80M cycles**, comfortably under the limit, and the 3-pairing precompute hack is
   gone.
   *Investigation note (one-time historical measurement, on this CKB-VM).* Early in the
   investigation, a throwaway microbench (run under `ckb-debugger`) timed **one** BN254 pairing each
   way:
   - `substrate-bn` (our former verifier's lib, now the difftest reference): **1,119,056,067
     cycles** (~1067M/pairing).
   - `ark-bn254` (modern pure Rust, `no_std`): **16,853,046 cycles** (~16.1M/pairing).

   That was a **~66x speedup per pairing, in pure Rust**, no C++/FFI, and motivated the port. (The
   C++ `ckb-alt-bn128` = mohanson `bn128` was a dead end here: it needs a ckb-patched `intx` not
   publicly cloneable, the bare-metal `riscv64-unknown-elf-g++` lacks the full C++20 STL upstream
   `intx` pulls, and FFI into `no_std` Rust is its own task, **and it turned out to be
   unnecessary**.) The old 3.47B verify was 3 `substrate-bn` pairings (~1B each) + final-exp + MSM;
   the `ark-bn254` port brought the full verifier to **~80M cycles**, i.e. from **99.3% of the block
   limit to ~2.3%**, and the 3-pairing precompute hack was dropped. `substrate-bn` now survives only
   as the reference impl in `crates/verifier-difftest`.
2. **Reconsider the proof system for the on-chain leg.** Groth16-via-zkVM is ergonomic but the
   most expensive on-chain option. Cheaper paths: the optimized **Plonk** SP1 verifier (~63M
   cycles, already exists for ckb-vm), or a **Clover-style aSVC / hand-rolled circuit** for the
   narrow payment STF, which avoids zkVM overhead entirely (~200M cycles/op). The zkVM buys
   developer velocity; if on-chain cost dominates, a purpose-built circuit wins.
3. **Cheaper deposits/withdrawals (borrow from Clover).** Today every deposit rides a full proven
   checkpoint. A deposit/withdraw could instead be a **lock-script path that checks an SMT
   inclusion proof directly** (no zkVM proof), the way Clover updates its commitment in the lock
   script. That removes the ~7-min proof from the most common user action.
4. **Shrink DA for scale.** Full leaf diffs are heavy. Move toward Clover's compact per-tx
   witness encoding, or Intmax-style nullifiers + client-held state, to raise txs-per-checkpoint.
   Trade-off: more client responsibility (and a step toward the stateless model).
5. **Proving throughput.** ~7-min CPU Groth16 → GPU or the SP1 prover network; recursive
   aggregation across checkpoints. Deposit/withdraw **batching is already implemented** (many
   users share one proof), which is the cheapest large win and is live.
6. **Operational durability.** A sequencer **replay log** (persist sealed batches, replay on
   restart) so the pool survives a process restart without redeploy. Not cryptography, just
   robustness, and currently the demo's main fragility.
7. **Optional, product-dependent.** Drop the trusted setup by going transparent (STARK-only or
   FRI on-chain, higher cost); add **privacy** (encrypted DA + amount-hiding) if the use case
   needs it, which is exactly Intmax's territory.

## Bottom line for a reviewer

Liquid Cells is a **complete, working, CKB-cell-native instance** of a well-established idea
(payment zk-rollup), sitting between Clover (CKB aSVC rollup, demo) and the stateless model
(Intmax). Its contribution is **engineering and integration on a live chain**, plus a couple of
clean CKB-idiomatic choices (anchor-cell-as-pool, lock-continuity permissionlessness). It is
**not** a novel protocol; its on-chain verifier is now the `ark-bn254` build (~80M cycles, ~2.3%
of the block limit, live via upgrade tx `0x68f9730a`), so the once-dominant verifier cost is no
longer the bottleneck (item 1 above records that work). Treat it as a strong reference
implementation and product base, not as a research result.

*Sources: github.com/sec-bit/clover-protocol, github.com/sec-bit/ckb-zkp, eprint.iacr.org/2023/1082,
github.com/godwokenrises/godwoken, github.com/nervosnetwork/fiber,
talk.nervos.org/t/optimized-sp1-verifier-for-ckb-vm/10144,
talk.nervos.org/t/performance-improvement-of-ckb-hard-fork-take-ckb-zkp-as-an-example/6265.*
