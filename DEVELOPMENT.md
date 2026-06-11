# Development Log

A running record of what was built each working session, newest first. Every entry
should be committed and pushed to `main`. Keep it factual: what landed, what was
decided, what is next.

> Convention: commit straight to `main`, no AI/co-author attribution on commits.

---

## 2026-06-11 — Phase 2b-1: on-chain Groth16 verify of the transition

**Landed**
- `crates/ckb-contract` — the anchor type script (no_std, ckb-std 0.16,
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
  verifier (`3,810,585,066`) — so it's the *inherent* cost of a BN254 Groth16 verify
  in CKB-VM, not a regression. Deployable on Pudge (bridge precedent); mainnet
  cycle-limit feasibility / a BN254-precompile path is the optimization to track.
- Crucially **constant per checkpoint** (fixed 356-byte proof) regardless of batch
  size — so larger batches amortize the on-chain cost. Reinforces wanting big batches.

**Next (Phase 2b-2)**
- Convert from baked fixtures to a real type script: read `proof`/`public_values`
  from the witness; pin `prev_*`/`new_*` to input/output anchor cell data; recompute
  `deposits_commitment`/`withdrawals_commitment` from the real deposit cells /
  withdrawal outputs; bind DA. Test with a mock tx (ckb-debugger/ckb-testtool) incl.
  adversarial cases, then deploy to Pudge.

---

## 2026-06-11 — Phase 2a: Groth16 wrap + on-chain verifier spec

**Landed**
- Host `groth16` mode (sp1-sdk feature **`native-gnark`**): generates + verifies a
  Groth16-wrapped proof and dumps on-chain fixtures.
- **First real Groth16 proof of a Liquid Cells transition, verified.** n=1:
  `proof = 356 bytes`, `public_values = 240 bytes`, program
  `vkey = 0x00fda595…ace165`, circuit `v6.1.0`, `new_root = 0x3bd5018a…` (matches
  core/execute/native). Wall ~431s (mostly one-time R1CS/pk load; gnark prove ~49s).
- `fixtures/` — `groth16_proof.bin`, `public_values.bin`, `vkey.txt`,
  `circuit_version.txt`, plus `fixtures/reference/` (SP1's `Groth16Verifier.sol`,
  `SP1VerifierGroth16.sol`, `groth16_vk.bin`).
- `scripts/groth16.sh` — reproducible proof generation.
- `docs/ONCHAIN-VERIFY.md` — the full recipe the CKB type script must implement
  (proof layout, selector `0x4388a21c`, `VK_ROOT`, sha256 digest + 5 Groth16 public
  inputs, and the public-value→chain-fact pins).

**Gotchas (recorded in `scripts/groth16.sh`)**
- gnark needs `ulimit -s unlimited` or the solver dies silently (exit 253, no output).
- without `native-gnark`, SP1 shells out to Docker, which isn't wired into this distro.
- the public-values digest is **sha256** (not keccak); the commitments stay keccak.

**Next (Phase 2b)**
- `crates/ckb-contract`: anchor type script — BN254 Groth16 verify (reuse g16ckb) +
  decode public values + pin to cell data / deposit cells / withdrawal outputs / DA.
  Test against `fixtures/`. Deploy to Pudge.

---

## 2026-06-11 — Phase 1b: SP1 guest, cycle measurement, precompiles

**Landed**
- `crates/sp1-guest` — SP1 zkVM program (standalone workspace). Decodes the input
  bundle, runs the identical `prove_transition`, commits `PublicValues`. Builds with
  `cargo prove build` (SP1 6.2, `riscv64im-succinct-zkvm-elf`).
- `crates/sp1-host` — driver (standalone workspace, `sp1-sdk` 6.2 blocking API).
  Builds a funded pool + batch, executes the guest, and **asserts the guest's
  committed `PublicValues` equal the native ones** — guest⇄native equivalence holds.
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
unpatched — ~8×). Keccak (the SMT path hashing) was the dominant cost, not the
signature; the keccak precompile is what unlocked it. `MAX_LEAVES_PER_BATCH = 1024`
≈ 0.64B cycles worst case.

**Next (Phase 1c / Phase 2)**
- Generate + verify a real SP1 core proof locally (pipeline is execute-validated).
- Benchmark proving wall-time to turn `MAX_LEAVES_PER_BATCH` from a cycle estimate
  into a latency-based number.
- Begin the CKB anchor type script (Groth16 verify + public-input binding).

---

## 2026-06-11 — Phase 1a: partial-witness refactor + guest codec

**Landed**
- `smt.rs` — multi-leaf witness: `Smt::frontier_siblings` (producer, from the full
  tree) and `root_from_witness` (consumer, no full tree). Frontier siblings are
  emitted/consumed in identical DFS order; shared path prefixes are not duplicated.
- `transition.rs` — **rewritten around `prove_transition(prev, witness, batch)`**, the
  exact function the SP1 guest will prove. It binds the witness to `prev_root`,
  applies ops over a working map of only the touched leaves, and recomputes
  `new_root` from the same siblings. Proving cost now scales with batch size, not
  pool size. The full-tree `apply`/`build_witness` remain the sequencer path and
  debug-assert that the full-tree root equals the witness-derived `new_root`.
- `codec.rs` — manual canonical encode/decode of the guest input bundle
  `(prev, witness, batch)` and of `PublicValues` (no serde; explicit big-endian).
- New errors `MalformedWitness`, `PrevRootMismatch`.
- `tests/witness.rs` — 8 tests: witness/full-tree parity, isolated-key 256-deep
  proof, tampered-leaf / missing-leaf / extra-sibling / wrong-prev-root rejection,
  codec round-trips. **All green (19 tests total across the crate).**

**Decisions**
- Guest I/O is hand-encoded bytes, not serde — sidesteps `[u8; 33]`/`[u8; 64]` serde
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

## 2026-06-11 — Phase 0: state-transition function

**Landed**
- Cargo workspace + `liquid-cells-stf` crate (the keystone STF — sequencer and SP1
  guest will both run this exact code).
- `hash.rs` — keccak-256 primitives (chosen for the SP1 keccak precompile).
- `smt.rs` — depth-256 sparse Merkle tree over keccak keys, with root + membership /
  non-membership proofs and a `verify_proof` matching the future on-chain check.
- `types.rs` — canonical fixed-width big-endian layouts for `Leaf`, `Transfer`,
  `Withdrawal`, `Deposit`, `Batch`, `PoolState`, `PublicValues`; domain-separated
  signing digests.
- `sig.rs` — secp256k1 ECDSA (low-S normalized); native now, SP1-precompile-patched
  in the guest later.
- `transition.rs` — `apply(state, batch)` enforcing the two safety invariants:
  *no debit without a signature* and *value conservation*.
- `tests/properties.rs` — 11 property tests: happy path, signature-required,
  tamper-after-sign, replay/nonce, insufficient balance, self-transfer, expiry,
  withdrawal conservation, mixed-batch conservation, SMT membership/non-membership,
  commitment order-sensitivity. **All green.**

**Decisions**
- Proving system: **SP1 zkVM** (reuses the existing ChiralSP1 + Groth16-on-CKB stack;
  can verify native secp256k1 in-circuit).
- SMT hash: **keccak-256** (SP1 precompile) rather than CKB-native blake2b; the
  on-chain force-exit verifier will use the same keccak SMT.
- Account model: leaf stores only `{balance, nonce}`; identity is the SMT key
  `keccak(pubkey)`, proven on spend — so receiving needs no registration.

**Next (Phase 1)**
- Wrap the STF as an SP1 guest (`crates/sp1-guest`), refactor `State` to accept a
  partial witness (touched leaves + sibling hashes) instead of the full tree.
- Prove a batch locally in WSL, measure cycles, and fix `MAX_LEAVES_PER_BATCH`.
