# Development Log

A running record of what was built each working session, newest first. Every entry
should be committed and pushed to `main`. Keep it factual: what landed, what was
decided, what is next.

> Convention: commit straight to `main`, no AI/co-author attribution on commits.

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
