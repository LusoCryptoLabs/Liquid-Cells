# Governance multisig for the upgrade-key lockdown (C-1)

How to construct the `governance_lock_hash` that the timelocked upgrade lock
([UPGRADE-TIMELOCK.md](UPGRADE-TIMELOCK.md), `crates/ckb-contract/src/upgrade_lock.rs`) checks, using a
**solo-operator 2-of-3 hardware multisig**. This is the concrete spec for committee finding D
([REBAKE-COMMITTEE.md](REBAKE-COMMITTEE.md)); it is a **mainnet-value prerequisite**, NOT needed for a
testnet re-bake dry-run (a single key or the always-success lock is fine to rehearse the mechanics).

## What this buys, and what it does not (read first)

A solo 2-of-3 is **custody hardening, not user-facing trust-minimization.** Because one operator holds
all three keys, the 2-of-3 quorum is always reachable by that operator, so it raises the bar for an
outside thief but adds no check on the operator themselves.

- **Protects against:** compromise of a single device (a thief needs 2 of 3), loss of a single device
  (lose 1, still upgrade with 2), and (via the timelock, orthogonally) any sudden/secret code swap.
- **Does NOT protect against:** a malicious or coerced operator (they can still drive a delayed,
  announced upgrade); a thief who gets 2 of 3 devices; users who do not act during the exit window;
  loss of 2-of-3 keys (upgrades bricked forever, though force-exit still works); a poisoned-but-
  correctly-announced build (the lock checks the data hash, not that the bytes are safe).
- **Honest trust statement:** users do not have to trust that the operator is honest, but they DO have
  to (a) watch the chain for an announcement and (b) force-exit within their window if they dislike
  what is coming. The lock guarantees no upgrade lands suddenly or secretly (it must be a 2-of-3
  announcement committing to specific bytes, aged strictly longer than the force-exit window), and the
  escape hatch is the ultimate backstop. For genuine user-facing trust-minimization, distribute the
  2-of-3 across **independent** parties; that is the only structural fix and is out of scope here.

## The lock construction (verified)

The governance lock is the **CKB system `secp256k1_blake160_multisig_all`** lock.

| Field | Value |
|---|---|
| `code_hash` | `0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8` (network-independent type hash; RFC0024) |
| `hash_type` | `type` (packs as the single byte `0x01`) |
| `args` | `blake160(multisig_script)` (20 bytes), the no-time-lock form |

**`multisig_script` preimage** (concatenated, no length prefix; 64 bytes for 2-of-3):

```
S(1) | R(1) | M(1) | N(1) | blake160(pk1)(20) | blake160(pk2)(20) | blake160(pk3)(20)
0x00 | 0x00 | 0x02 | 0x03 | ......20......... | ......20......... | ......20.........
```
- `S` = reserved/version, MUST be `0x00`
- `R` = require-first-N (number of the first pubkeys whose sig MUST be present); `0x00` for a plain 2-of-3
- `M` = threshold (signatures required) = `0x02`
- `N` = total pubkeys = `0x03`
- `blake160(pk)` = first 20 bytes of `blake2b-256` (with CKB's `ckb-default-hash` personalization) of the 33-byte compressed secp256k1 pubkey

**`governance_lock_hash`** = `blake2b-256` (ckb-default-hash personalization) of the molecule-packed
`Script { code_hash, hash_type=0x01, args }`. This is exactly what `load_cell_lock_hash` returns
on-chain, and exactly the 32 bytes `upgrade_lock.rs` reads from `args[0..32]` and compares to the
announcement input's lock hash. **It goes into the upgrade lock's args:**
`upgrade_lock.args = governance_lock_hash(32) | delay_epochs(8 BE)`, with `delay_epochs > 180`
(the lock rejects `<= 180` with code 89; pick e.g. 200 for margin).

**Cell dep** (needed in any tx that spends a cell locked by this multisig, i.e. the execute tx): the
system **multisig dep GROUP** (`dep_type = dep_group`, it expands to `secp256k1_data` +
`secp256k1_blake160_multisig_all`). The outpoint is **network-specific, pull it from `offckb` / the
genesis, do not hardcode blindly**:
- Pudge / Aggron testnet: `tx 0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37`, index `0x1`, dep_group
- Lina mainnet: `tx 0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c`, index `0x1`, dep_group

**Witness (signing) format:** the `lock` field of the `WitnessArgs` of the FIRST input in the multisig
group carries `multisig_script_preimage(64) | sig1(65) | sig2(65)` = 194 bytes for 2-of-3. Each
signature is a 65-byte recoverable secp256k1 sig (`r||s||recid`). Standard `sighash_all` flow: fill the
lock field with the preimage + `M` zeroed 65-byte placeholders, compute the blake2b sighash message
over the tx + grouped witnesses, each of the 2 signers signs that message, replace the placeholders.

## Custody model (solo 2-of-3)

Three keys, three independent failure domains, so no single break-in / fire / coercion yields two:
- **Key 1, hot signer:** a hardware wallet (e.g. Ledger) you use to co-sign.
- **Key 2, cold signer:** a key on an air-gapped machine in a different location.
- **Key 3, deep backup:** an offline steel/paper backup in a third location (e.g. a bank vault).

Any 2 sign to upgrade. Single-device theft or loss is survivable; the practical risk to manage is
losing TWO (which bricks upgrades, see below) and one person being the organizational single point.

## Key ceremony (one-time, before mainnet lockdown)

1. Generate the three secp256k1 keys, each on its own device, never co-located. Record the three
   33-byte compressed pubkeys.
2. **Fix a canonical pubkey ORDER** and record it: `S=0, R=0, M=2, N=3` then `blake160(pk1), blake160(pk2),
   blake160(pk3)` in that order. The `governance_lock_hash` and every future witness depend on this
   exact order, so write it down (the ordered pubkey hashes + S/R/M/N) so the lock can be reconstructed
   at signing time.
3. Compute `multisig_script` (64 bytes), then `args = blake160(multisig_script)`, then
   `governance_lock_hash = blake2b256(packed Script)`. Use `ckb-default-hash`-personalized blake2b
   throughout (a vanilla blake2b silently yields a wrong hash that never matches on-chain). `offckb` /
   `@ckb-lumos`/`ccc` compute all of this; verify the resulting lock against `load_cell_lock_hash` on a
   throwaway cell before trusting it.
4. **Rehearse the full flow on testnet first** (below) before locking anything on mainnet.

## Announce -> wait -> execute runbook

The multisig gates EXECUTION: an announcement cell that the execute path accepts must be locked by
`governance_lock_hash`, and spending it requires 2-of-3. (Anyone can create a cell locked by the gov
multisig, but they cannot SPEND it without quorum, so a forged announcement is a dead memo.)

1. **Announce.** Build the new anchor code cell, compute its data hash. Create an announcement cell
   locked by the gov multisig, with `data = that data hash` (32 bytes). Record its outpoint + block.
   (Creating it needs only funding, not the multisig; spending it later will need 2-of-3.)
2. **Wait** at least `delay_epochs` (> 180, ~30+ days). The lock measures this from the announcement
   cell's own block via relative-epoch `since` (top byte `0xA0`), so it cannot be backdated.
   The delay is REQUIRED to exceed the force-exit window, so every user's exit window outlasts any
   upgrade, malicious or remedial.
3. **Execute.** Build a tx: inputs = `[old code cell (upgrade_lock), announcement cell (gov multisig)]`,
   outputs = `[new code cell (same type-id)]`. Set the announcement input's `since` to a relative-epoch
   `>= delay_epochs`. Include the multisig dep group. 2-of-3 sign the announcement input (the multisig
   witness above). The upgrade lock then unlocks the old code cell because a matured, gov-locked,
   correctly-committed announcement is present.

## Recovery and failure modes

- **Critical bug found after lockdown (keys intact):** announce the fix, wait `delay_epochs`, execute.
  During the mandatory wait the bug is live, but because `delay_epochs > FORCE_EXIT_TIMEOUT_EPOCHS`,
  every user has a force-exit window strictly shorter than the time any code change takes to land:
  users force-exit against the last-committed root (reconstructable from L1 DA) while the fix matures.
  A fast patch is impossible by design; the exit always beats the upgrade for anyone who acts.
- **Lose 2-of-3 keys:** no recovery. The code cell can never be respent, so the contract is frozen on
  its current verifier forever (no future patches). Survivable for users (force-exit still works,
  it needs no governance), terminal for the protocol's evolvability. Mitigate with truly independent
  failure domains + periodic verify-and-rotate drills.
- **Thief obtains 2 of 3 devices:** cryptographically identical to the operator; they can drive a
  delayed upgrade. Mitigate with physical/operational separation and by MONITORING the chain for ANY
  announcement cell locked by `governance_lock_hash`, an unexpected one is the canary and starts
  everyone's force-exit clock. A long `delay_epochs` maximizes the reaction window.
- **Poisoned-but-announced build:** the lock checks the announced data hash, not that the bytes are
  benign. Use reproducible builds and publicly diff the announced data hash against source DURING the
  delay window (that window exists precisely to catch this).

## Caveats (must confirm at deploy)

- Pull the multisig **dep-group outpoint from `offckb` / the live genesis** for the target network; the
  values above are correct for Lina/Pudge but verify against the actual target.
- The `code_hash` (type hash) and `hash_type=type` are network-independent, but confirm the system
  multisig cell exists on the target network's genesis.
- Use **`ckb-default-hash`-personalized** blake2b for `blake160` and the script hash; a wrong
  personalization silently produces a wrong `governance_lock_hash`.
- Record and reuse the **canonical pubkey order**; the lock and every witness depend on it.
- This is the **plain 20-byte args** form (no embedded `since`); the timelock is enforced by
  `upgrade_lock.rs`, not the multisig args.
- **Validate the whole flow on testnet first.** Lockdown is the deliberately irreversible LAST step,
  applied only AFTER the re-bake is live and validated (see REBAKE-COMMITTEE.md order).
