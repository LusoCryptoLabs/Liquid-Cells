# Timelocked upgrades — capping the upgrade-key blast radius

The single largest trust caveat (see [NON-CUSTODY.md](NON-CUSTODY.md), HARDENING) is that the anchor
type script is **upgradable in place** (type-id) by whoever controls the **code cell's lock**. A plain
key there can swap in a malicious verifier and drain every pool **instantly**, with no chance for
users to exit. The **timelocked upgrade lock** (`crates/ckb-contract/src/upgrade_lock.rs`,
`liquid-cells-upgrade-lock`) removes the "instant": an upgrade must be **announced** and then **wait a
fixed delay** before it can execute, giving every user a guaranteed, publicly-visible window to
force-exit first. It turns a silent rug into a slow, exit-able, on-chain event — *regardless of who
holds the governance key*, which is why it is user-protective even before a governance multisig.

## Mechanism (commit-reveal + consensus-enforced delay)

Lock `args` (40 bytes): `governance_lock_hash(32) ‖ delay_epochs(8 BE)`.

1. **Announce.** Governance creates an *announcement* cell — locked by `governance_lock_hash`, whose
   data is the **blake2b data hash of the new code cell** it intends to deploy. Public: anyone can see
   an upgrade to exactly that code is pending.
2. **Wait `delay` epochs.** Users who don't trust the upgrade force-exit during this window
   (`lc-exit`); their funds leave against the current, still-honest root.
3. **Execute.** A tx consumes the old code cell (this lock) **and** the announcement, and creates the
   new code cell. The lock requires the announcement input to be (a) governance-locked, (b) committing
   to the new code cell's data hash, and (c) spent with a **relative-epoch `since` ≥ `delay`**.

Why it's sound (tested in `crates/ckb-contract-tests/tests/upgrade_lock.rs`):
- **No backdating the delay** — *relative*-epoch `since` is measured by consensus from the
  announcement cell's own block, so the execute tx cannot be mined until `delay` epochs after the
  announcement was actually created (an *absolute*-since announcement is rejected, code 87).
- **Binds the exact upgrade** — the announcement commits to the new code cell's data hash; deploying
  any other bytes than were announced rejects (code 88), so the window can't be used to announce
  benign code and ship malicious code.
- **Governance-gated** — only a `governance_lock_hash`-locked announcement counts (a non-governance
  announcement rejects), so a random party can't drive an upgrade.

## Migration (operator step — a deploy, not done here)

Adopt it by redeploying the anchor **code cell** with `lock = liquid-cells-upgrade-lock` (args =
`governance_lock_hash ‖ delay`), keeping the same type-id (so every pool's `codeHash` is unchanged and
no pool migration is needed). For the strongest story, set `governance_lock_hash` to a **multisig**;
the timelock supplies the user-exit-window, the multisig removes single-key control. Pick `delay`
comfortably above the force-exit timeout so users always have time to exit within the window.

## Honest scope
- This is implemented + adversarially tested in-repo; **deploying it is a separate, operator-authorized
  migration** (it replaces the live code cell's lock).
- It does **not** by itself make the contract immutable or multi-party — it bounds *when* an upgrade
  can take effect. Full governance (multisig as the gov lock) and eventual immutability are the
  later, deliberately-last steps (HARDENING). What it buys now: **no instant malicious upgrade** — the
  thing that most endangers user funds while a single key still controls upgrades.
