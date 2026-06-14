# Sequencing — the operator model is a knob, not a fixed "single operator"

A common first read of any rollup is "you still trust the sequencer." For Liquid Cells that is
**false for safety** and **configurable for liveness**. This doc lays out why, the spectrum of
operator models the *same* contract supports, what is already built and live, and the honest gaps.

## Why "who sequences" is not a trust boundary

The on-chain anchor type script re-derives and checks **every** fact a checkpoint asserts: the
Groth16 validity proof of the state transition, value conservation, the data-availability commitment
over the published diff, and sequence/fee/epoch continuity. A sequencer therefore **cannot steal,
mint, double-spend, or withhold data — no matter who it is.** That collapses "who may sequence" from
a trust question down to a pure **liveness / efficiency** question.

So the protocol puts the entire policy in **one knob: the anchor cell's lock**, and the contract
enforces **lock continuity** — `output anchor lock == input anchor lock` (`crates/ckb-contract/src/main.rs:284`).
Whatever lock the pool is created (genesis) with becomes a **permanent, capture-proof** policy for who
may advance the root. No checkpoint — honest or malicious — can ever re-lock the anchor to seize
sequencing, because changing the lock is itself rejected.

## The spectrum (same protocol, one knob)

| Model | Anchor lock | What it gives | Liveness depends on |
|---|---|---|---|
| **Single operator** (current default) | a specific key/lock | Safety holds; simplest to run | that one operator (force-exit is the backstop) |
| **Federated / multisig** | M-of-N multisig | No single point of control; M operators must co-sign a checkpoint | any M of N |
| **Permissionless** | always-success / proof-only | **Anyone** who can produce a valid proof advances the root; capture-proof | the open set of sequencers |

Safety (no-steal / no-mint / DA / force-exit) is **identical** across all three rows — only liveness
and decentralization change.

## Live evidence (Pudge testnet)

Permissionless is not theoretical:

- **A permissionless pool advanced UNSIGNED.** A second pool was deployed with an always-success
  anchor lock; checkpoint 2 (seq 1 → 2) advanced the root with **no operator signature at all**,
  gated only by the validity proof + lock continuity. (See DEPLOY.md for the tx hashes.)
- **Capture-proofness is tested** — a checkpoint that tries to change the anchor lock is rejected.

## What is already built so permissionless *works*, not just is *safe*

- **Lock continuity + capture-rejection** — `crates/ckb-contract/src/main.rs` (enforced + tested).
- **Permissionless deposits** — the deposit lock (`crates/ckb-contract/src/deposit_lock.rs`) lets any
  sequencer include a user's deposit without the depositor trusting that sequencer.
- **Self-sustaining economics** — the **sequencer reward** mechanism is *deployed live* on Pudge (a
  non-anchor reward cell paid out of the *proven* `fee_withdrawal`, bounded by fee revenue so it can
  never come from a user balance; `main.rs:394`). It makes producing a checkpoint profitable, so
  permissionless sequencing is economically rational, not charity. *Honest status:* the contract path
  is live, but a *demonstration* of a sequencer actually pocketing a fee is still pending only because
  a reward cell must clear the ~61-CKB occupied-capacity floor (a funding detail, not a design gap —
  see DEPLOY.md).
- **Anti-griefing leader schedule** — `crates/sequencer/src/coordinator.rs`: every sequencer computes
  the *same* deterministic priority order over the active set (`keccak(id ‖ root)`, lowest leads), so
  in the common case only the leader proves and submits; if it stalls, the next-ranked takes over.
  Leadership rotates per-root, fairly and unpredictably. Racing is only a *wasted proof*, never a loss
  — so this cooperative, off-chain mechanism is sufficient. 4 tests.
- **Sharding** — `ShardedSequencer` partitions the keyspace into independent anchors for K-fold
  throughput and K-fold mass-exit relief; each shard carries its own operator-model knob.

## Honest gaps (operational infrastructure, not protocol)

What remains to lean *fully* on permissionless in production is infra, not new protocol design:

1. **Shared mempool / intent propagation.** Competing sequencers each hold their own mempool; gossip
   so they see the same pending intents is **off-chain infrastructure that is not built here**
   (`coordinator.rs` notes this explicitly). Without it, permissionless sequencers can still each seal
   what they individually receive, but there is no shared ordering of un-propagated intents.
2. **On-chain commit-reveal leader election.** Deliberately **deferred** as over-engineering: the
   off-chain schedule is cooperative, and an adversarial racer can only waste its *own* proof (never
   steal), so an on-chain mechanism — which would need an anchor-layout change, backward-compat for
   the live pools, and a redeploy — is not justified to solve a purely-wasted-work problem.
3. **Prover fleet + per-shard HA.** Real operational work (GPU/prover-network, failover), not design.
4. **Censorship.** In *every* model, a user's ultimate backstop is **force-exit** — unilateral exit
   against the last committed root, no sequencer cooperation required.

## This is the operator's choice, not a protocol mandate

Everything above is a **deploy-time configuration menu** for whoever runs a pool — **not** a to-do in
this codebase and **not** something the protocol imposes. The protocol is neutral: it enforces
*whatever lock you put on the anchor* (via lock continuity) and proves *whatever STF the vkey is bound
to*. Picking a sequencing model and an upgrade policy is the operator's call at pool creation (and at
upgrade time), and **none of these choices touch the proven STF or the vkey** — they are just which
lock scripts you select.

| If you are running… | Anchor lock (your choice) | Upgrade policy (your choice) | Repo work needed |
|---|---|---|---|
| a hobby / demo pool | single secp lock | plain key (or none) | none — simplest |
| a pool holding real value | **multisig** (federation) | the [timelock upgrade lock](UPGRADE-TIMELOCK.md), ideally with a multisig gov lock | none new — multisig is a stock CKB lock; the timelock lock is already built, you just deploy the code cell with it |
| a public / decentralized pool | **always-success** (permissionless) | timelock + multisig | none on the contract; operational infra (mempool gossip, prover fleet) is the remaining work |

Notes:
- **Federated multisig** is *pure configuration* — CKB ships multisig lock scripts; "going federated"
  is putting one in the anchor's lock slot at genesis. Zero protocol work.
- **The timelock upgrade lock** is built and tested in-repo; *adopting* it is opt-in (deploy the
  anchor code cell with that lock, keeping the same type-id). An operator who doesn't want it omits it.
- **Permissionless** is a first-class mode of the same contract (lock continuity + reward + deposit
  lock + leader schedule are done); leaning fully on it is operational infra, not new protocol.

The takeaway: **"single operator" is just the simplest default a deployer can pick, not a property of
the design.** The same contract already supports federated and permissionless sequencing as
first-class, capture-proof modes — one of which has advanced a real checkpoint, unsigned, on testnet.
