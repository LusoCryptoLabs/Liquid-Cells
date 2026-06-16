# Operating a Liquid Cells pool (operator runbook)

> **Status:** runbook for running a pool's **operator** (sequencer + prover): auto
> restart, crash/host loss recovery, failover, monitoring. Markers: **[built]** = a mechanism the
> protocol/code provides; **[ops]** = standard infra you configure; **[roadmap]** = automation not yet
> in tree. Liquid Cells is testnet-only and unaudited.

## 0. Read first: liveness is not safety

Because any user can **force-exit** from L1 after the operator-silence window (~30 days / 180 epochs;
see [FORCE-EXIT.md](FORCE-EXIT.md), [REPRODUCE-EXIT.md](REPRODUCE-EXIT.md)), **funds are never trapped
by operator failure.** Everything below is about keeping the pool *progressing* and recovering fast,
not about protecting funds. An operator outage degrades UX, never custody.

## 1. What an operator runs

| Component | Role | State |
|---|---|---|
| **Sequencer service** (`crates/sequencer-service`, binary `liquid-cells-sequencer-service`) | HTTP front: accepts signed intents, runs the mempool, seals batches, serves queries + DA; can hand back a soft-confirmation **receipt** (`crates/sequencer/src/receipt.rs`, liveness not finality) | durable (journal) **[built]**, also rebuildable from L1 |
| **Prove + submit driver** (`crates/sp1-host`) | picks up a sealed batch's `sp1_input` from `/seal`, generates the ~7-min Groth16 proof, submits the checkpoint tx + DA blob, advances the anchor | stateless |
| **CKB full node + indexer** | chain I/O, recovery source, user lookups | chain copy |

The off-chain half (mempool, seal, query, DA) and the heavy proving/submission half are deliberately
**separate processes**, so you supervise, scale, and fail them over independently.

## 2. Recovery model (built, you write no custom recovery code)

Two layers, both already in the code:

- **Crash recovery (local state intact):** the durable sequencer replays its write-ahead journal
  through the identical STF to a **byte-identical** state (root, seq, total, fee_acc, leaves, pending
  mempool), tolerating a torn trailing frame. A process that died mid-write comes back consistent.
  **[built]**
- **Total-loss recovery (journal gone, or a fresh host):** `Sequencer::resume` rebuilds the entire
  state from **on-chain DA**, the same reconstruction `lc-exit` does for users. **The chain is the
  source of truth, so the operator's state survives the loss of any or all local storage.** **[built]**

**Consequence:** "host dies" never means "pool state lost." A new operator anywhere re-derives the
exact state from L1.

## 3. Process auto-restart (crashes and reboots)

**Safe here by design:** a restarted operator reconciles to the on-chain anchor; it cannot fork or get
ahead of canonical state (advancing the root needs a valid proof consuming the *current* anchor, so a
stale attempt simply fails to land), and validity proofs cap the blast radius at "a rejected tx or a
brief stall", never theft, inflation, or invalid state. Re-broadcasting an already-landed checkpoint
fails because its input anchor is spent. **[built guarantees]**

Put a supervisor in front of the sequencer service and the prove/submit driver, **with backoff and
alerting** so a *deterministic* crash (bug, OOM, poison input) slows down and pages you instead of hot
looping. (Resilient seal already prevents a bad user intent from crashing a batch.) **[ops]**

```ini
# /etc/systemd/system/lc-sequencer.service
[Unit]
Description=Liquid Cells sequencer service
After=network-online.target

[Service]
ExecStart=/opt/liquid-cells/liquid-cells-sequencer-service   # plus your flags/env
Restart=on-failure
RestartSec=5
# crash-loop guard: more than 5 failures in 5 min stops it and alerts (no hot loop)
StartLimitIntervalSec=300
StartLimitBurst=5
OnFailure=lc-alert@%n.service        # your pager/webhook unit
StateDirectory=liquid-cells          # journal on durable storage, see section 6

[Install]
WantedBy=multi-user.target
```

Run the **prove/submit driver** under its own unit the same way. Kubernetes equivalent: a `Deployment`
with `restartPolicy: Always` (built-in exponential backoff), a **liveness probe** on checkpoint
progress, and an alert on `CrashLoopBackOff`.

**Limit:** same-host restart does **not** survive the host dying, that is section 4.

## 4. Host death and failover

State is on L1 (section 2), so host loss costs *progress for minutes*, not data. Pick an automation
level:

- **Warm standby in another zone (recommended).** It tails L1 continuously; on losing the primary it
  promotes itself: `Sequencer::resume` from L1, then continue sealing. Sequencing is **permissionless
  and keyless** (a checkpoint advanced the root unsigned, [SEQUENCING.md](SEQUENCING.md)), so there is
  **no key handoff**: the standby needs only a CKB node and a prover. Failover is detect + resume
  (seconds to minutes). **[mechanism built; promotion automation is ops]**
- **Cloud auto-healing / k8s.** A managed instance group or Deployment reschedules the operator onto a
  healthy node; on start it `resume`s. Self-healing across hosts, orchestration is yours. **[ops]**
- **Manual.** Spin up the operator on a fresh box, run the resume path, continue. Fully recovers from
  L1, just slower. **[ops]**

Automated detection-and-promotion (true HA) is **[roadmap]** (ROADMAP Tier D: per-shard sequencer
HA/failover); today it is a standby plus health-checked promotion.

### Promotion procedure (host death)
1. Confirm the primary is actually gone (no checkpoint advance + host unreachable), avoid flapping.
2. On the standby: ensure a synced CKB node and a working prover.
3. Run the **resume** path (`Sequencer::resume`) to rebuild state from the live anchor's checkpoint
   history; assert the reconstructed root equals the on-chain anchor root before sealing.
4. Resume sealing, proving, and submitting checkpoints.
5. Page on completion; investigate the dead primary out of band.

## 5. Split-brain is non-destructive

If two operators ever run the same pool at once, they **cannot** both advance it: a checkpoint consumes
the single on-chain **anchor cell**, so only one tx lands and the other fails (anchor already spent).
The chain serializes it: **no corruption, no double-advance**, only wasted proving on the loser. So you
can fail over aggressively. Still use simple leader election (a lease/lock) to avoid burning duplicate
proofs. **[built guarantee]**

## 6. Storage and the prover

- **Do not depend on ephemeral local disk.** Treat **L1 as the durable source** (resume rebuilds
  everything); optionally replicate the journal to network/redundant storage to make crash recovery
  faster than a full L1 replay. **[ops]**
- **The prove/submit driver is stateless**, so a dead prover host needs only a replacement (backup box
  or an SP1 prover-network account). Keep a spare so a single prover failure cannot stall checkpoints.
  Ranked prover failover is **[roadmap]**. **[ops]**

## 7. Monitoring and alert thresholds

| Signal | Alert when | Why |
|---|---|---|
| **Checkpoint cadence** | no anchor advance for more than N min (e.g. 2 to 3x your seal interval) | the primary liveness signal; drives failover |
| **Proof time / failures** | proof exceeds budget or errors | prover degradation before it stalls |
| **Crash-loop** | supervisor hit `StartLimitBurst` / `CrashLoopBackOff` | a deterministic failure needs a human |
| **Host / RAM / disk** | RSS near limit, disk low, host unhealthy | proving is RAM-heavy; pre-empt OOM (benchmark with the `bench` bin) |
| **CKB node sync** | node behind or unreachable | recovery and submission depend on it |

## 8. Honest gaps / roadmap

- **Automated HA (cross-host failover):** standby plus runbook today; auto-promotion is roadmap.
- **Federation / multi-operator:** the operator model is a knob (single / federated / permissionless,
  [SEQUENCING.md](SEQUENCING.md)); multi-operator is not operationalized.
- **Prover-network ranked failover and GPU proving (~1 min):** roadmap; a manual backup prover works
  now.
- **~30-day force-exit window:** a baked constant (180 epochs); the ultimate user backstop, not an
  operator tool. A normal failover should bring the pool back in minutes, far inside it.

## 9. References

- [SEQUENCING.md](SEQUENCING.md), operator model and permissionless takeover
- [FORCE-EXIT.md](FORCE-EXIT.md), [REPRODUCE-EXIT.md](REPRODUCE-EXIT.md), the user safety floor
- [DA.md](DA.md), why state is rebuildable from L1
- [NON-CUSTODY.md](NON-CUSTODY.md), what operator failure can and cannot do
- [../ROADMAP.md](../ROADMAP.md), HA / federation / prover-network items
- [../HARDENING.md](../HARDENING.md), durable-sequencer detail
- `crates/sequencer-service/README.md`, the HTTP endpoints
