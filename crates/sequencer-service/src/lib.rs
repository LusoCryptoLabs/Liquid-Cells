//! The Liquid Cells sequencer as a service: a [`Sequencer`] plus the published DA history, with
//! pure request handlers that a thin HTTP front (`src/bin/lc-sequencer-service.rs`) routes to.
//!
//! This is the missing link between "a client signs an intent" and "the intent lands in a
//! checkpoint": the WASM SDK serializes an intent with [`liquid_cells_client::wire`], POSTs it here,
//! the service parses it with the SAME `wire` definitions and submits it to the sequencer, and a
//! seal advances the committed root. The heavy Groth16 proving + on-chain submission of a sealed
//! [`liquid_cells_sequencer::CheckpointJob`] stays the separate driver it already is; the handlers
//! return the `sp1_input` so that driver can pick it up.
//!
//! The handlers are pure (`&mut self` / `&self` -> `Result<Value, String>`), so the whole
//! submit -> seal -> query -> reconstruct flow is unit-tested with no socket.

use liquid_cells_client::wire::{self, hexs, Intent};
use liquid_cells_sequencer::{FeePolicy, Sequencer};
use liquid_cells_stf::Hash;
use serde_json::{json, Value};

/// Cap on un-sealed (pending) intents (L-5). `/submit` rejects past this with an over-capacity signal
/// (the HTTP front maps it to 429), so an anonymous client cannot grow the mempool without bound
/// between seals and OOM the single-process service. Generous: a sealed batch is at most
/// `MAX_LEAVES_PER_BATCH` (1024) leaves, and a seal drains the mempool, so this is ~10 batches of slack.
pub const MAX_PENDING: usize = 10_000;

/// A running sequencer service: the sequencer, the pool identity (for `/info`), and every DA blob
/// it has published (so `/da` lets a client reconstruct and force-exit from L1 alone).
pub struct Service {
    seq: Sequencer,
    pool_id: Hash,
    chain_id: u64,
    da_history: Vec<Vec<u8>>,
}

impl Service {
    /// A fresh service over an empty pool.
    pub fn genesis(pool_id: Hash, chain_id: u64) -> Self {
        Self { seq: Sequencer::genesis(pool_id, chain_id), pool_id, chain_id, da_history: Vec::new() }
    }

    /// The accumulated DA blobs (oldest-first), the input to `liquid_cells_client::reconstruct_tree`.
    pub fn da_blobs(&self) -> &[Vec<u8>] {
        &self.da_history
    }

    /// `POST /submit`: parse a tagged intent JSON (the SDK's `wire` encoding) and add it to the
    /// mempool. Validation happens at seal (the STF's atomic apply), so this only rejects malformed
    /// JSON, never an economically-invalid-but-well-formed intent.
    ///
    /// A `Deposit` is REJECTED here: its only legitimate authority is the consumed on-chain deposit
    /// cell, so accepting one from an anonymous HTTP client would let anyone mint balance in the
    /// off-chain committed state (a phantom deposit that no honest checkpoint can ever seal, since
    /// the on-chain `deposits_commitment` is recomputed from real L1 cells, but it wedges the local
    /// state/DA). Deposits enter only via [`admin_deposit`](Self::admin_deposit), the operator's
    /// confirmed-L1 ingestion path.
    pub fn submit(&mut self, body: &str) -> Result<Value, String> {
        // L-5: bound the mempool so spam between seals cannot grow memory without limit.
        if self.seq.pending() >= MAX_PENDING {
            return Err(format!(
                "overloaded: mempool full ({} pending, cap {MAX_PENDING}); retry after a seal",
                self.seq.pending()
            ));
        }
        let policy = self.seq.fee_policy();
        let kind = match wire::intent_from_json(body)? {
            Intent::Deposit(_) => {
                return Err("deposits are not accepted over /submit; they are authorized by an on-chain deposit cell".to_string())
            }
            // M-3: reject underpaying fee-bearing intents at the operator boundary (admission), so a
            // zero-fee griefing flood never enters the mempool. Policy, not proof; the atomic seal
            // re-validates, and the matching provable floor is the staged `min_fee` (re-bake).
            Intent::Transfer(t) => {
                if !policy.admits(t.fee) {
                    return Err(format!("underpaid: fee {} is below the {} floor", t.fee, policy.min_fee_per_intent));
                }
                self.seq.submit_transfer(t);
                "transfer"
            }
            Intent::Withdrawal(w) => {
                self.seq.submit_withdrawal(w);
                "withdrawal"
            }
            Intent::HtlcLock(l) => {
                if !policy.admits(l.fee) {
                    return Err(format!("underpaid: fee {} is below the {} floor", l.fee, policy.min_fee_per_intent));
                }
                self.seq.submit_htlc_lock(l);
                "htlc_lock"
            }
            Intent::HtlcClaim(c) => {
                self.seq.submit_htlc_claim(c);
                "htlc_claim"
            }
            Intent::HtlcRefund(r) => {
                self.seq.submit_htlc_refund(r);
                "htlc_refund"
            }
        };
        Ok(json!({ "ok": true, "accepted": kind, "pending": self.seq.pending() }))
    }

    /// Install the operator's fee-admission floor (M-3): `/submit` then rejects any transfer / HTLC-lock
    /// paying below `min_fee`. `0` disables it (admits everything). The production binary defaults this
    /// to a non-zero anti-zero-fee floor; `Service::genesis` leaves it at `0` so unit tests are
    /// unaffected. See [`liquid_cells_sequencer::FeePolicy`].
    pub fn set_fee_floor(&mut self, min_fee: u128) {
        self.seq.set_fee_policy(FeePolicy::new(min_fee));
    }

    /// Operator-only deposit ingestion (NOT the public `/submit` path). In production this is called
    /// only after the on-chain deposit cell is confirmed to the configured depth; in a local/demo
    /// deployment it doubles as a faucet. The HTTP front exposes it only when started with an
    /// explicit opt-in flag, so it is never reachable by an anonymous client by default.
    pub fn admin_deposit(&mut self, body: &str) -> Result<Value, String> {
        match wire::intent_from_json(body)? {
            Intent::Deposit(d) => {
                self.seq.submit_deposit(d);
                Ok(json!({ "ok": true, "accepted": "deposit", "pending": self.seq.pending() }))
            }
            _ => Err("admin_deposit accepts only a deposit intent".to_string()),
        }
    }

    /// `POST /seal`: seal the mempool into one checkpoint at `current_epoch`, drawing `fee_withdrawal`
    /// from accumulated fee revenue. Advances the committed root, records the DA blob, and returns the
    /// new anchor + DA blob + the `sp1_input` for the proving driver. Atomic: on an invalid intent the
    /// whole seal errors and the mempool is left intact (the bad intent can be dropped and retried).
    pub fn seal(&mut self, current_epoch: u64, fee_withdrawal: u128) -> Result<Value, String> {
        let job = self.seq.seal_batch(current_epoch, fee_withdrawal).map_err(|e| format!("seal failed: {e:?}"))?;
        self.da_history.push(job.da_blob.clone());
        Ok(json!({
            "seq": self.seq.seq(),
            "root": hexs(&self.seq.root()),
            "new_anchor": hexs(&job.new_anchor),
            "da_blob": hexs(&job.da_blob),
            "sp1_input": hexs(&job.sp1_input),
            "total": self.seq.total().to_string(),
            "fee_acc": self.seq.fee_acc().to_string(),
        }))
    }

    /// `GET /info`: the pool identity and current committed state.
    pub fn info(&self) -> Value {
        json!({
            "pool_id": hexs(&self.pool_id),
            "chain_id": self.chain_id,
            "seq": self.seq.seq(),
            "root": hexs(&self.seq.root()),
            "total": self.seq.total().to_string(),
            "fee_acc": self.seq.fee_acc().to_string(),
            "last_epoch": self.seq.last_epoch(),
            "pending": self.seq.pending(),
            "max_pending": MAX_PENDING,
            "min_fee": self.seq.fee_policy().min_fee_per_intent.to_string(),
            "checkpoints": self.da_history.len(),
        })
    }

    /// `GET /leaf?key=0x..`: a key's current `{balance, nonce}` from the committed state.
    pub fn leaf(&self, key_hex: &str) -> Result<Value, String> {
        let key = wire::parse_hash(key_hex)?;
        let leaf = self.seq.state().get_leaf(&key);
        Ok(json!({ "key": hexs(&key), "balance": leaf.balance.to_string(), "nonce": leaf.nonce }))
    }

    /// `GET /da`: every published DA blob (`0x`-hex, oldest-first), so a client can reconstruct the
    /// tree and build a force-exit witness with no further trust in the operator.
    pub fn da(&self) -> Value {
        json!({ "blobs": self.da_history.iter().map(|b| hexs(b)).collect::<Vec<_>>() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liquid_cells_client::{reconstruct_tree, Account};
    use liquid_cells_stf::keccak;

    const CHAIN: u64 = 0x434b_42;
    fn pool_id() -> Hash {
        keccak(b"service-pool")
    }

    #[test]
    fn submit_seal_query_reconstruct_full_loop() {
        let mut svc = Service::genesis(pool_id(), CHAIN);
        let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
        let bob = Account::new(pool_id(), CHAIN, [9u8; 32]);

        // 1. fund Alice with a deposit via the operator-only path (on-chain it binds a real L1
        // cell); the public /submit rejects deposits (see below).
        let dep = wire::deposit_to_value(&liquid_cells_stf::Deposit { to_key: alice.key(), amount: 1_000_000 }).to_string();
        assert!(svc.submit(&dep).is_err(), "deposits are not accepted over the public submit path");
        let r = svc.admin_deposit(&dep).unwrap();
        assert_eq!(r["pending"], 1);
        svc.seal(1, 0).unwrap();
        assert_eq!(svc.leaf(&hexs(&alice.key())).unwrap()["balance"], "1000000");

        // 2. Alice signs a transfer to Bob through the client; the service parses the SAME wire JSON.
        let t = alice.transfer(bob.key(), 250_000, 10, 100);
        svc.submit(&wire::transfer_to_value(&t).to_string()).unwrap();
        let sealed = svc.seal(2, 0).unwrap();
        assert_eq!(sealed["seq"], 2);

        // 3. Bob got paid; Alice debited amount + fee.
        assert_eq!(svc.leaf(&hexs(&bob.key())).unwrap()["balance"], "250000");
        assert_eq!(svc.leaf(&hexs(&alice.key())).unwrap()["balance"], (1_000_000u128 - 250_000 - 10).to_string());

        // 4. The published DA alone reconstructs to the committed root (no sequencer trust).
        let blobs = svc.da_blobs().to_vec();
        let root = reconstruct_tree(&blobs).unwrap().root();
        assert_eq!(hexs(&root), svc.info()["root"], "DA reconstruct == on-chain root");
    }

    #[test]
    fn malformed_submit_is_rejected_cleanly() {
        let mut svc = Service::genesis(pool_id(), CHAIN);
        assert!(svc.submit("not json").is_err());
        assert!(svc.submit(r#"{"type":"nope"}"#).is_err());
        assert!(svc.leaf("0xzz").is_err());
    }

    #[test]
    fn fee_floor_rejects_underpayers_at_admission() {
        // M-3: with a floor installed, a below-floor transfer is rejected at /submit (never enters the
        // mempool), while one paying the floor is admitted. genesis() leaves the floor at 0 (tests).
        let mut svc = Service::genesis(pool_id(), CHAIN);
        assert_eq!(svc.info()["min_fee"], "0", "genesis admits everything");
        let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
        let bob = Account::new(pool_id(), CHAIN, [9u8; 32]);

        svc.set_fee_floor(1);
        assert_eq!(svc.info()["min_fee"], "1");
        // fee 0 -> rejected at admission, mempool stays empty.
        let zero = alice.transfer(bob.key(), 100, 0, 100);
        let err = svc.submit(&wire::transfer_to_value(&zero).to_string()).unwrap_err();
        assert!(err.starts_with("underpaid"), "zero-fee transfer rejected: {err}");
        assert_eq!(svc.info()["pending"], 0, "underpayer never entered the mempool");
        // fee 1 -> admitted.
        let paid = alice.transfer(bob.key(), 100, 1, 101);
        svc.submit(&wire::transfer_to_value(&paid).to_string()).unwrap();
        assert_eq!(svc.info()["pending"], 1);
    }

    #[test]
    fn mempool_is_bounded_against_spam() {
        // L-5: pending is capped; a flood past MAX_PENDING is rejected with an overloaded signal.
        let mut svc = Service::genesis(pool_id(), CHAIN);
        let mut alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
        let bob = Account::new(pool_id(), CHAIN, [9u8; 32]);
        // The mempool does not validate at submit, so one well-formed intent re-submitted just queues
        // duplicates, which is exactly the spam shape we are bounding (and avoids 10k signatures).
        let body = wire::transfer_to_value(&alice.transfer(bob.key(), 1, 0, 1_000_000)).to_string();
        for _ in 0..MAX_PENDING {
            svc.submit(&body).unwrap();
        }
        assert_eq!(svc.info()["pending"], MAX_PENDING);
        let err = svc.submit(&body).unwrap_err();
        assert!(err.starts_with("overloaded"), "spam past the cap is rejected: {err}");
    }

    #[test]
    fn seal_with_a_bad_signature_errors_and_keeps_the_mempool() {
        let mut svc = Service::genesis(pool_id(), CHAIN);
        let alice = Account::new(pool_id(), CHAIN, [7u8; 32]);
        // A transfer from an unfunded account with a tampered sig: well-formed JSON, rejected at seal.
        let mut t = Account::new(pool_id(), CHAIN, [7u8; 32]);
        let mut tx = t.transfer(alice.key(), 10, 0, 100);
        tx.sig[0] ^= 0xff;
        svc.submit(&wire::transfer_to_value(&tx).to_string()).unwrap();
        let _ = &mut t;
        assert!(svc.seal(1, 0).is_err(), "invalid intent fails the seal");
        assert_eq!(svc.info()["pending"], 1, "mempool intact after a failed seal");
    }
}
