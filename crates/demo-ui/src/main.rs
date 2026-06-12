//! Liquid Cells on-chain demo server.
//!
//! Drives a REAL pooled-rollup on the CKB Pudge testnet from a browser. It holds the live
//! [`Sequencer`] (synced to the on-chain anchor by replaying the genesis bootstrap), accepts
//! self-custodially-signed tips and withdrawals from the page, and lands each checkpoint on
//! Pudge: it seals the batch, then a background thread proves it (Groth16, ~7 min) and submits
//! the checkpoint tx, whose BN254 proof the anchor type script verifies on a live block.
//!
//! Deposits and withdrawals are BATCHED: an incoming deposit/withdrawal lands in a pending
//! buffer, and a batcher thread seals everything accumulated within a short window into ONE
//! checkpoint. So dozens of people depositing at once collapse into a single ~7-min proof (the
//! proving cost is dominated by the fixed BN254 wrap, not the number of accounts in the batch),
//! instead of a queue of one proof per deposit. Tips already pool off-chain and ride the next
//! checkpoint. The operator only orders and proves; it cannot steal, inflate, or redirect a
//! withdrawal (the user's session key signs it, bound to their own lock).
//!
//!   cargo run -p liquid-cells-demo-ui    # then open http://127.0.0.1:8088

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use liquid_cells_client::Account;
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::{
    key_of_pubkey, keccak, sig, transfer_msg, withdraw_msg, Deposit, Hash, Transfer, Withdrawal,
};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};

const CHAIN_ID: u64 = 0x0043_4b42;
const CKB: f64 = 100_000_000.0;
const EXPIRY: u64 = 10_000_000;
/// Miner fee drawn from the pool's fee reserve per checkpoint (0.01 CKB).
const FEE_WD: u128 = 1_000_000;

// --- batching: collapse near-simultaneous deposits/withdrawals into one checkpoint ---
/// Collection window: after the first pending deposit/withdrawal arrives, wait this long for
/// more before sealing, so a burst of depositors shares one proof. A lone depositor waits only
/// this long (negligible next to the ~7-min proof).
const BATCH_WINDOW: Duration = Duration::from_secs(8);
/// Seal immediately (do not wait out the window) once this many deposits are queued.
const BATCH_MAX: usize = 24;

// --- the operator bootstrap (must match lc-demo-genesis.mjs + the live cp1 on Pudge) ---
const OP_SECRET: [u8; 32] = [0x11; 32];
const BOOT_DEPOSIT: u128 = 10_000_000_000; // 100 CKB
const BOOT_RESERVE: u128 = 500_000_000; // 5 CKB seeded into fee_acc
const BOOT_FEE_WD: u128 = 1_000_000; // 0.01 CKB drawn for cp1's miner fee
const LIVE_BOOTSTRAP_ROOT: &str = "ea1da02dddbce9707ce8bf95dc46e48643bd3c4c17c0f5e07f08ff245176ed7d";

const DEMO_DIR: &str = "/root/liquid-cells/fixtures/demo";
const WRAPPER: &str = "/root/liquid-cells/fixtures/demo/lc-run-checkpoint.sh";
const AS_CODE_HASH: &str = "0xd8c2346649752dc03e8e747ae6152fe13675be36b3c77e459d6f841988c2d06e";

fn pool_id() -> Hash {
    keccak(b"sp1-pool")
}
fn fee_sink_key() -> Hash {
    keccak(b"liquid-cells-demo/fee-sink")
}
fn creator_secret(name: &str) -> [u8; 32] {
    keccak(format!("liquid-cells-demo/creator/{name}").as_bytes())
}
fn hexs(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
fn parse_hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap_or_default()
}
fn parse_hash(s: &str) -> Option<Hash> {
    let v = parse_hex(s);
    (v.len() == 32).then(|| {
        let mut h = [0u8; 32];
        h.copy_from_slice(&v);
        h
    })
}
fn parse_pubkey(s: &str) -> Option<[u8; 33]> {
    let v = parse_hex(s);
    (v.len() == 33).then(|| {
        let mut p = [0u8; 33];
        p.copy_from_slice(&v);
        p
    })
}
fn parse_sig(s: &str) -> Option<[u8; 64]> {
    let v = parse_hex(s);
    (v.len() == 64).then(|| {
        let mut p = [0u8; 64];
        p.copy_from_slice(&v);
        p
    })
}
fn u128_of(v: &Value, k: &str) -> Option<u128> {
    match v.get(k) {
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64().map(|x| x as u128),
        _ => None,
    }
}
fn u64_of(v: &Value, k: &str) -> Option<u64> {
    match v.get(k) {
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
}
fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

#[derive(Clone)]
struct AnchorRef {
    tx: String,
    index: u64,
    capacity: u128,
    root: String,
    seq: u64,
}

#[derive(Clone)]
struct AccountInfo {
    label: String,
    pubkey: [u8; 33],
    key: Hash,
    is_user: bool,
}

#[derive(Clone)]
struct PendingTip {
    from_key: Hash,
    to_key: Hash,
    from_label: String,
    to_label: String,
    amount: u128,
    fee: u128,
    transfer: Transfer,
}

/// A deposit waiting to be swept into the next batched checkpoint.
#[derive(Clone)]
struct DepositReq {
    label: String,
    to_key: Hash,
    amount: u128,
    tx: String,
    index: u64,
}

/// A withdrawal waiting to be swept into the next batched checkpoint.
#[derive(Clone)]
struct WithdrawReq {
    w: Withdrawal,
    lock: Value,
    label: String,
}

#[derive(Clone)]
struct Job {
    id: u64,
    kind: String,
    status: String, // proving | confirmed | failed
    detail: String,
    seq: u64,
    anchor_tx: Option<String>,
}

struct Demo {
    seq: Sequencer,
    anchor: AnchorRef,
    accounts: BTreeMap<Hash, AccountInfo>,
    creators: Vec<Hash>,
    pending: Vec<PendingTip>,
    pending_deposits: Vec<DepositReq>,
    pending_withdrawals: Vec<WithdrawReq>,
    /// When the first item of the current batch arrived (deposits/withdrawals only).
    batch_since: Option<Instant>,
    epoch: u64,
    in_flight: bool,
    jobs: Vec<Job>,
    job_counter: u64,
}

fn read_json_file(path: &str) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

impl Demo {
    fn new() -> Self {
        // Replay the genesis bootstrap so the in-memory root matches the live on-chain anchor.
        let mut seq = Sequencer::genesis(pool_id(), CHAIN_ID);
        let op_key = key_of_pubkey(&sig::pubkey(&OP_SECRET));
        seq.submit_deposit(Deposit { to_key: op_key, amount: BOOT_DEPOSIT });
        let mut op = Account::new(pool_id(), CHAIN_ID, OP_SECRET);
        seq.submit_transfer(op.transfer(fee_sink_key(), 1, BOOT_RESERVE, EXPIRY));
        seq.seal_batch(0, BOOT_FEE_WD).expect("bootstrap replay");
        assert_eq!(
            hexs(&seq.root()),
            format!("0x{LIVE_BOOTSTRAP_ROOT}"),
            "bootstrap replay did not reproduce the live cp1 root; redeploy the demo pool"
        );

        let state = read_json_file(&format!("{DEMO_DIR}/state.json"))
            .expect("state.json (run lc-demo-genesis.mjs + cp1)");
        let a = &state["anchor"];
        let anchor = AnchorRef {
            tx: a["txHash"].as_str().unwrap().to_string(),
            index: a["index"].as_u64().unwrap_or(0),
            capacity: a["capacity"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            root: a["root"].as_str().unwrap_or("").to_string(),
            seq: a["seq"].as_u64().unwrap_or(1),
        };

        let mut d = Demo {
            seq,
            anchor,
            accounts: BTreeMap::new(),
            creators: Vec::new(),
            pending: Vec::new(),
            pending_deposits: Vec::new(),
            pending_withdrawals: Vec::new(),
            batch_since: None,
            epoch: 1,
            in_flight: false,
            jobs: Vec::new(),
            job_counter: 0,
        };
        for name in ["Streamer", "ArtistAna", "GamerGus"] {
            let pubkey = sig::pubkey(&creator_secret(name));
            let key = key_of_pubkey(&pubkey);
            d.accounts
                .insert(key, AccountInfo { label: name.into(), pubkey, key, is_user: false });
            d.creators.push(key);
        }
        d
    }

    fn committed_balance(&self, key: &Hash) -> u128 {
        self.seq.state().get_leaf(key).balance
    }
    fn committed_nonce(&self, key: &Hash) -> u64 {
        self.seq.state().get_leaf(key).nonce
    }
    /// Off-chain delta from pending (not-yet-checkpointed) tips, deposits, and withdrawals.
    fn pending_delta(&self, key: &Hash) -> i128 {
        let mut d: i128 = 0;
        for p in &self.pending {
            if &p.to_key == key {
                d += p.amount as i128;
            }
            if &p.from_key == key {
                d -= (p.amount + p.fee) as i128;
            }
        }
        for dep in &self.pending_deposits {
            if &dep.to_key == key {
                d += dep.amount as i128;
            }
        }
        for w in &self.pending_withdrawals {
            if key_of_pubkey(&w.w.from_pubkey) == *key {
                d -= w.w.amount as i128;
            }
        }
        d
    }
    fn display_balance(&self, key: &Hash) -> u128 {
        (self.committed_balance(key) as i128 + self.pending_delta(key)).max(0) as u128
    }
    /// Nonce the next signed intent from `key` must use: committed nonce + pending spends (tips
    /// and queued withdrawals from this key).
    fn expected_nonce(&self, key: &Hash) -> u64 {
        let tips = self.pending.iter().filter(|p| &p.from_key == key).count() as u64;
        let wds = self
            .pending_withdrawals
            .iter()
            .filter(|w| key_of_pubkey(&w.w.from_pubkey) == *key)
            .count() as u64;
        self.committed_nonce(key) + tips + wds
    }

    fn role(&self, key: &Hash) -> &'static str {
        match self.accounts.get(key).map(|a| a.label.as_str()) {
            Some("Streamer") => "Live streamer",
            Some("ArtistAna") => "Digital artist",
            Some("GamerGus") => "Speedrunner",
            _ => "Creator",
        }
    }

    /// Register a wallet's session identity. Each distinct session pubkey is its own pool account,
    /// keyed by `keccak(pubkey)`; balances are never shared between wallets.
    fn register_user(&mut self, pubkey: [u8; 33]) -> Hash {
        let key = key_of_pubkey(&pubkey);
        self.accounts
            .entry(key)
            .or_insert_with(|| AccountInfo { label: "You".into(), pubkey, key, is_user: true });
        key
    }

    fn tip(&mut self, t: Transfer) -> Result<(), String> {
        let from_key = key_of_pubkey(&t.from_pubkey);
        let msg = transfer_msg(
            CHAIN_ID, &pool_id(), &from_key, &t.to_key, t.amount, t.fee, t.nonce, t.expiry,
        );
        if !sig::verify(&t.from_pubkey, &msg, &t.sig) {
            return Err("bad signature".into());
        }
        if t.nonce != self.expected_nonce(&from_key) {
            return Err(format!("bad nonce (expected {})", self.expected_nonce(&from_key)));
        }
        if self.display_balance(&from_key) < t.amount + t.fee {
            return Err("not enough balance".into());
        }
        if !self.accounts.contains_key(&t.to_key) {
            return Err("unknown recipient".into());
        }
        let from_label = self.accounts.get(&from_key).map(|a| a.label.clone()).unwrap_or_default();
        let to_label = self.accounts.get(&t.to_key).map(|a| a.label.clone()).unwrap_or_default();
        self.pending.push(PendingTip {
            from_key,
            to_key: t.to_key,
            from_label,
            to_label,
            amount: t.amount,
            fee: t.fee,
            transfer: t,
        });
        Ok(())
    }

    /// Queue a deposit for the next batched checkpoint (the deposit cell is already on Pudge).
    fn enqueue_deposit(&mut self, label: String, to_key: Hash, amount: u128, tx: String, index: u64) {
        self.pending_deposits.push(DepositReq { label, to_key, amount, tx, index });
        if self.batch_since.is_none() {
            self.batch_since = Some(Instant::now());
        }
    }
    /// Queue a (validated) withdrawal for the next batched checkpoint.
    fn enqueue_withdraw(&mut self, w: Withdrawal, lock: Value, label: String) {
        self.pending_withdrawals.push(WithdrawReq { w, lock, label });
        if self.batch_since.is_none() {
            self.batch_since = Some(Instant::now());
        }
    }

    /// Is a batched checkpoint due? (the collection window elapsed, or the deposit cap hit).
    fn batch_ready(&self) -> bool {
        if self.in_flight {
            return false;
        }
        match self.batch_since {
            Some(t) => t.elapsed() >= BATCH_WINDOW || self.pending_deposits.len() >= BATCH_MAX,
            None => false,
        }
    }
    fn seconds_until_seal(&self) -> Option<u64> {
        self.batch_since.map(|t| BATCH_WINDOW.saturating_sub(t.elapsed()).as_secs())
    }

    /// Seal ALL pending tips + deposits + withdrawals into one checkpoint, write the prover +
    /// submit fixtures, and mark a job `proving`. Returns (job_id, job_name).
    fn seal_pending(&mut self) -> Result<(u64, String), String> {
        if self.in_flight {
            return Err("a checkpoint is already being proved, please wait".into());
        }
        let (nd, nw, nt) =
            (self.pending_deposits.len(), self.pending_withdrawals.len(), self.pending.len());
        if nd == 0 && nw == 0 && nt == 0 {
            return Err("nothing to checkpoint".into());
        }

        for p in &self.pending {
            self.seq.submit_transfer(p.transfer.clone());
        }
        let mut deposit_cells = Vec::new();
        for d in &self.pending_deposits {
            self.seq.submit_deposit(Deposit { to_key: d.to_key, amount: d.amount });
            deposit_cells.push(json!({"txHash": d.tx, "index": d.index, "capacity": d.amount.to_string()}));
        }
        let mut withdrawal_outputs = Vec::new();
        for wr in &self.pending_withdrawals {
            self.seq.submit_withdrawal(wr.w.clone());
            withdrawal_outputs.push(json!({"lock": wr.lock, "capacity": wr.w.amount.to_string()}));
        }

        let epoch = self.epoch;
        let job = self.seq.seal_batch(epoch, FEE_WD).map_err(|e| {
            format!("seal failed: {e:?} (in-memory state may be ahead of chain; restart server)")
        })?;
        let name = format!("cp{}", job.new_seq());
        let dir = format!("{DEMO_DIR}/{name}");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        fs::write(format!("{dir}/sp1_input.bin"), &job.sp1_input).map_err(|e| e.to_string())?;
        fs::write(format!("{dir}/new_anchor.bin"), job.new_anchor).map_err(|e| e.to_string())?;
        fs::write(format!("{dir}/da_blob.bin"), &job.da_blob).map_err(|e| e.to_string())?;
        let jobjson = json!({
            "feeWithdrawalShannons": FEE_WD.to_string(),
            "epoch": epoch,
            "newRoot": hexs(&job.new_root()),
            "newSeq": job.new_seq(),
            "depositCells": deposit_cells,
            "withdrawals": withdrawal_outputs,
        });
        fs::write(format!("{dir}/job.json"), serde_json::to_string_pretty(&jobjson).unwrap())
            .map_err(|e| e.to_string())?;

        let kind = {
            let mut parts = Vec::new();
            if nd > 0 {
                parts.push(format!("{nd} deposit{}", if nd == 1 { "" } else { "s" }));
            }
            if nw > 0 {
                parts.push(format!("{nw} withdrawal{}", if nw == 1 { "" } else { "s" }));
            }
            if nt > 0 {
                parts.push(format!("{nt} tip{}", if nt == 1 { "" } else { "s" }));
            }
            parts.join(" + ")
        };

        self.epoch += 1;
        self.pending.clear();
        self.pending_deposits.clear();
        self.pending_withdrawals.clear();
        self.batch_since = None;
        self.in_flight = true;
        self.job_counter += 1;
        let id = self.job_counter;
        self.jobs.push(Job {
            id,
            kind,
            status: "proving".into(),
            detail: format!("proving + submitting {name} (~7 min)"),
            seq: job.new_seq(),
            anchor_tx: None,
        });
        Ok((id, name))
    }

    fn on_done(&mut self, id: u64, name: &str, ok: bool) {
        self.in_flight = false;
        let result = read_json_file(&format!("{DEMO_DIR}/{name}/result.json"));
        if ok {
            if let Some(r) = &result {
                self.anchor = AnchorRef {
                    tx: r["anchorTx"].as_str().unwrap_or("").to_string(),
                    index: r["anchorIndex"].as_u64().unwrap_or(0),
                    capacity: r["capacity"].as_str().and_then(|s| s.parse().ok()).unwrap_or(self.anchor.capacity),
                    root: r["root"].as_str().unwrap_or("").trim_start_matches("0x").to_string(),
                    seq: r["seq"].as_u64().unwrap_or(self.anchor.seq + 1),
                };
            }
            if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
                j.status = "confirmed".into();
                j.anchor_tx = result.as_ref().and_then(|r| r["anchorTx"].as_str().map(|s| s.to_string()));
                j.detail = format!("verified on-chain (seq {})", self.anchor.seq);
            }
        } else if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
            j.status = "failed".into();
            j.detail = "prove or submit failed (see fixtures/demo/<cp>/run.log)".into();
        }
    }

    /// Snapshot for the caller. `req_key` is the requesting wallet's session key, so each browser
    /// sees ONLY its own balance (multi-user safe).
    fn state_json(&self, req_key: Option<Hash>) -> Value {
        let user = req_key.filter(|k| self.accounts.contains_key(k)).map(|k| {
            json!({
                "registered": true,
                "key": hexs(&k),
                "balanceCkb": self.display_balance(&k) as f64 / CKB,
                "committedCkb": self.committed_balance(&k) as f64 / CKB,
                "nextNonce": self.expected_nonce(&k),
            })
        });
        let creators: Vec<Value> = self
            .creators
            .iter()
            .map(|k| json!({"label": self.accounts[k].label, "role": self.role(k), "key": hexs(k),
                            "earnedCkb": self.display_balance(k) as f64 / CKB}))
            .collect();
        let jobs: Vec<Value> = self
            .jobs
            .iter()
            .rev()
            .take(8)
            .map(|j| json!({"id": j.id, "kind": j.kind, "status": j.status, "detail": j.detail,
                            "seq": j.seq, "anchorTx": j.anchor_tx}))
            .collect();
        json!({
            "network": "pudge",
            "inFlight": self.in_flight,
            "batch": {
                "pendingDeposits": self.pending_deposits.len(),
                "pendingWithdrawals": self.pending_withdrawals.len(),
                "pendingTips": self.pending.len(),
                "sealingInSecs": if self.in_flight { Value::Null } else { json!(self.seconds_until_seal()) },
            },
            "user": user.unwrap_or(json!({"registered": false})),
            "creators": creators,
            "jobs": jobs,
            "deposit": { "alwaysSuccessLock": {"codeHash": AS_CODE_HASH, "hashType": "type", "args": "0x"} },
            "pool": {
                "anchorTx": self.anchor.tx,
                "anchorIndex": self.anchor.index,
                "root": format!("0x{}", self.anchor.root),
                "anchorSeq": self.anchor.seq,
                "totalCkb": self.seq.total() as f64 / CKB,
                "feeAccCkb": self.seq.fee_acc() as f64 / CKB,
                "poolCapacityCkb": self.anchor.capacity as f64 / CKB,
            }
        })
    }
}

type Shared = Arc<Mutex<Demo>>;

fn spawn_pipeline(shared: &Shared, id: u64, name: String) {
    let shared = shared.clone();
    thread::spawn(move || {
        let ok = Command::new("bash")
            .arg(WRAPPER)
            .arg(&name)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        shared.lock().unwrap().on_done(id, &name, ok);
    });
}

/// The batcher: every second, if a batched checkpoint is due, seal all pending deposits +
/// withdrawals + tips into one checkpoint and spawn its prove+submit pipeline.
fn spawn_batcher(shared: Shared) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1000));
        let sealed = {
            let mut d = shared.lock().unwrap();
            if d.batch_ready() {
                d.seal_pending().ok()
            } else {
                None
            }
        };
        if let Some((id, name)) = sealed {
            spawn_pipeline(&shared, id, name);
        }
    });
}

fn body(req: &mut tiny_http::Request) -> Value {
    let mut s = String::new();
    let _ = std::io::Read::read_to_string(req.as_reader(), &mut s);
    serde_json::from_str(&s).unwrap_or(Value::Null)
}
fn jr(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(v.to_string()).with_header(h)
}

fn handle(shared: &Shared, path: &str, b: &Value) -> Value {
    match path {
        "/api/register" => {
            let Some(pubkey) = parse_pubkey(&str_of(b, "pubkey")) else {
                return json!({"error": "bad pubkey"});
            };
            let key = shared.lock().unwrap().register_user(pubkey);
            json!({"ok": true, "key": hexs(&key)})
        }
        "/api/tip" => {
            let parsed = (
                parse_pubkey(&str_of(b, "fromPubkey")),
                parse_hash(&str_of(b, "toKey")),
                u128_of(b, "amount"),
                u128_of(b, "fee"),
                u64_of(b, "nonce"),
                u64_of(b, "expiry"),
                parse_sig(&str_of(b, "sig")),
            );
            let t = match parsed {
                (Some(fp), Some(tk), Some(a), Some(f), Some(n), Some(e), Some(s)) => {
                    Transfer { from_pubkey: fp, to_key: tk, amount: a, fee: f, nonce: n, expiry: e, sig: s }
                }
                _ => return json!({"error": "malformed tip"}),
            };
            match shared.lock().unwrap().tip(t) {
                Ok(()) => json!({"ok": true}),
                Err(e) => json!({"error": e}),
            }
        }
        "/api/deposit" => {
            let Some(to_key) = parse_hash(&str_of(b, "toKey")) else {
                return json!({"error": "bad toKey"});
            };
            let Some(amount) = u128_of(b, "amount") else {
                return json!({"error": "bad amount"});
            };
            let tx = str_of(b, "txHash");
            if tx.is_empty() {
                return json!({"error": "missing deposit outpoint"});
            }
            let index = u64_of(b, "index").unwrap_or(0);
            let mut d = shared.lock().unwrap();
            let label =
                d.accounts.get(&to_key).map(|a| a.label.clone()).unwrap_or_else(|| "someone".into());
            d.enqueue_deposit(label, to_key, amount, tx, index);
            json!({"ok": true, "queued": true, "pendingDeposits": d.pending_deposits.len(),
                   "sealingInSecs": d.seconds_until_seal()})
        }
        "/api/withdraw" => {
            let parsed = (
                parse_pubkey(&str_of(b, "fromPubkey")),
                parse_hash(&str_of(b, "targetLockHash")),
                u128_of(b, "amount"),
                u64_of(b, "nonce"),
                u64_of(b, "expiry"),
                parse_sig(&str_of(b, "sig")),
            );
            let w = match parsed {
                (Some(fp), Some(tlh), Some(a), Some(n), Some(e), Some(s)) => {
                    Withdrawal { from_pubkey: fp, target_lock_hash: tlh, amount: a, nonce: n, expiry: e, sig: s }
                }
                _ => return json!({"error": "malformed withdrawal"}),
            };
            let lock = b.get("lock").cloned().unwrap_or(Value::Null);
            let mut d = shared.lock().unwrap();
            let from_key = key_of_pubkey(&w.from_pubkey);
            let msg =
                withdraw_msg(CHAIN_ID, &pool_id(), &from_key, &w.target_lock_hash, w.amount, w.nonce, w.expiry);
            if !sig::verify(&w.from_pubkey, &msg, &w.sig) {
                return json!({"error": "bad signature"});
            }
            if w.nonce != d.expected_nonce(&from_key) {
                return json!({"error": format!("bad nonce (expected {})", d.expected_nonce(&from_key))});
            }
            if d.display_balance(&from_key) < w.amount {
                return json!({"error": "cannot withdraw more than your balance"});
            }
            let label = d.accounts.get(&from_key).map(|a| a.label.clone()).unwrap_or_default();
            d.enqueue_withdraw(w, lock, label);
            json!({"ok": true, "queued": true, "sealingInSecs": d.seconds_until_seal()})
        }
        "/api/settle" => {
            // Manual flush: seal whatever is pending now (e.g. tips with no deposit/withdrawal).
            let sealed = { shared.lock().unwrap().seal_pending() };
            match sealed {
                Ok((id, name)) => {
                    spawn_pipeline(shared, id, name);
                    json!({"ok": true, "jobId": id})
                }
                Err(e) => json!({"error": e}),
            }
        }
        _ => json!({"error": "not found"}),
    }
}

fn main() {
    let server = Server::http("0.0.0.0:8088").expect("bind");
    let shared: Shared = Arc::new(Mutex::new(Demo::new()));
    {
        let d = shared.lock().unwrap();
        println!(
            "Liquid Cells on-chain demo: pool seq {} root 0x{} anchor {}:{}",
            d.seq.seq(),
            d.anchor.root,
            d.anchor.tx,
            d.anchor.index
        );
    }
    println!("open http://127.0.0.1:8088 (deposits/withdrawals batch into one checkpoint per ~8s window)");
    spawn_batcher(shared.clone());

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let query = url.split('?').nth(1).unwrap_or("").to_string();

        let resp = match (&method, path.as_str()) {
            (Method::Get, "/") => {
                // Served from disk so UI edits don't need a server rebuild/restart.
                let html = fs::read_to_string("/root/liquid-cells/crates/demo-ui/src/index.html")
                    .unwrap_or_else(|_| "<h1>index.html not found</h1>".into());
                let h =
                    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                req.respond(Response::from_string(html).with_header(h)).ok();
                continue;
            }
            (Method::Get, "/api/state") => {
                let req_key =
                    query.split('&').find_map(|kv| kv.strip_prefix("key=")).and_then(parse_hash);
                jr(shared.lock().unwrap().state_json(req_key))
            }
            (Method::Post, _) => {
                let b = body(&mut req);
                jr(handle(&shared, path.as_str(), &b))
            }
            _ => jr(json!({"error": "not found"})),
        };
        req.respond(resp).ok();
    }
}
