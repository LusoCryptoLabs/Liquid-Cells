//! Liquid Cells interactive demo server.
//!
//! Runs the REAL protocol crates (the same `liquid-cells-stf` the SP1 guest proves, the real
//! sequencer, the real client SDK) behind a tiny HTTP API, and serves a single-page UI. Drive a
//! creator-tipping scenario: fund viewers, send sub-1-CKB tips, seal checkpoints, then recover a
//! balance from L1 data alone and build an escape-hatch witness. The ~7-minute Groth16 proof is
//! not run per click; the logic runs instantly and the UI links to the live Pudge checkpoints.
//!
//!   cargo run -p liquid-cells-demo-ui    # then open http://127.0.0.1:8088

use std::collections::BTreeMap;
use std::sync::Mutex;

use liquid_cells_client::{proof_from_da, Account};
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::{keccak, verify_proof, Deposit, Hash};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};

const CHAIN_ID: u64 = 0x0043_4b42;
const CKB: f64 = 100_000_000.0; // shannons per CKB
const EXPIRY: u64 = 1_000_000;

fn pool_id() -> Hash {
    keccak(b"liquid-cells-demo")
}
fn account_secret(name: &str) -> [u8; 32] {
    keccak(format!("liquid-cells-demo/account/{name}").as_bytes())
}
fn hexs(h: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in h {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
fn to_shannons(ckb: f64) -> u128 {
    (ckb * CKB).round() as u128
}

struct Demo {
    seq: Sequencer,
    accounts: BTreeMap<String, Account>,
    order: Vec<String>,            // display order
    epoch: u64,                    // advances per checkpoint
    blobs: Vec<Vec<u8>>,           // published DA blobs (for trustless reconstruction)
    checkpoints: Vec<(u64, Hash)>, // (seq, root) history
    pending: BTreeMap<Hash, i128>, // optimistic net delta per key since the last checkpoint
}

impl Demo {
    fn new() -> Self {
        let mut d = Demo {
            seq: Sequencer::genesis(pool_id(), CHAIN_ID),
            accounts: BTreeMap::new(),
            order: Vec::new(),
            epoch: 0,
            blobs: Vec::new(),
            checkpoints: Vec::new(),
            pending: BTreeMap::new(),
        };
        // Seed a creator-tipping scenario: one streamer plus three funded viewers.
        for n in ["Streamer", "Alice", "Bob", "Carol"] {
            d.add_account(n);
        }
        for n in ["Alice", "Bob", "Carol"] {
            let key = d.accounts[n].key();
            d.seq.submit_deposit(Deposit { to_key: key, amount: to_shannons(100.0) });
            *d.pending.entry(key).or_default() += to_shannons(100.0) as i128;
        }
        let _ = d.checkpoint(); // checkpoint 1: viewers funded
        d
    }

    fn add_account(&mut self, name: &str) {
        if self.accounts.contains_key(name) {
            return;
        }
        self.accounts.insert(name.to_string(), Account::new(pool_id(), CHAIN_ID, account_secret(name)));
        self.order.push(name.to_string());
    }

    fn sealed_balance(&self, key: &Hash) -> u128 {
        self.seq.state().get_leaf(key).balance
    }
    fn available(&self, key: &Hash) -> i128 {
        self.sealed_balance(key) as i128 + self.pending.get(key).copied().unwrap_or(0)
    }

    /// Queue a signed tip (transfer). Pre-checked against the optimistic balance so the mempool
    /// stays valid; the signature and nonce are produced by the real client SDK.
    fn tip(&mut self, from: &str, to: &str, amount: u128, fee: u128) -> Result<(), String> {
        let to_key = self.accounts.get(to).ok_or("unknown recipient")?.key();
        let from_key = self.accounts.get(from).ok_or("unknown sender")?.key();
        if from == to {
            return Err("cannot tip yourself".into());
        }
        if self.available(&from_key) < (amount + fee) as i128 {
            return Err("insufficient available balance".into());
        }
        let t = self.accounts.get_mut(from).unwrap().transfer(to_key, amount, fee, EXPIRY);
        self.seq.submit_transfer(t);
        *self.pending.entry(from_key).or_default() -= (amount + fee) as i128;
        *self.pending.entry(to_key).or_default() += amount as i128;
        Ok(())
    }

    fn deposit(&mut self, name: &str, amount: u128) -> Result<(), String> {
        let key = self.accounts.get(name).ok_or("unknown account")?.key();
        self.seq.submit_deposit(Deposit { to_key: key, amount });
        *self.pending.entry(key).or_default() += amount as i128;
        Ok(())
    }

    /// Seal the mempool into a checkpoint: advance the root, publish the DA blob. This is the
    /// real `seal_batch`; on Pudge the same transition is proven and verified on-chain.
    fn checkpoint(&mut self) -> Result<Value, String> {
        if self.seq.pending() == 0 {
            return Err("nothing pending to checkpoint".into());
        }
        let job = self.seq.seal_batch(self.epoch, 0).map_err(|e| format!("{e:?}"))?;
        self.epoch += 1;
        self.blobs.push(job.da_blob.clone());
        self.checkpoints.push((job.new_seq(), job.new_root()));
        self.pending.clear();
        Ok(json!({
            "seq": job.new_seq(),
            "root": hexs(&job.new_root()),
            "daBytes": job.da_blob.len(),
        }))
    }

    fn state(&self) -> Value {
        let accounts: Vec<Value> = self
            .order
            .iter()
            .map(|name| {
                let a = &self.accounts[name];
                let key = a.key();
                let leaf = self.seq.state().get_leaf(&key);
                json!({
                    "name": name,
                    "key": hexs(&key),
                    "balanceCkb": leaf.balance as f64 / CKB,
                    "availableCkb": self.available(&key) as f64 / CKB,
                    "nonce": leaf.nonce,
                })
            })
            .collect();
        let cps: Vec<Value> =
            self.checkpoints.iter().map(|(s, r)| json!({"seq": s, "root": hexs(r)})).collect();
        json!({
            "pool": {
                "root": hexs(&self.seq.root()),
                "seq": self.seq.seq(),
                "totalCkb": self.seq.total() as f64 / CKB,
                "feeAccCkb": self.seq.fee_acc() as f64 / CKB,
            },
            "accounts": accounts,
            "pending": self.seq.pending(),
            "checkpoints": cps,
        })
    }

    /// Rebuild an account's leaf + inclusion proof from the published DA blobs alone, with no help
    /// from the sequencer, then verify the proof against the committed root.
    fn reconstruct(&self, name: &str) -> Result<Value, String> {
        let key = self.accounts.get(name).ok_or("unknown account")?.key();
        let (leaf, siblings) = proof_from_da(&self.blobs, &key).ok_or("no DA / malformed")?;
        let verified = verify_proof(&self.seq.root(), &key, &leaf.hash(), &siblings);
        let matches = leaf == self.seq.state().get_leaf(&key);
        Ok(json!({
            "name": name,
            "balanceCkb": leaf.balance as f64 / CKB,
            "nonce": leaf.nonce,
            "verifiedAgainstRoot": verified,
            "matchesSequencer": matches,
            "root": hexs(&self.seq.root()),
        }))
    }

    /// Build the account's force-exit witness from L1 DA, and confirm its inclusion proof verifies
    /// against the live root (exactly the check the on-chain force-exit mode performs).
    fn force_exit(&self, name: &str) -> Result<Value, String> {
        let acct = self.accounts.get(name).ok_or("unknown account")?;
        let key = acct.key();
        let witness = acct.force_exit_witness(&self.blobs).ok_or("nothing to exit (zero balance?)")?;
        let (leaf, siblings) = proof_from_da(&self.blobs, &key).ok_or("no DA")?;
        let verified = verify_proof(&self.seq.root(), &key, &leaf.hash(), &siblings);
        Ok(json!({
            "name": name,
            "witnessBytes": witness.len(),
            "balanceCkb": leaf.balance as f64 / CKB,
            "verifiedAgainstRoot": verified,
            "root": hexs(&self.seq.root()),
        }))
    }
}

fn body_json(req: &mut tiny_http::Request) -> Value {
    let mut s = String::new();
    let _ = req.as_reader().read_to_string(&mut s);
    serde_json::from_str(&s).unwrap_or(Value::Null)
}
fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn num(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn json_resp(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(v.to_string()).with_header(h)
}

fn main() {
    // Bind all interfaces so it is reachable from the Windows host via WSL2 localhost forwarding.
    let addr = "0.0.0.0:8088";
    let server = Server::http(addr).expect("bind");
    let demo = Mutex::new(Demo::new());
    println!("Liquid Cells demo UI running, open http://127.0.0.1:8088");

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let query = url.split('?').nth(1).unwrap_or("").to_string();

        let resp = match (&method, path.as_str()) {
            (Method::Get, "/") => {
                let h = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                req.respond(Response::from_string(include_str!("index.html")).with_header(h)).ok();
                continue;
            }
            (Method::Get, "/api/state") => json_resp(demo.lock().unwrap().state()),
            (Method::Post, "/api/reset") => {
                *demo.lock().unwrap() = Demo::new();
                json_resp(json!({"ok": true}))
            }
            (Method::Post, "/api/account") => {
                let b = body_json(&mut req);
                let name = s(&b, "name");
                let mut d = demo.lock().unwrap();
                if name.is_empty() {
                    json_resp(json!({"error": "name required"}))
                } else {
                    d.add_account(&name);
                    json_resp(json!({"ok": true}))
                }
            }
            (Method::Post, "/api/deposit") => {
                let b = body_json(&mut req);
                let mut d = demo.lock().unwrap();
                match d.deposit(&s(&b, "name"), to_shannons(num(&b, "ckb"))) {
                    Ok(()) => json_resp(json!({"ok": true})),
                    Err(e) => json_resp(json!({"error": e})),
                }
            }
            (Method::Post, "/api/tip") => {
                let b = body_json(&mut req);
                let mut d = demo.lock().unwrap();
                match d.tip(&s(&b, "from"), &s(&b, "to"), to_shannons(num(&b, "ckb")), to_shannons(num(&b, "feeCkb"))) {
                    Ok(()) => json_resp(json!({"ok": true})),
                    Err(e) => json_resp(json!({"error": e})),
                }
            }
            (Method::Post, "/api/checkpoint") => {
                let mut d = demo.lock().unwrap();
                match d.checkpoint() {
                    Ok(v) => json_resp(v),
                    Err(e) => json_resp(json!({"error": e})),
                }
            }
            (Method::Get, "/api/reconstruct") => {
                let name = query.strip_prefix("name=").unwrap_or("");
                match demo.lock().unwrap().reconstruct(name) {
                    Ok(v) => json_resp(v),
                    Err(e) => json_resp(json!({"error": e})),
                }
            }
            (Method::Get, "/api/forceexit") => {
                let name = query.strip_prefix("name=").unwrap_or("");
                match demo.lock().unwrap().force_exit(name) {
                    Ok(v) => json_resp(v),
                    Err(e) => json_resp(json!({"error": e})),
                }
            }
            _ => json_resp(json!({"error": "not found"})),
        };
        req.respond(resp).ok();
    }
}
