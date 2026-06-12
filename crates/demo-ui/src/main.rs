//! Liquid Cells interactive demo server, a consumer-journey version.
//!
//! Runs the REAL protocol crates (the same `liquid-cells-stf` the SP1 guest proves, the real
//! sequencer, the real client SDK) behind a tiny HTTP API, and serves a single-page consumer app:
//! a first-person tipping journey, add funds, tip creators in tiny amounts, see that your money is
//! always recoverable, and cash out. Each action is settled instantly for usability; the
//! ~7-minute Groth16 proof is not run per click and the UI links to the live Pudge checkpoints.
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
const ME: &str = "You";

fn pool_id() -> Hash {
    keccak(b"liquid-cells-demo")
}
fn account_secret(name: &str) -> [u8; 32] {
    keccak(format!("liquid-cells-demo/account/{name}").as_bytes())
}
fn wallet_lock(name: &str) -> Hash {
    keccak(format!("liquid-cells-demo/wallet/{name}").as_bytes())
}
fn hexs(h: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in h {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
fn to_shannons(ckb: f64) -> u128 {
    (ckb * CKB).round().max(0.0) as u128
}
fn role(name: &str) -> &'static str {
    match name {
        "Streamer" => "Live streamer",
        "ArtistAna" => "Digital artist",
        "GamerGus" => "Speedrunner",
        _ => "Creator",
    }
}

struct Demo {
    seq: Sequencer,
    accounts: BTreeMap<String, Account>,
    creators: Vec<String>,
    epoch: u64,
    blobs: Vec<Vec<u8>>,
    checkpoints: usize,
    withdrawn: u128,
    activity: Vec<String>,
}

impl Demo {
    fn new() -> Self {
        let mut d = Demo {
            seq: Sequencer::genesis(pool_id(), CHAIN_ID),
            accounts: BTreeMap::new(),
            creators: vec!["Streamer".into(), "ArtistAna".into(), "GamerGus".into()],
            epoch: 0,
            blobs: Vec::new(),
            checkpoints: 0,
            withdrawn: 0,
            activity: Vec::new(),
        };
        d.add(ME);
        let creators = d.creators.clone();
        for c in &creators {
            d.add(c);
        }
        d.log("Welcome. Add funds to start tipping creators.".into());
        d
    }

    fn add(&mut self, name: &str) {
        self.accounts
            .entry(name.to_string())
            .or_insert_with(|| Account::new(pool_id(), CHAIN_ID, account_secret(name)));
    }
    fn key(&self, name: &str) -> Option<Hash> {
        self.accounts.get(name).map(|a| a.key())
    }
    fn balance(&self, name: &str) -> u128 {
        self.key(name).map(|k| self.seq.state().get_leaf(&k).balance).unwrap_or(0)
    }
    fn log(&mut self, m: String) {
        self.activity.push(m);
    }

    /// Settle the mempool into a checkpoint, the real `seal_batch`. On Pudge the same transition is
    /// proven and verified on-chain; here it is instant so the journey flows.
    fn settle(&mut self) -> Result<(), String> {
        if self.seq.pending() == 0 {
            return Ok(());
        }
        let job = self.seq.seal_batch(self.epoch, 0).map_err(|e| format!("{e:?}"))?;
        self.epoch += 1;
        self.blobs.push(job.da_blob.clone());
        self.checkpoints += 1;
        Ok(())
    }

    fn deposit(&mut self, amount: u128) -> Result<(), String> {
        if amount == 0 {
            return Err("enter an amount".into());
        }
        let key = self.key(ME).ok_or("no account")?;
        self.seq.submit_deposit(Deposit { to_key: key, amount });
        self.settle()?;
        self.log(format!("You added {} CKB to your wallet.", amount as f64 / CKB));
        Ok(())
    }

    fn tip(&mut self, to: &str, amount: u128) -> Result<(), String> {
        let to_key = self.key(to).ok_or("unknown creator")?;
        let fee = to_shannons(0.001);
        if self.balance(ME) < amount + fee {
            return Err("not enough balance, add funds first".into());
        }
        let t = self.accounts.get_mut(ME).unwrap().transfer(to_key, amount, fee, EXPIRY);
        self.seq.submit_transfer(t);
        self.settle()?;
        self.log(format!("You tipped {to} {} CKB.", amount as f64 / CKB));
        Ok(())
    }

    fn withdraw(&mut self, amount: u128) -> Result<(), String> {
        if amount == 0 {
            return Err("enter an amount".into());
        }
        if self.balance(ME) < amount {
            return Err("you cannot withdraw more than your balance".into());
        }
        let target = wallet_lock(ME);
        let w = self.accounts.get_mut(ME).unwrap().withdraw(target, amount, EXPIRY);
        self.seq.submit_withdrawal(w);
        self.settle()?;
        self.withdrawn += amount;
        self.log(format!("You withdrew {} CKB to your own CKB wallet.", amount as f64 / CKB));
        Ok(())
    }

    fn state(&self) -> Value {
        let creators: Vec<Value> = self
            .creators
            .iter()
            .map(|c| json!({"name": c, "role": role(c), "earnedCkb": self.balance(c) as f64 / CKB}))
            .collect();
        let mut act = self.activity.clone();
        act.reverse(); // newest first
        json!({
            "you": { "balanceCkb": self.balance(ME) as f64 / CKB, "withdrawnCkb": self.withdrawn as f64 / CKB },
            "creators": creators,
            "activity": act,
            "underHood": {
                "root": hexs(&self.seq.root()),
                "seq": self.seq.seq(),
                "poolTotalCkb": self.seq.total() as f64 / CKB,
                "feesCkb": self.seq.fee_acc() as f64 / CKB,
                "checkpoints": self.checkpoints,
            }
        })
    }

    /// One friendly trust check for `name`: rebuild the balance from L1 data alone (no operator),
    /// verify the inclusion proof against the committed root, and confirm a valid escape-hatch
    /// (force-exit) witness exists. This is the consumer-facing form of the real trust guarantees.
    fn safety(&self, name: &str) -> Result<Value, String> {
        let key = self.key(name).ok_or("unknown account")?;
        if self.balance(name) == 0 {
            return Ok(json!({"empty": true, "balanceCkb": 0.0}));
        }
        let (leaf, siblings) = proof_from_da(&self.blobs, &key).ok_or("no data yet")?;
        let recovered = verify_proof(&self.seq.root(), &key, &leaf.hash(), &siblings)
            && leaf == self.seq.state().get_leaf(&key);
        let witness = self.accounts.get(name).and_then(|a| a.force_exit_witness(&self.blobs));
        Ok(json!({
            "empty": false,
            "balanceCkb": leaf.balance as f64 / CKB,
            "recoveredFromL1": recovered,
            "escapeHatchBytes": witness.as_ref().map(|w| w.len()).unwrap_or(0),
            "escapeHatchValid": witness.is_some() && recovered,
            "root": hexs(&self.seq.root()),
        }))
    }
}

fn body(req: &mut tiny_http::Request) -> Value {
    let mut s = String::new();
    let _ = req.as_reader().read_to_string(&mut s);
    serde_json::from_str(&s).unwrap_or(Value::Null)
}
fn num(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0)
}
fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn jr(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    Response::from_string(v.to_string()).with_header(h)
}
fn res<T, E: std::fmt::Display>(r: Result<T, E>) -> Response<std::io::Cursor<Vec<u8>>> {
    match r {
        Ok(_) => jr(json!({"ok": true})),
        Err(e) => jr(json!({"error": e.to_string()})),
    }
}

fn main() {
    let addr = "0.0.0.0:8088";
    let server = Server::http(addr).expect("bind");
    let demo = Mutex::new(Demo::new());
    println!("Liquid Cells demo running, open http://127.0.0.1:8088");

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let query = url.split('?').nth(1).unwrap_or("").to_string();

        let resp = match (&method, path.as_str()) {
            (Method::Get, "/") => {
                let h =
                    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                req.respond(Response::from_string(include_str!("index.html")).with_header(h)).ok();
                continue;
            }
            (Method::Get, "/api/state") => jr(demo.lock().unwrap().state()),
            (Method::Post, "/api/reset") => {
                *demo.lock().unwrap() = Demo::new();
                jr(json!({"ok": true}))
            }
            (Method::Post, "/api/deposit") => {
                let b = body(&mut req);
                res(demo.lock().unwrap().deposit(to_shannons(num(&b, "ckb"))))
            }
            (Method::Post, "/api/tip") => {
                let b = body(&mut req);
                res(demo.lock().unwrap().tip(&str_of(&b, "to"), to_shannons(num(&b, "ckb"))))
            }
            (Method::Post, "/api/withdraw") => {
                let b = body(&mut req);
                res(demo.lock().unwrap().withdraw(to_shannons(num(&b, "ckb"))))
            }
            (Method::Get, "/api/safety") => {
                let name = query.strip_prefix("name=").unwrap_or(ME);
                let name = if name.is_empty() { ME } else { name };
                match demo.lock().unwrap().safety(name) {
                    Ok(v) => jr(v),
                    Err(e) => jr(json!({"error": e})),
                }
            }
            _ => jr(json!({"error": "not found"})),
        };
        req.respond(resp).ok();
    }
}
