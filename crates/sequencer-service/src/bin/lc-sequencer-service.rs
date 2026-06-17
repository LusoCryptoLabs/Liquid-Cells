//! `lc-sequencer-service`: run the Liquid Cells sequencer behind a tiny HTTP front, so a client (the
//! WASM SDK, `curl`, anything) can submit signed intents and seal checkpoints over the wire.
//!
//! Endpoints (all JSON):
//!   GET  /            | /info        pool identity + committed state (seq, root, total, pending)
//!   POST /submit                     body = a tagged intent JSON (the SDK `wire` encoding)
//!   POST /seal                       body = { "current_epoch": N, "fee_withdrawal": "0" }
//!   GET  /leaf?key=0x..              a key's { balance, nonce } from the committed state
//!   GET  /da                         every published DA blob (0x-hex), for trustless reconstruct
//!
//! Single-threaded (one request at a time), which is all a local/demo sequencer needs; the heavy
//! Groth16 proving + Pudge submission of a sealed checkpoint stays the separate driver it already is.
//!
//! Build/run:  cargo run -p liquid-cells-sequencer-service --bin lc-sequencer-service -- --port 8910

use liquid_cells_sequencer_service::Service;
use liquid_cells_stf::{keccak, Hash};
use serde_json::{json, Value};
use std::io::Read;
use tiny_http::{Header, Method, Response, Server};

/// Maximum accepted request body. Intents are small (a few hundred bytes); a cap stops a multi-GB
/// body OOM-ing the single-process service.
const MAX_BODY: u64 = 64 * 1024;

/// Default operator fee-admission floor (M-3): reject `/submit` intents paying below this. `1` rejects
/// only literal zero-fee griefing (the disabled-by-default finding) while admitting any paying intent,
/// and it matches the staged provable floor `liquid_cells_stf::MIN_FEE_PER_LEAF`. An operator raises
/// it with `--min-fee N` to cover the real per-leaf DA + proving + L1 cost, or `--min-fee 0` to
/// disable. This is the LIVE economic backstop until the `min_fee` re-bake makes the floor unforgeable.
const DEFAULT_MIN_FEE: u128 = 1;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

fn parse_hash(s: &str) -> Option<Hash> {
    let v = hex::decode(s.trim_start_matches("0x")).ok()?;
    (v.len() == 32).then(|| {
        let mut h = [0u8; 32];
        h.copy_from_slice(&v);
        h
    })
}

/// `fee_withdrawal` may arrive as a decimal string or a JSON number; tolerate both.
fn parse_u128_field(v: &Value, key: &str) -> u128 {
    v.get(key)
        .and_then(|x| x.as_str().and_then(|s| s.parse().ok()).or_else(|| x.as_u64().map(|n| n as u128)))
        .unwrap_or(0)
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

fn main() {
    let port: u16 = arg("--port").and_then(|s| s.parse().ok()).unwrap_or(8910);
    let chain_id: u64 = arg("--chain-id")
        .and_then(|s| {
            let t = s.trim_start_matches("0x");
            u64::from_str_radix(t, 16).ok().or_else(|| s.parse().ok())
        })
        .unwrap_or(0x0043_4b42);
    let pool_id: Hash = arg("--pool-id").and_then(|s| parse_hash(&s)).unwrap_or_else(|| keccak(b"lc-service-pool"));
    // Deposits are operator-authorized (an on-chain deposit cell), never client-submittable. The
    // /admin/deposit faucet endpoint is exposed only with this explicit opt-in (off by default).
    let allow_deposits = flag("--allow-deposits");
    // M-3: the production driver defaults to a non-zero fee-admission floor (genesis() itself stays at
    // 0 for tests). `--min-fee N` overrides it; 0 disables.
    let min_fee: u128 = arg("--min-fee").and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_MIN_FEE);

    let mut svc = Service::genesis(pool_id, chain_id);
    svc.set_fee_floor(min_fee);
    let server = Server::http(format!("0.0.0.0:{port}")).unwrap_or_else(|e| panic!("bind :{port}: {e}"));
    println!("lc-sequencer-service on http://127.0.0.1:{port}");
    println!(
        "pool_id 0x{}  chain_id 0x{:x}  admin_deposits={allow_deposits}  min_fee={min_fee}  max_pending={}",
        hex::encode(pool_id), chain_id, liquid_cells_sequencer_service::MAX_PENDING
    );

    let header = || Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();

        // L-5: reject an over-cap declared Content-Length BEFORE reading the body, so a giant body is
        // refused without consuming it. (The read below is still capped in case the header lies.)
        let declared = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Content-Length"))
            .and_then(|h| h.value.as_str().parse::<u64>().ok());
        if declared.is_some_and(|n| n > MAX_BODY) {
            println!("{method} {path} -> 413 (declared body too large)");
            let payload = json!({ "error": "request body too large" }).to_string();
            let _ = req.respond(Response::from_string(payload).with_status_code(413).with_header(header()));
            continue;
        }

        // Read the body with a hard cap so a giant body cannot OOM the process.
        let mut body = String::new();
        let _ = req.as_reader().take(MAX_BODY + 1).read_to_string(&mut body);
        if body.len() as u64 > MAX_BODY {
            println!("{method} {path} -> 413 (body too large)");
            let payload = json!({ "error": "request body too large" }).to_string();
            let _ = req.respond(Response::from_string(payload).with_status_code(413).with_header(header()));
            continue;
        }

        let result: Result<Value, String> = match (&method, path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/info") => Ok(svc.info()),
            (Method::Post, "/submit") => svc.submit(&body),
            (Method::Post, "/admin/deposit") => {
                if allow_deposits {
                    svc.admin_deposit(&body)
                } else {
                    Err("forbidden: start the service with --allow-deposits to enable the deposit faucet".to_string())
                }
            }
            (Method::Post, "/seal") => {
                let v: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
                let epoch = v.get("current_epoch").and_then(|x| x.as_u64()).unwrap_or(1);
                svc.seal(epoch, parse_u128_field(&v, "fee_withdrawal"))
            }
            (Method::Get, "/leaf") => match query_param(&url, "key") {
                Some(k) => svc.leaf(&k),
                None => Err("missing ?key=0x..".to_string()),
            },
            (Method::Get, "/da") => Ok(svc.da()),
            _ => Err(format!("no route for {} {}", method, path)),
        };

        let (code, payload) = match &result {
            Ok(v) => (200, v.to_string()),
            Err(e) => {
                let code = if e.starts_with("no route") {
                    404
                } else if e.starts_with("forbidden") {
                    403
                } else if e.starts_with("overloaded") {
                    429 // L-5: mempool full
                } else if e.starts_with("underpaid") {
                    402 // M-3: fee below the admission floor
                } else {
                    400
                };
                (code, json!({ "error": e }).to_string())
            }
        };
        println!("{method} {path} -> {code}");
        let _ = req.respond(Response::from_string(payload).with_status_code(code).with_header(header()));
    }
}
