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
use tiny_http::{Header, Method, Response, Server};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
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

    let mut svc = Service::genesis(pool_id, chain_id);
    let server = Server::http(format!("0.0.0.0:{port}")).unwrap_or_else(|e| panic!("bind :{port}: {e}"));
    println!("lc-sequencer-service on http://127.0.0.1:{port}");
    println!("pool_id 0x{}  chain_id 0x{:x}", hex::encode(pool_id), chain_id);

    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let url = req.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);

        let result: Result<Value, String> = match (&method, path.as_str()) {
            (Method::Get, "/") | (Method::Get, "/info") => Ok(svc.info()),
            (Method::Post, "/submit") => svc.submit(&body),
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
            Err(e) => (if e.starts_with("no route") { 404 } else { 400 }, json!({ "error": e }).to_string()),
        };
        println!("{method} {path} -> {code}");
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let _ = req.respond(Response::from_string(payload).with_status_code(code).with_header(header));
    }
}
