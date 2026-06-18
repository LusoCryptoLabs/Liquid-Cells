//! `lc-exit`, reconstruct your Liquid Cells balance from L1 alone and build a force-exit witness,
//! **without the sequencer**. This is the runnable proof that the escape hatch works end-to-end:
//! it scrapes the pool's checkpoint chain from a CKB RPC (via the indexer), folds the published DA
//! blobs through the canonical `liquid_cells_stf::reconstruct`, checks the rebuilt root equals the
//! live on-chain anchor, and emits the exact `force-exit` witness bytes the anchor type script
//! consumes. No trust in the operator: only L1 data + your key.
//!
//! Build:  cargo build -p liquid-cells-client --features cli --release
//! Usage:  lc-exit --code-hash <0x..> --args <0x..pool-type-id..> --secret <0x..32B> [--rpc URL] [--key <0x..32B>]
//!   --code-hash  anchor type-script code hash (default: the deployed anchor)
//!   --args       anchor type-script args = the pool's type-id (empty "0x" for a legacy baked-POOL_ID pool)
//!   --secret     your 32-byte account secret (derives pubkey+key, builds the full force-exit witness)
//!   --key        OR your 32-byte SMT key, read-only (balance + inclusion proof, no signed-payout witness)
//!   --rpc        CKB JSON-RPC + indexer endpoint (default: https://testnet.ckb.dev)

use liquid_cells_client::{proof_from_da, reconstruct_tree, Account, FORCE_EXIT_WITNESS_LEN};
use liquid_cells_stf::{key_of_pubkey, sig, Hash, Leaf};
use serde_json::{json, Value};

/// blake160(data) = first 20 bytes of CKB's default blake2b-256 (the secp lock's args).
fn blake160(data: &[u8]) -> [u8; 20] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..20]);
    r
}

const DEFAULT_RPC: &str = "https://testnet.ckb.dev";
const DEFAULT_CODE_HASH: &str = "0x83158549bb5b2241997d1e8bb5e24b432a78e74473c8601cea276411bca99f1e";

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn hexdec(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("invalid hex")
}
fn h32(v: &[u8]) -> Hash {
    let mut a = [0u8; 32];
    a.copy_from_slice(&v[..32]);
    a
}
fn u32le(b: &[u8]) -> usize {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
}

/// Extract `output_type` (the DA blob) from a WitnessArgs molecule (table of 3 BytesOpt:
/// lock, input_type, output_type). Returns None if output_type is absent/empty.
fn witness_output_type(w: &[u8]) -> Option<Vec<u8>> {
    if w.len() < 16 {
        return None;
    }
    let total = u32le(&w[0..4]);
    let off_output = u32le(&w[12..16]); // 3rd field offset
    if off_output >= total || off_output + 4 > w.len() {
        return None;
    }
    let field = &w[off_output..total.min(w.len())];
    let len = u32le(&field[0..4]);
    if 4 + len > field.len() {
        return None;
    }
    Some(field[4..4 + len].to_vec())
}

fn agent() -> ureq::Agent {
    // native-tls (OpenSSL) → honors the system CA store, so this works through TLS-intercepting
    // egress proxies (unlike rustls' bundled roots).
    let tls = native_tls::TlsConnector::new().expect("native-tls");
    ureq::AgentBuilder::new().tls_connector(std::sync::Arc::new(tls)).build()
}

fn rpc(ag: &ureq::Agent, url: &str, method: &str, params: Value) -> Value {
    let body = json!({"id": 1, "jsonrpc": "2.0", "method": method, "params": params});
    let resp = ag
        .post(url)
        .set("content-type", "application/json")
        .send_string(&body.to_string())
        .unwrap_or_else(|e| panic!("rpc {method} failed: {e}"));
    let v: Value = serde_json::from_str(&resp.into_string().expect("read rpc body")).expect("rpc json");
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        panic!("rpc {method} error: {err}");
    }
    v["result"].clone()
}

fn main() {
    let rpc_url = arg("--rpc").unwrap_or_else(|| DEFAULT_RPC.to_string());
    let code_hash = arg("--code-hash").unwrap_or_else(|| DEFAULT_CODE_HASH.to_string());
    let args = arg("--args").unwrap_or_else(|| "0x".to_string());
    let ag = agent();
    let script = json!({"code_hash": code_hash, "hash_type": "type", "args": args});

    // key to recover: from --secret (full witness) or --key (read-only)
    let secret = arg("--secret").map(|s| h32(&hexdec(&s)));
    let key: Hash = match (&secret, arg("--key")) {
        (Some(sk), _) => key_of_pubkey(&sig::pubkey(sk)),
        (None, Some(k)) => h32(&hexdec(&k)),
        (None, None) => {
            eprintln!("error: provide --secret <0x..32B> (full witness) or --key <0x..32B> (read-only)");
            std::process::exit(2);
        }
    };

    // 1. live anchor cell (its data root is the ground truth to check our reconstruction against)
    let cells = rpc(&ag, &rpc_url, "get_cells", json!([{"script": script, "script_type": "type"}, "asc", "0x10", null]));
    let objs = cells["objects"].as_array().cloned().unwrap_or_default();
    if objs.is_empty() {
        eprintln!("error: no live anchor cell for that type script (wrong code_hash/args, or pool spent?)");
        std::process::exit(1);
    }
    let live = &objs[objs.len() - 1];
    let onchain_data = hexdec(live["output_data"].as_str().unwrap());
    let onchain_root = h32(&onchain_data[0..32]);
    let onchain_seq = u64::from_be_bytes(onchain_data[32..40].try_into().unwrap());
    println!("live anchor : {}:{}", live["out_point"]["tx_hash"].as_str().unwrap(), live["out_point"]["index"].as_str().unwrap());
    println!("on-chain    : root=0x{} seq={onchain_seq}", hex::encode(onchain_root));

    // 2. every checkpoint tx touching this anchor type, oldest-first (genesis first)
    let txs = rpc(&ag, &rpc_url, "get_transactions", json!([{"script": script, "script_type": "type"}, "asc", "0x200", null]));
    let mut ordered: Vec<String> = Vec::new();
    for o in txs["objects"].as_array().cloned().unwrap_or_default() {
        let h = o["tx_hash"].as_str().unwrap().to_string();
        if ordered.last() != Some(&h) {
            ordered.push(h);
        }
    }

    // 3. pull each checkpoint's DA blob from witness[0].output_type (genesis has none -> skipped)
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for tx_hash in &ordered {
        let t = rpc(&ag, &rpc_url, "get_transaction", json!([tx_hash]));
        let ws = t["transaction"]["witnesses"].as_array().cloned().unwrap_or_default();
        if let Some(w0) = ws.first().and_then(|w| w.as_str()) {
            if let Some(blob) = witness_output_type(&hexdec(w0)) {
                blobs.push(blob);
            }
        }
    }
    println!("checkpoints : {} tx(s), {} DA blob(s) folded", ordered.len(), blobs.len());

    // 4. reconstruct from L1 alone and verify the root matches the live anchor
    let smt = reconstruct_tree(&blobs).expect("reconstruct: malformed DA blob");
    let recon_root = smt.root();
    let ok = recon_root == onchain_root;
    println!("reconstructed: root=0x{}  [{}]", hex::encode(recon_root), if ok { "MATCH" } else { "MISMATCH, DA withholding/corruption!" });

    // 5. your leaf + inclusion proof + the force-exit witness
    let (leaf, _siblings) = proof_from_da(&blobs, &key).expect("proof_from_da");
    println!("your key    : 0x{}", hex::encode(key));
    println!("your balance: {} shannons ({} CKB), nonce {}", leaf.balance, leaf.balance as f64 / 1e8, leaf.nonce);
    if let Some(sk) = secret {
        match Account::new([0u8; 32], 0, sk).force_exit_witness(&blobs) {
            Some(w) => {
                // Deployed (depth-256) witness is the fixed FORCE_EXIT_WITNESS_LEN; under `compact_smt`
                // it is SPARSE (a 1-byte tag + bitmap + only the non-empty siblings), so its length is
                // variable and a fixed-length assert is wrong (v2 re-bake finding).
                #[cfg(not(feature = "compact_smt"))]
                assert_eq!(w.len(), FORCE_EXIT_WITNESS_LEN);
                println!("force-exit witness ({} bytes): 0x{}", w.len(), hex::encode(&w));
                println!("=> submit a force-exit tx consuming the live anchor with this as witness[0].input_type,");
                println!("   paying {} shannons to your secp256k1_blake160 lock (args=blake160(pubkey)).", leaf.balance);
                // The output (nullified) anchor root: same tree with this leaf emptied (balance->0,
                // nonce kept), computed via the canonical STF so the submitter need not reimplement it.
                let mut smt2 = reconstruct_tree(&blobs).expect("reconstruct");
                smt2.set_leaf_hash(key, Leaf { balance: 0, nonce: leaf.nonce }.hash());
                let nullified_root = smt2.root();
                let pubkey = sig::pubkey(&sk);
                let b160 = blake160(&pubkey);
                println!(
                    "FORCEEXIT_JOB={}",
                    json!({
                        "witness": format!("0x{}", hex::encode(&w)),
                        "nullifiedRoot": format!("0x{}", hex::encode(nullified_root)),
                        "payoutB160": format!("0x{}", hex::encode(b160)),
                        "balance": leaf.balance.to_string(),
                        "nonce": leaf.nonce,
                    })
                );
            }
            None => println!("(zero balance, nothing to exit)"),
        }
    }
    if !ok {
        std::process::exit(3);
    }
}
