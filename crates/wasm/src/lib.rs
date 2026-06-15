//! # liquid-cells-wasm
//!
//! The Liquid Cells client SDK for the browser / JavaScript, a thin `wasm-bindgen` skin over
//! [`liquid_cells_client`], which is itself a thin skin over the canonical [`liquid_cells_stf`].
//!
//! The point of compiling (rather than reimplementing) the STF to WebAssembly is the same
//! "one STF, no divergence" discipline the whole protocol rests on: a JS client signs over the
//! EXACT canonical byte layouts and rebuilds the EXACT keccak SMT the sequencer seals and the
//! on-chain contract verifies. A hand-written JS reimplementation would reintroduce the
//! "divergent root" class of bug; this cannot, the bytes come from the same Rust.
//!
//! ## Conventions at the JS boundary
//!   * 32-byte values (pool id, SMT key, hashlock, lock hash) and the 33-byte pubkey / 64-byte
//!     signature cross as `0x`-prefixed hex strings.
//!   * `u128` amounts cross as **decimal strings** (JS numbers cannot hold 128 bits).
//!   * Signed intents are returned as **JSON strings** (all fields hex / decimal-string), the shape
//!     a JS app submits to a sequencer. DA blobs are passed in as a JSON array of hex strings.
//!
//! ```ignore
//! import init, { WasmAccount, reconstruct_root } from "liquid-cells-wasm";
//! await init();
//! const alice = new WasmAccount(poolIdHex, 0x434b42, secretHex);
//! const transfer = JSON.parse(alice.transfer(bobKeyHex, "1000", "10", 100)); // signed, submit to sequencer
//! const root = reconstruct_root(JSON.stringify(daBlobsHex));                 // check vs on-chain anchor
//! ```

use liquid_cells_client::{htlc_claim as build_claim, htlc_refund as build_refund, proof_from_da, reconstruct_tree, Account};
use liquid_cells_client::swap::swap_hashlock as sha256_hashlock;
use liquid_cells_stf::{Hash, HtlcLock, HtlcRef, Transfer, Withdrawal};
use wasm_bindgen::prelude::*;

// --- pure helpers (tested natively) --------------------------------------------------------------

fn hexs(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn parse_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("invalid hex: {e}"))
}

fn parse_hash(s: &str) -> Result<Hash, String> {
    let v = parse_bytes(s)?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&v);
    Ok(h)
}

fn parse_secret(s: &str) -> Result<[u8; 32], String> {
    parse_hash(s) // 32-byte secret key, same shape
}

fn parse_u128(s: &str) -> Result<u128, String> {
    s.trim().parse::<u128>().map_err(|e| format!("invalid u128 '{s}': {e}"))
}

/// Parse DA blobs from a JSON array of hex strings (oldest-first), e.g. `["0x..","0x.."]`.
fn parse_blobs(json: &str) -> Result<Vec<Vec<u8>>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("blobs json: {e}"))?;
    let arr = v.as_array().ok_or("blobs must be a JSON array of hex strings")?;
    arr.iter()
        .map(|x| x.as_str().ok_or_else(|| "blob entry not a string".to_string()).and_then(parse_bytes))
        .collect()
}

fn transfer_json(t: &Transfer) -> String {
    serde_json::json!({
        "type": "transfer",
        "from_pubkey": hexs(&t.from_pubkey),
        "to_key": hexs(&t.to_key),
        "amount": t.amount.to_string(),
        "fee": t.fee.to_string(),
        "nonce": t.nonce,
        "expiry": t.expiry,
        "sig": hexs(&t.sig),
    })
    .to_string()
}

fn withdrawal_json(w: &Withdrawal) -> String {
    serde_json::json!({
        "type": "withdrawal",
        "from_pubkey": hexs(&w.from_pubkey),
        "target_lock_hash": hexs(&w.target_lock_hash),
        "amount": w.amount.to_string(),
        "nonce": w.nonce,
        "expiry": w.expiry,
        "sig": hexs(&w.sig),
    })
    .to_string()
}

fn htlcref_value(r: &HtlcRef) -> serde_json::Value {
    serde_json::json!({
        "sender_key": hexs(&r.sender_key),
        "receiver_key": hexs(&r.receiver_key),
        "amount": r.amount.to_string(),
        "hashlock": hexs(&r.hashlock),
        "timeout": r.timeout,
        "lock_nonce": r.lock_nonce,
    })
}

fn htlclock_json(l: &HtlcLock, r: &HtlcRef) -> String {
    serde_json::json!({
        "type": "htlc_lock",
        "sender_pubkey": hexs(&l.sender_pubkey),
        "receiver_key": hexs(&l.receiver_key),
        "amount": l.amount.to_string(),
        "fee": l.fee.to_string(),
        "hashlock": hexs(&l.hashlock),
        "timeout": l.timeout,
        "nonce": l.nonce,
        "sig": hexs(&l.sig),
        "htlc_ref": htlcref_value(r), // the terms the holder later claims/refunds against
    })
    .to_string()
}

fn parse_htlcref(json: &str) -> Result<HtlcRef, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("htlc_ref json: {e}"))?;
    let g = |k: &str| -> Result<&serde_json::Value, String> { v.get(k).ok_or(format!("htlc_ref missing '{k}'")) };
    let gs = |k: &str| -> Result<String, String> { Ok(g(k)?.as_str().ok_or(format!("htlc_ref '{k}' not a string"))?.to_string()) };
    let gu = |k: &str| -> Result<u64, String> { g(k)?.as_u64().ok_or(format!("htlc_ref '{k}' not a u64")) };
    Ok(HtlcRef {
        sender_key: parse_hash(&gs("sender_key")?)?,
        receiver_key: parse_hash(&gs("receiver_key")?)?,
        amount: parse_u128(&gs("amount")?)?,
        hashlock: parse_hash(&gs("hashlock")?)?,
        timeout: gu("timeout")?,
        lock_nonce: gu("lock_nonce")?,
    })
}

fn claim_json(htlc: &HtlcRef, preimage: &[u8]) -> String {
    let c = build_claim(*htlc, preimage.to_vec());
    serde_json::json!({
        "type": "htlc_claim",
        "htlc_ref": htlcref_value(&c.htlc),
        "preimage": hexs(&c.preimage),
    })
    .to_string()
}

fn refund_json(htlc: &HtlcRef) -> String {
    let r = build_refund(*htlc);
    serde_json::json!({ "type": "htlc_refund", "htlc_ref": htlcref_value(&r.htlc) }).to_string()
}

fn err(e: String) -> JsError {
    JsError::new(&e)
}

// --- the JS-facing API ---------------------------------------------------------------------------

/// A Liquid Cells account in the browser: hold a secret, sign intents, track the local nonce, and
/// recover from L1. Wraps [`liquid_cells_client::Account`].
#[wasm_bindgen]
pub struct WasmAccount {
    inner: Account,
}

#[wasm_bindgen]
impl WasmAccount {
    /// Derive an account from a 32-byte `secret_hex`, scoped to `(pool_id_hex, chain_id)`. The nonce
    /// starts at 0, call [`sync_from_da`](Self::sync_from_da) (or [`set_nonce`](Self::set_nonce)) to
    /// align with L1 before signing.
    #[wasm_bindgen(constructor)]
    pub fn new(pool_id_hex: &str, chain_id: u64, secret_hex: &str) -> Result<WasmAccount, JsError> {
        let pool_id = parse_hash(pool_id_hex).map_err(err)?;
        let secret = parse_secret(secret_hex).map_err(err)?;
        Ok(WasmAccount { inner: Account::new(pool_id, chain_id, secret) })
    }

    /// The account's SMT key (`keccak(pubkey)`), where others address payments. `0x`-hex.
    pub fn key(&self) -> String {
        hexs(&self.inner.key())
    }
    /// The compressed secp256k1 public key. `0x`-hex (33 bytes).
    pub fn pubkey(&self) -> String {
        hexs(&self.inner.pubkey())
    }
    /// The CKB `secp256k1_blake160` lock args (`blake160(pubkey)`), the only lock a force-exit /
    /// force-refund of this account may pay to. `0x`-hex (20 bytes).
    pub fn ckb_lock_args(&self) -> String {
        hexs(&self.inner.ckb_lock_args())
    }
    pub fn nonce(&self) -> u64 {
        self.inner.nonce()
    }
    pub fn set_nonce(&mut self, nonce: u64) {
        self.inner.set_nonce(nonce);
    }

    /// Build and sign a transfer of `amount` (+ `fee`, both decimal strings) to `to_key_hex`, valid
    /// through `expiry`. Advances the local nonce. Returns the signed intent as a JSON string.
    pub fn transfer(&mut self, to_key_hex: &str, amount: &str, fee: &str, expiry: u64) -> Result<String, JsError> {
        let to = parse_hash(to_key_hex).map_err(err)?;
        let t = self.inner.transfer(to, parse_u128(amount).map_err(err)?, parse_u128(fee).map_err(err)?, expiry);
        Ok(transfer_json(&t))
    }

    /// Build and sign a withdrawal of `amount` to the on-chain `target_lock_hash_hex`, valid through
    /// `expiry`. Advances the local nonce. Returns the signed intent as a JSON string.
    pub fn withdraw(&mut self, target_lock_hash_hex: &str, amount: &str, expiry: u64) -> Result<String, JsError> {
        let target = parse_hash(target_lock_hash_hex).map_err(err)?;
        let w = self.inner.withdraw(target, parse_u128(amount).map_err(err)?, expiry);
        Ok(withdrawal_json(&w))
    }

    /// Build and sign an HTLC lock escrowing `amount` (+ `fee`) to `receiver_key_hex` under
    /// `hashlock_hex` until `timeout`. Advances the local nonce. The returned JSON includes the
    /// `htlc_ref` terms to later claim or refund against (pass them to [`htlc_claim`]/[`htlc_refund`]).
    pub fn htlc_lock(
        &mut self,
        receiver_key_hex: &str,
        amount: &str,
        fee: &str,
        hashlock_hex: &str,
        timeout: u64,
    ) -> Result<String, JsError> {
        let receiver = parse_hash(receiver_key_hex).map_err(err)?;
        let hashlock = parse_hash(hashlock_hex).map_err(err)?;
        let (lock, r) =
            self.inner.htlc_lock(receiver, parse_u128(amount).map_err(err)?, parse_u128(fee).map_err(err)?, hashlock, timeout);
        Ok(htlclock_json(&lock, &r))
    }

    /// Recover this account's `{balance, nonce}` from L1 DA (`blobs_json` = JSON array of hex,
    /// oldest-first) and resync the local nonce. Returns `{ "balance": "..", "nonce": N }`.
    pub fn sync_from_da(&mut self, blobs_json: &str) -> Result<String, JsError> {
        let blobs = parse_blobs(blobs_json).map_err(err)?;
        let lp = self.inner.sync_from_da(&blobs).ok_or_else(|| err("malformed DA blob".into()))?;
        Ok(serde_json::json!({ "balance": lp.leaf.balance.to_string(), "nonce": lp.leaf.nonce }).to_string())
    }

    /// Assemble the **force-exit** witness for this account from L1 DA alone (no sequencer): the exact
    /// `input_type` bytes the anchor type script's force-exit mode consumes. `0x`-hex, or an error if
    /// the balance is zero / a blob is malformed.
    pub fn force_exit_witness(&self, blobs_json: &str) -> Result<String, JsError> {
        let blobs = parse_blobs(blobs_json).map_err(err)?;
        let w = self.inner.force_exit_witness(&blobs).ok_or_else(|| err("no balance to exit / malformed blob".into()))?;
        Ok(hexs(&w))
    }

    /// Assemble the **force-refund** witness for a timed-out HTLC this account sent (`htlc_ref_json`
    /// from [`htlc_lock`](Self::htlc_lock)). `0x`-hex `input_type` for the contract's force-refund
    /// mode, or an error if it is not this account's escrow / not present / malformed.
    pub fn force_refund_witness(&self, blobs_json: &str, htlc_ref_json: &str) -> Result<String, JsError> {
        let blobs = parse_blobs(blobs_json).map_err(err)?;
        let r = parse_htlcref(htlc_ref_json).map_err(err)?;
        let w = self.inner.force_refund_witness(&blobs, &r).ok_or_else(|| err("not your escrow / not present".into()))?;
        Ok(hexs(&w))
    }
}

/// `H = sha256(secret)`, the Fiber-compatible swap hashlock both legs lock to. `secret_hex` in,
/// `0x`-hex `H` out.
#[wasm_bindgen]
pub fn swap_hashlock_sha256(secret_hex: &str) -> Result<String, JsError> {
    let s = parse_bytes(secret_hex).map_err(err)?;
    Ok(hexs(&sha256_hashlock(&s)))
}

/// Rebuild the SMT root from the published DA blobs (`blobs_json` = JSON array of hex, oldest-first),
/// the trust-minimised check: it must equal the live on-chain anchor root, else the operator withheld
/// or corrupted data. `0x`-hex root.
#[wasm_bindgen]
pub fn reconstruct_root(blobs_json: &str) -> Result<String, JsError> {
    let blobs = parse_blobs(blobs_json).map_err(err)?;
    let smt = reconstruct_tree(&blobs).ok_or_else(|| err("malformed DA blob".into()))?;
    Ok(hexs(&smt.root()))
}

/// Recover `key_hex`'s `{balance, nonce}` from L1 DA alone. Returns `{ "balance": "..", "nonce": N }`.
#[wasm_bindgen]
pub fn leaf_from_da(blobs_json: &str, key_hex: &str) -> Result<String, JsError> {
    let blobs = parse_blobs(blobs_json).map_err(err)?;
    let key = parse_hash(key_hex).map_err(err)?;
    let (leaf, _siblings) = proof_from_da(&blobs, &key).ok_or_else(|| err("malformed DA blob".into()))?;
    Ok(serde_json::json!({ "balance": leaf.balance.to_string(), "nonce": leaf.nonce }).to_string())
}

/// Build an (unsigned) HTLC claim revealing `preimage_hex`, against `htlc_ref_json`. The receiver is
/// fixed by the escrow's `htlc_id`, so knowledge of the preimage is the only authority. JSON out.
#[wasm_bindgen]
pub fn htlc_claim(htlc_ref_json: &str, preimage_hex: &str) -> Result<String, JsError> {
    let r = parse_htlcref(htlc_ref_json).map_err(err)?;
    let preimage = parse_bytes(preimage_hex).map_err(err)?;
    Ok(claim_json(&r, &preimage))
}

/// Build an (unsigned) HTLC refund for a timed-out escrow `htlc_ref_json`. The sender is fixed by
/// `htlc_id`; the timeout is the authority. JSON out.
#[wasm_bindgen]
pub fn htlc_refund(htlc_ref_json: &str) -> Result<String, JsError> {
    let r = parse_htlcref(htlc_ref_json).map_err(err)?;
    Ok(refund_json(&r))
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const SECRET: &str = "0x0000000000000000000000000000000000000000000000000000000000000007";

    fn acct() -> WasmAccount {
        WasmAccount::new(POOL, 0x434b_42, SECRET).unwrap()
    }

    #[test]
    fn account_identity_round_trips() {
        let a = acct();
        // key = keccak(pubkey); both are 0x-hex of the right length.
        assert!(a.key().starts_with("0x") && a.key().len() == 66);
        assert!(a.pubkey().starts_with("0x") && a.pubkey().len() == 68); // 33 bytes
        assert!(a.ckb_lock_args().len() == 42); // 20 bytes
        assert_eq!(a.nonce(), 0);
    }

    #[test]
    fn transfer_is_well_formed_and_advances_nonce() {
        let mut a = acct();
        let to = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let j: serde_json::Value = serde_json::from_str(&a.transfer(to, "1000", "10", 100).unwrap()).unwrap();
        assert_eq!(j["type"], "transfer");
        assert_eq!(j["to_key"], to);
        assert_eq!(j["amount"], "1000");
        assert_eq!(j["fee"], "10");
        assert_eq!(j["nonce"], 0);
        assert_eq!(j["sig"].as_str().unwrap().len(), 130); // 0x + 64 bytes
        assert_eq!(a.nonce(), 1, "nonce advanced locally");
    }

    #[test]
    fn htlc_lock_round_trips_through_ref_to_claim_and_refund() {
        let mut a = acct();
        let recv = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let hl = swap_hashlock_sha256("0xdeadbeef").unwrap();
        let locked: serde_json::Value =
            serde_json::from_str(&a.htlc_lock(recv, "5000", "1", &hl, 50).unwrap()).unwrap();
        assert_eq!(locked["type"], "htlc_lock");
        let r = locked["htlc_ref"].to_string();
        // The ref parses back and builds a claim + refund.
        let c: serde_json::Value = serde_json::from_str(&htlc_claim(&r, "0xdeadbeef").unwrap()).unwrap();
        assert_eq!(c["type"], "htlc_claim");
        assert_eq!(c["preimage"], "0xdeadbeef");
        let rf: serde_json::Value = serde_json::from_str(&htlc_refund(&r).unwrap()).unwrap();
        assert_eq!(rf["type"], "htlc_refund");
    }

    #[test]
    fn swap_hashlock_matches_sha256() {
        // H = sha256("liquid-cells") computed independently.
        let h = swap_hashlock_sha256(&hexs(b"liquid-cells")).unwrap();
        assert_eq!(h, hexs(&sha256_hashlock(b"liquid-cells")));
    }

    #[test]
    fn bad_inputs_error_cleanly() {
        // The error paths surface JsError, which cannot be constructed off-wasm, so assert the pure
        // parsers (the actual validators) reject malformed input; the wasm methods just wrap these.
        assert!(parse_hash("0xzz").is_err()); // bad hex
        assert!(parse_hash("0x00").is_err()); // wrong length (1 byte, not 32)
        assert!(parse_secret("0x00").is_err()); // secret wrong length
        assert!(parse_u128("not-a-number").is_err()); // bad amount
        assert!(parse_blobs("not json").is_err());
        assert!(parse_blobs("{}").is_err()); // not an array
        assert!(parse_htlcref("{}").is_err()); // missing fields
    }
}
