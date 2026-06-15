//! Canonical JSON wire format for Liquid Cells intents: the ONE shape a client serializes and a
//! sequencer service parses, defined here once so the two cannot drift. This is the same
//! "one definition, no divergence" discipline the STF rests on, applied to the network boundary:
//! the WASM SDK ([`crate`] compiled to wasm) serializes with these functions, and the sequencer
//! service parses with them, so a malformed or mismatched encoding is impossible by construction.
//!
//! Behind `--features wire` (pulls `serde_json` + `hex`).
//!
//! Conventions: byte values (32-byte keys/hashes, the 33-byte pubkey, 64-byte signatures) are
//! `0x`-hex strings; `u128` amounts are decimal strings (JSON numbers cannot hold 128 bits); `u64`
//! fields (nonce, expiry, timeout) are JSON numbers. Each object carries a `"type"` tag.

use liquid_cells_stf::{Deposit, Hash, HtlcClaim, HtlcLock, HtlcRef, HtlcRefund, Transfer, Withdrawal};
use serde_json::{json, Value};

/// `0x`-hex of a byte slice.
pub fn hexs(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse `0x`-hex (or bare hex) into bytes.
pub fn parse_bytes(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| format!("invalid hex: {e}"))
}

/// Parse a fixed-width `N`-byte hex value (used for the 32-byte hash, 33-byte pubkey, 64-byte sig).
pub fn parse_arr<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = parse_bytes(s)?;
    if v.len() != N {
        return Err(format!("expected {N} bytes, got {}", v.len()));
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Parse a 32-byte hash / key.
pub fn parse_hash(s: &str) -> Result<Hash, String> {
    parse_arr::<32>(s)
}

/// Parse a `u128` amount from a decimal string.
pub fn parse_u128(s: &str) -> Result<u128, String> {
    s.trim().parse::<u128>().map_err(|e| format!("invalid u128 '{s}': {e}"))
}

// --- field accessors over a serde_json object ----------------------------------------------------

fn fstr(v: &Value, k: &str) -> Result<String, String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or(format!("missing/!string field '{k}'"))
}
fn fu64(v: &Value, k: &str) -> Result<u64, String> {
    v.get(k).and_then(|x| x.as_u64()).ok_or(format!("missing/!u64 field '{k}'"))
}
fn fhash(v: &Value, k: &str) -> Result<Hash, String> {
    parse_hash(&fstr(v, k)?)
}
fn fu128(v: &Value, k: &str) -> Result<u128, String> {
    parse_u128(&fstr(v, k)?)
}

// --- Transfer ------------------------------------------------------------------------------------

pub fn transfer_to_value(t: &Transfer) -> Value {
    json!({
        "type": "transfer",
        "from_pubkey": hexs(&t.from_pubkey),
        "to_key": hexs(&t.to_key),
        "amount": t.amount.to_string(),
        "fee": t.fee.to_string(),
        "nonce": t.nonce,
        "expiry": t.expiry,
        "sig": hexs(&t.sig),
    })
}
pub fn transfer_from_value(v: &Value) -> Result<Transfer, String> {
    Ok(Transfer {
        from_pubkey: parse_arr::<33>(&fstr(v, "from_pubkey")?)?,
        to_key: fhash(v, "to_key")?,
        amount: fu128(v, "amount")?,
        fee: fu128(v, "fee")?,
        nonce: fu64(v, "nonce")?,
        expiry: fu64(v, "expiry")?,
        sig: parse_arr::<64>(&fstr(v, "sig")?)?,
    })
}

// --- Withdrawal ----------------------------------------------------------------------------------

pub fn withdrawal_to_value(w: &Withdrawal) -> Value {
    json!({
        "type": "withdrawal",
        "from_pubkey": hexs(&w.from_pubkey),
        "target_lock_hash": hexs(&w.target_lock_hash),
        "amount": w.amount.to_string(),
        "nonce": w.nonce,
        "expiry": w.expiry,
        "sig": hexs(&w.sig),
    })
}
pub fn withdrawal_from_value(v: &Value) -> Result<Withdrawal, String> {
    Ok(Withdrawal {
        from_pubkey: parse_arr::<33>(&fstr(v, "from_pubkey")?)?,
        target_lock_hash: fhash(v, "target_lock_hash")?,
        amount: fu128(v, "amount")?,
        nonce: fu64(v, "nonce")?,
        expiry: fu64(v, "expiry")?,
        sig: parse_arr::<64>(&fstr(v, "sig")?)?,
    })
}

// --- Deposit (no signature; its authority is the consumed L1 cell) -------------------------------

pub fn deposit_to_value(d: &Deposit) -> Value {
    json!({ "type": "deposit", "to_key": hexs(&d.to_key), "amount": d.amount.to_string() })
}
pub fn deposit_from_value(v: &Value) -> Result<Deposit, String> {
    Ok(Deposit { to_key: fhash(v, "to_key")?, amount: fu128(v, "amount")? })
}

// --- HtlcRef (the lock terms; also embedded in an htlc_lock for the holder's later claim/refund) --

pub fn htlcref_to_value(r: &HtlcRef) -> Value {
    json!({
        "sender_key": hexs(&r.sender_key),
        "receiver_key": hexs(&r.receiver_key),
        "amount": r.amount.to_string(),
        "hashlock": hexs(&r.hashlock),
        "timeout": r.timeout,
        "lock_nonce": r.lock_nonce,
    })
}
pub fn htlcref_from_value(v: &Value) -> Result<HtlcRef, String> {
    Ok(HtlcRef {
        sender_key: fhash(v, "sender_key")?,
        receiver_key: fhash(v, "receiver_key")?,
        amount: fu128(v, "amount")?,
        hashlock: fhash(v, "hashlock")?,
        timeout: fu64(v, "timeout")?,
        lock_nonce: fu64(v, "lock_nonce")?,
    })
}

// --- HtlcLock (includes the htlc_ref the sender later claims/refunds against) ---------------------

pub fn htlclock_to_value(l: &HtlcLock, r: &HtlcRef) -> Value {
    json!({
        "type": "htlc_lock",
        "sender_pubkey": hexs(&l.sender_pubkey),
        "receiver_key": hexs(&l.receiver_key),
        "amount": l.amount.to_string(),
        "fee": l.fee.to_string(),
        "hashlock": hexs(&l.hashlock),
        "timeout": l.timeout,
        "nonce": l.nonce,
        "sig": hexs(&l.sig),
        "htlc_ref": htlcref_to_value(r),
    })
}
pub fn htlclock_from_value(v: &Value) -> Result<HtlcLock, String> {
    Ok(HtlcLock {
        sender_pubkey: parse_arr::<33>(&fstr(v, "sender_pubkey")?)?,
        receiver_key: fhash(v, "receiver_key")?,
        amount: fu128(v, "amount")?,
        fee: fu128(v, "fee")?,
        hashlock: fhash(v, "hashlock")?,
        timeout: fu64(v, "timeout")?,
        nonce: fu64(v, "nonce")?,
        sig: parse_arr::<64>(&fstr(v, "sig")?)?,
    })
}

// --- HtlcClaim / HtlcRefund (unsigned; the htlc_ref + preimage are the authority) ----------------

pub fn claim_to_value(c: &HtlcClaim) -> Value {
    json!({ "type": "htlc_claim", "htlc_ref": htlcref_to_value(&c.htlc), "preimage": hexs(&c.preimage) })
}
pub fn claim_from_value(v: &Value) -> Result<HtlcClaim, String> {
    let r = htlcref_from_value(v.get("htlc_ref").ok_or("missing 'htlc_ref'")?)?;
    Ok(HtlcClaim { htlc: r, preimage: parse_bytes(&fstr(v, "preimage")?)? })
}

pub fn refund_to_value(r: &HtlcRefund) -> Value {
    json!({ "type": "htlc_refund", "htlc_ref": htlcref_to_value(&r.htlc) })
}
pub fn refund_from_value(v: &Value) -> Result<HtlcRefund, String> {
    Ok(HtlcRefund { htlc: htlcref_from_value(v.get("htlc_ref").ok_or("missing 'htlc_ref'")?)? })
}

// --- tagged dispatch (what a sequencer service consumes) ------------------------------------------

/// Any submittable intent, parsed from its tagged JSON. The sequencer service matches on this to
/// call the right `Sequencer::submit_*`.
#[derive(Clone, Debug)]
pub enum Intent {
    Deposit(Deposit),
    Transfer(Transfer),
    Withdrawal(Withdrawal),
    HtlcLock(HtlcLock),
    HtlcClaim(HtlcClaim),
    HtlcRefund(HtlcRefund),
}

/// Parse a tagged intent JSON string into an [`Intent`] (the inverse of the per-type `*_to_value`).
pub fn intent_from_json(s: &str) -> Result<Intent, String> {
    let v: Value = serde_json::from_str(s).map_err(|e| format!("json: {e}"))?;
    match v.get("type").and_then(|t| t.as_str()) {
        Some("deposit") => Ok(Intent::Deposit(deposit_from_value(&v)?)),
        Some("transfer") => Ok(Intent::Transfer(transfer_from_value(&v)?)),
        Some("withdrawal") => Ok(Intent::Withdrawal(withdrawal_from_value(&v)?)),
        Some("htlc_lock") => Ok(Intent::HtlcLock(htlclock_from_value(&v)?)),
        Some("htlc_claim") => Ok(Intent::HtlcClaim(claim_from_value(&v)?)),
        Some("htlc_refund") => Ok(Intent::HtlcRefund(refund_from_value(&v)?)),
        other => Err(format!("unknown intent type: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_round_trips() {
        let t = Transfer {
            from_pubkey: [3u8; 33],
            to_key: [7u8; 32],
            amount: 123_456_789_000_000_000_000,
            fee: 42,
            nonce: 9,
            expiry: 100,
            sig: [5u8; 64],
        };
        let j = transfer_to_value(&t).to_string();
        assert_eq!(transfer_from_value(&serde_json::from_str(&j).unwrap()).unwrap(), t);
        // and through the tagged dispatcher
        match intent_from_json(&j).unwrap() {
            Intent::Transfer(t2) => assert_eq!(t2, t),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn all_intents_round_trip_through_dispatch() {
        let d = Deposit { to_key: [1u8; 32], amount: u128::MAX };
        let w = Withdrawal { from_pubkey: [2u8; 33], target_lock_hash: [4u8; 32], amount: 5, nonce: 1, expiry: 2, sig: [6u8; 64] };
        let r = HtlcRef { sender_key: [8u8; 32], receiver_key: [9u8; 32], amount: 7, hashlock: [1u8; 32], timeout: 50, lock_nonce: 3 };
        let l = HtlcLock { sender_pubkey: [3u8; 33], receiver_key: r.receiver_key, amount: r.amount, fee: 1, hashlock: r.hashlock, timeout: r.timeout, nonce: r.lock_nonce, sig: [7u8; 64] };
        let c = HtlcClaim { htlc: r, preimage: b"secret-bytes".to_vec() };
        let rf = HtlcRefund { htlc: r };

        assert!(matches!(intent_from_json(&deposit_to_value(&d).to_string()).unwrap(), Intent::Deposit(x) if x == d));
        assert!(matches!(intent_from_json(&withdrawal_to_value(&w).to_string()).unwrap(), Intent::Withdrawal(x) if x == w));
        assert!(matches!(intent_from_json(&htlclock_to_value(&l, &r).to_string()).unwrap(), Intent::HtlcLock(x) if x == l));
        assert!(matches!(intent_from_json(&claim_to_value(&c).to_string()).unwrap(), Intent::HtlcClaim(x) if x == c));
        assert!(matches!(intent_from_json(&refund_to_value(&rf).to_string()).unwrap(), Intent::HtlcRefund(x) if x == rf));
    }

    #[test]
    fn malformed_is_rejected() {
        assert!(intent_from_json("not json").is_err());
        assert!(intent_from_json("{}").is_err()); // no type
        assert!(intent_from_json(r#"{"type":"transfer"}"#).is_err()); // missing fields
        assert!(intent_from_json(r#"{"type":"nope"}"#).is_err());
        // wrong-length pubkey
        assert!(transfer_from_value(&json!({"from_pubkey":"0x00","to_key":hexs(&[0u8;32]),"amount":"1","fee":"0","nonce":0,"expiry":1,"sig":hexs(&[0u8;64])})).is_err());
    }
}
