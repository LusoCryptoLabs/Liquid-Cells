//! fnn-backed [`CounterpartyLeg`]: drive a LIVE Fiber payment-channel HTLC as the swap's
//! counterparty leg, so the swap drivers ([`crate::swap::MakerDriver`] / [`crate::swap::TakerDriver`])
//! run against a real `fnn` node instead of [`crate::swap::MockLeg`], with no change to the
//! coordinator logic. Behind `--features fiber`.
//!
//! Fiber's HTLC is hold-invoice based, which maps onto the swap roles as:
//!   * **maker** (dust holder) = invoice PAYEE: creates a `sha256` hold invoice whose `payment_hash`
//!     is `H = sha256(secret)` ([`FiberLeg::create_hold_invoice`]), then `settle_invoice`s it with
//!     the secret to claim the payment ([`CounterpartyLeg::claim`]). Settling reveals the secret
//!     across the HTLC chain.
//!   * **taker** (LP) = invoice PAYER: `send_payment`s the invoice ([`CounterpartyLeg::lock`]); its
//!     payment reaches `Success` only once the maker has settled, i.e. revealed the secret.
//!
//! Both observe the SAME on-network HTLC, each from its own node: the maker via `get_invoice`
//! (`Open` -> `Received` -> `Paid`), the taker via `get_payment` (`Inflight` -> `Success`).
//! [`CounterpartyLeg::state`] maps those node states onto [`LegState`].
//!
//! ## The preimage gap (honest note)
//!
//! When the maker settles, the preimage propagates back to the taker as the HTLC fulfillment, so the
//! taker's node DOES hold it (we verified it lands in the taker node's channel store). A production
//! Lightning/Fiber node exposes that fulfilled preimage to its operator; **fnn v0.8.1's `get_payment`
//! does not** (it returns status only, no preimage field; the value lives solely in the node's
//! RocksDB). So this adapter learns the revealed secret as follows, in order:
//!   1. the `payment_preimage` / `preimage` field of `get_payment`, if a node exposes it (forward
//!      compatible with later fnn or other nodes);
//!   2. otherwise a caller-supplied `expected_secret` (the demo path), surfaced ONLY after
//!      `get_payment` independently proves `Success` (the maker provably revealed it) and always
//!      re-checked `sha256(preimage) == payment_hash` before use.
//!
//! The swap's safety does not rest on this bridge: the taker's [`crate::swap::decide`] re-verifies
//! `sha256(preimage) == H` regardless, and a payment only reaches `Success` if the real preimage was
//! revealed on the network. The fallback only closes the fnn RPC gap so the end-to-end demo can run
//! unattended.

use crate::swap::{swap_hashlock, CounterpartyLeg, LegState};
use liquid_cells_stf::Hash;
use serde_json::{json, Value};

/// Which Fiber endpoint this leg drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FiberRole {
    /// Dust holder = invoice payee (creates + settles the hold invoice).
    Maker,
    /// LP = invoice payer (pays the invoice; learns the secret on fulfillment).
    Taker,
}

fn hexstr(h: &[u8]) -> String {
    format!("0x{}", hex::encode(h))
}
fn hexdec(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap_or_default()
}

fn http_agent() -> ureq::Agent {
    // native-tls (OpenSSL) honors the system CA store, matching the `cli` HTTP path; harmless for
    // the plain-HTTP localhost fnn RPC, and lets the same agent reach an https fnn if pointed at one.
    let tls = native_tls::TlsConnector::new().expect("native-tls");
    ureq::AgentBuilder::new().tls_connector(std::sync::Arc::new(tls)).build()
}

fn rpc(ag: &ureq::Agent, url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"id": 1, "jsonrpc": "2.0", "method": method, "params": params});
    let resp = ag
        .post(url)
        .set("content-type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("{method}: {e}"))?;
    let text = resp.into_string().map_err(|e| format!("{method}: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{method}: {e}"))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(format!("{method}: {err}"));
    }
    Ok(v["result"].clone())
}

// --- pure status -> LegState mappers (unit-tested without a node) --------------------------------

/// Map a maker-side `get_invoice` status onto the counterparty leg state the maker observes.
fn invoice_status_to_leg(status: &str, hashlock: Hash, amount: u128, timeout: u64) -> LegState {
    match status {
        "Open" => LegState::Empty,                                               // taker has not paid yet
        "Received" => LegState::Locked { hashlock, amount, timeout },            // taker's HTLC held
        "Paid" => LegState::Claimed { preimage: Vec::new() },                    // maker settled (decide ignores the preimage here)
        "Cancelled" | "Expired" => LegState::Refunded,
        _ => LegState::Empty,
    }
}

/// Map a taker-side `get_payment` status onto the counterparty leg state the taker observes. On
/// `Success`, surface the revealed preimage (RPC field first, else the supplied fallback), but only
/// if `sha256(preimage) == hashlock`; otherwise stay `Locked` rather than surface an unverified one.
fn payment_status_to_leg(
    status: &str,
    rpc_preimage: Option<&[u8]>,
    expected: &[u8],
    hashlock: Hash,
    amount: u128,
    timeout: u64,
) -> LegState {
    match status {
        "Created" | "Inflight" => LegState::Locked { hashlock, amount, timeout },
        "Success" => {
            let preimage = match rpc_preimage {
                Some(p) if !p.is_empty() => p.to_vec(),
                _ => expected.to_vec(),
            };
            if swap_hashlock(&preimage) == hashlock {
                LegState::Claimed { preimage }
            } else {
                LegState::Locked { hashlock, amount, timeout }
            }
        }
        "Failed" => LegState::Refunded,
        _ => LegState::Empty,
    }
}

/// A [`CounterpartyLeg`] backed by a live `fnn` JSON-RPC endpoint.
pub struct FiberLeg {
    agent: ureq::Agent,
    url: String,
    role: FiberRole,
    /// `H = sha256(secret)`, the invoice `payment_hash` both legs bind.
    payment_hash: Hash,
    /// The hold-invoice address (set by the maker at creation; the taker pays it).
    invoice: Option<String>,
    /// Agreed counterparty amount and timeout, so `state()` fills `LegState::Locked` faithfully.
    amount: u128,
    timeout: u64,
    /// The value that WILL be revealed, used only as the fnn-v0.8.1 preimage fallback (see module
    /// docs). Empty for the maker (which already knows the secret it settles with).
    expected_secret: Vec<u8>,
    /// Idempotency: the taker pays once, the maker settles once (re-polling before the node reflects
    /// the new status must not re-issue the RPC).
    did_pay: bool,
    did_claim: bool,
}

impl FiberLeg {
    /// Maker leg over the PAYEE node `url`, for `payment_hash = sha256(secret)`. Call
    /// [`create_hold_invoice`](Self::create_hold_invoice) before the taker pays.
    pub fn maker(url: &str, payment_hash: Hash, amount: u128, timeout: u64) -> Self {
        Self {
            agent: http_agent(), url: url.to_string(), role: FiberRole::Maker, payment_hash,
            invoice: None, amount, timeout, expected_secret: Vec::new(), did_pay: false, did_claim: false,
        }
    }

    /// Taker leg over the PAYER node `url`, paying `invoice` (the maker's hold invoice).
    /// `expected_secret` bridges fnn v0.8.1's missing payer-side preimage RPC (see module docs); it
    /// is surfaced only after the payment provably succeeds and is re-checked against `H`.
    pub fn taker(url: &str, payment_hash: Hash, invoice: &str, amount: u128, timeout: u64, expected_secret: Vec<u8>) -> Self {
        Self {
            agent: http_agent(), url: url.to_string(), role: FiberRole::Taker, payment_hash,
            invoice: Some(invoice.to_string()), amount, timeout, expected_secret, did_pay: false, did_claim: false,
        }
    }

    /// The fnn node's pubkey (a connectivity check).
    pub fn node_pubkey(&self) -> Result<String, String> {
        let r = rpc(&self.agent, &self.url, "node_info", json!([]))?;
        Ok(r.get("public_key").or_else(|| r.get("pubkey")).and_then(|v| v.as_str()).unwrap_or("").to_string())
    }

    /// MAKER: create the `sha256` hold invoice for `H`, returning its `invoice_address` (share it
    /// with the taker). `expiry_secs` is the invoice validity window.
    pub fn create_hold_invoice(&mut self, expiry_secs: u64, description: &str) -> Result<String, String> {
        let params = json!([{
            "amount": format!("0x{:x}", self.amount),
            "currency": "Fibt",
            "hash_algorithm": "sha256",
            "payment_hash": hexstr(&self.payment_hash),
            "expiry": format!("0x{expiry_secs:x}"),
            "description": description,
        }]);
        let r = rpc(&self.agent, &self.url, "new_invoice", params)?;
        let addr = r["invoice_address"].as_str().ok_or("new_invoice: no invoice_address")?.to_string();
        self.invoice = Some(addr.clone());
        Ok(addr)
    }

    /// The hold-invoice address this leg pays / created.
    pub fn invoice(&self) -> Option<&str> {
        self.invoice.as_deref()
    }

    fn maker_state(&self) -> LegState {
        if self.did_claim {
            return LegState::Claimed { preimage: Vec::new() }; // we revealed; advance decide even before fnn reflects Paid
        }
        match rpc(&self.agent, &self.url, "get_invoice", json!([{"payment_hash": hexstr(&self.payment_hash)}])) {
            Ok(r) => invoice_status_to_leg(r["status"].as_str().unwrap_or(""), self.payment_hash, self.amount, self.timeout),
            Err(_) => LegState::Empty,
        }
    }

    fn taker_state(&self) -> LegState {
        let r = match rpc(&self.agent, &self.url, "get_payment", json!([{"payment_hash": hexstr(&self.payment_hash)}])) {
            Ok(r) => r,
            Err(_) => return LegState::Empty, // payment not registered yet
        };
        let rpc_preimage = r
            .get("payment_preimage")
            .or_else(|| r.get("preimage"))
            .and_then(|v| v.as_str())
            .map(hexdec);
        payment_status_to_leg(
            r["status"].as_str().unwrap_or(""),
            rpc_preimage.as_deref(),
            &self.expected_secret,
            self.payment_hash,
            self.amount,
            self.timeout,
        )
    }
}

impl CounterpartyLeg for FiberLeg {
    /// TAKER: pay the maker's hold invoice (`hashlock`/`amount`/`timeout` are already bound into the
    /// invoice, so the abstract-clock args are not re-sent).
    fn lock(&mut self, _hashlock: Hash, _amount: u128, _timeout: u64) {
        if self.did_pay {
            return;
        }
        let invoice = match &self.invoice {
            Some(i) => i.clone(),
            None => {
                eprintln!("fiber lock: no invoice to pay");
                return;
            }
        };
        match rpc(&self.agent, &self.url, "send_payment", json!([{"invoice": invoice}])) {
            Ok(_) => self.did_pay = true,
            Err(e) => {
                // A duplicate / already-inflight payment is not fatal: the HTLC is locked.
                if e.to_lowercase().contains("exist") || e.to_lowercase().contains("duplicate") {
                    self.did_pay = true;
                } else {
                    eprintln!("fiber lock (send_payment): {e}");
                }
            }
        }
    }

    /// MAKER: settle the hold invoice with the secret, claiming the payment and revealing the secret.
    fn claim(&mut self, preimage: &[u8]) {
        if self.did_claim {
            return;
        }
        let params = json!([{
            "payment_hash": hexstr(&self.payment_hash),
            "payment_preimage": hexstr(preimage),
        }]);
        match rpc(&self.agent, &self.url, "settle_invoice", params) {
            Ok(_) => self.did_claim = true,
            Err(e) => eprintln!("fiber claim (settle_invoice): {e}"),
        }
    }

    /// TAKER: an outgoing held payment refunds via HTLC timeout; fnn exposes no unilateral
    /// payer-cancel, so this is a documented best-effort no-op. `state()` reports `Refunded` once the
    /// payment fails on the network.
    fn refund(&mut self) {}

    fn state(&self) -> LegState {
        match self.role {
            FiberRole::Maker => self.maker_state(),
            FiberRole::Taker => self.taker_state(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h() -> Hash {
        swap_hashlock(b"a-secret")
    }

    #[test]
    fn invoice_status_maps_to_the_makers_view() {
        let hl = h();
        assert_eq!(invoice_status_to_leg("Open", hl, 7, 9), LegState::Empty);
        assert_eq!(
            invoice_status_to_leg("Received", hl, 7, 9),
            LegState::Locked { hashlock: hl, amount: 7, timeout: 9 }
        );
        assert!(matches!(invoice_status_to_leg("Paid", hl, 7, 9), LegState::Claimed { .. }));
        assert_eq!(invoice_status_to_leg("Cancelled", hl, 7, 9), LegState::Refunded);
        assert_eq!(invoice_status_to_leg("Expired", hl, 7, 9), LegState::Refunded);
        assert_eq!(invoice_status_to_leg("???", hl, 7, 9), LegState::Empty);
    }

    #[test]
    fn payment_status_maps_to_the_takers_view() {
        let secret = b"a-secret";
        let hl = swap_hashlock(secret);
        assert_eq!(
            payment_status_to_leg("Inflight", None, secret, hl, 7, 9),
            LegState::Locked { hashlock: hl, amount: 7, timeout: 9 }
        );
        // Success + correct supplied fallback -> Claimed with that preimage.
        assert_eq!(
            payment_status_to_leg("Success", None, secret, hl, 7, 9),
            LegState::Claimed { preimage: secret.to_vec() }
        );
        assert_eq!(payment_status_to_leg("Failed", None, secret, hl, 7, 9), LegState::Refunded);
    }

    #[test]
    fn success_prefers_the_rpc_preimage_when_present() {
        let secret = b"the-real-secret";
        let hl = swap_hashlock(secret);
        // The node exposed the preimage over RPC: use it (here it matches H).
        assert_eq!(
            payment_status_to_leg("Success", Some(secret), b"ignored-fallback", hl, 1, 2),
            LegState::Claimed { preimage: secret.to_vec() }
        );
    }

    #[test]
    fn success_with_a_wrong_secret_does_not_surface_a_bad_preimage() {
        let hl = swap_hashlock(b"the-real-secret");
        // Neither the (absent) RPC field nor the fallback hashes to H: stay Locked, never Claimed.
        let s = payment_status_to_leg("Success", None, b"wrong-secret", hl, 1, 2);
        assert_eq!(s, LegState::Locked { hashlock: hl, amount: 1, timeout: 2 });
    }
}
