//! `lc-swap`: run a LIVE dust-egress atomic swap with the swap drivers wired to a real Fiber node.
//!
//! This is the runnable proof that the coordinator ([`liquid_cells_client::swap`]) drives a real
//! swap, not just a mock. The **counterparty (Fiber) leg is live**: a maker `fnn` node holds a
//! `sha256` hold invoice, a taker `fnn` node pays it over an open channel, the maker settles to
//! reveal the secret, all through [`liquid_cells_client::fiber::FiberLeg`] (a `CounterpartyLeg` over
//! fnn JSON-RPC). The **pool leg settles through the canonical `liquid_cells_stf`** in-process (the
//! exact STF the sequencer and on-chain contract run), the same faithful-pool approach the driver
//! tests use; a production operator would instead seal the returned pool intents into Groth16
//! checkpoints (that path is already proven live, seq 1 -> 2 -> 3).
//!
//! Build:  cargo build -p liquid-cells-client --features fiber --release
//! Usage:  lc-swap [--maker-rpc URL] [--taker-rpc URL] [--label STR] [--dust N] [--fiber-amount N]
//!   --maker-rpc   PAYEE node (creates + settles the hold invoice).  default http://127.0.0.1:8237
//!   --taker-rpc   PAYER node (pays the invoice).                    default http://127.0.0.1:8227
//!   --label       swap label; preimage = sha256(label), H = sha256(preimage). A timestamp salt is
//!                 appended for a fresh H per run unless --no-salt is given.
//!   --dust        in-pool dust escrowed to the LP (shannons).       default 200000000 (2 CKB)
//!   --fiber-amount Fibt the LP pays the maker (shannons).           default 100000000 (1 CKB)

use liquid_cells_client::fiber::FiberLeg;
use liquid_cells_client::swap::{swap_hashlock, CounterpartyLeg, DriverStep, LegState, MakerDriver, SwapTerms, TakerDriver};
use liquid_cells_client::Account;
use liquid_cells_stf::{apply, Batch, Deposit, State};
use std::time::{SystemTime, UNIX_EPOCH};

const CHAIN: u64 = 0x434b_42;
// Abstract-clock timeouts (pool epochs), kept large so a live swap never trips a refund branch; the
// real Fiber invoice expiry is what actually bounds the on-network HTLC.
const POOL_TIMEOUT: u64 = 1_000;
const FIBER_TIMEOUT: u64 = 500;
const POOL_FEE: u128 = 1_000;
const TICK_SECS: u64 = 3;
const MAX_TICKS: u64 = 40;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}
fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}
fn arg_u128(name: &str, default: u128) -> u128 {
    arg(name).and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn main() {
    let maker_rpc = arg("--maker-rpc").unwrap_or_else(|| "http://127.0.0.1:8237".to_string());
    let taker_rpc = arg("--taker-rpc").unwrap_or_else(|| "http://127.0.0.1:8227".to_string());
    let dust = arg_u128("--dust", 200_000_000);
    let fiber_amount = arg_u128("--fiber-amount", 100_000_000);
    let base_label = arg("--label").unwrap_or_else(|| "liquid-cells/fiber-swap/adapter-demo".to_string());
    let label = if flag("--no-salt") {
        base_label
    } else {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        format!("{base_label}/{nanos}")
    };

    // The secret IS the 32-byte preimage Fiber requires (payment_hash = sha256(preimage)). Deriving
    // it as sha256(label) yields a deterministic, 32-byte, Fiber-valid preimage; H = sha256(secret).
    let secret = swap_hashlock(label.as_bytes()).to_vec();
    let h = swap_hashlock(&secret);

    println!("== live dust-egress swap (drivers <-> live Fiber) ==");
    println!("label    : {label}");
    println!("preimage : 0x{}", hex::encode(&secret));
    println!("H        : 0x{}", hex::encode(h));
    println!("maker rpc: {maker_rpc}   taker rpc: {taker_rpc}");
    println!("amounts  : pool dust {dust}  Fibt {fiber_amount}\n");

    // In-process LC pool: fund the maker so it can escrow the dust.
    let mut maker_acct = Account::new(swap_pool_id(), CHAIN, [7u8; 32]);
    let taker_key = Account::new(swap_pool_id(), CHAIN, [9u8; 32]).key();
    let mut st = State::genesis(swap_pool_id(), CHAIN);
    apply(&mut st, &Batch {
        current_epoch: 0,
        deposits: vec![Deposit { to_key: maker_acct.key(), amount: dust + POOL_FEE + 1 }],
        ..Default::default()
    }).expect("fund maker");

    let terms = SwapTerms::propose(&maker_acct, taker_key, dust, fiber_amount, &secret, POOL_TIMEOUT, FIBER_TIMEOUT);
    terms.validate().expect("invalid swap terms");

    // Two live legs, one per node. The maker creates the hold invoice and shares its address with
    // the taker leg (out-of-band swap negotiation).
    let mut maker_leg = FiberLeg::maker(&maker_rpc, h, fiber_amount, FIBER_TIMEOUT);
    let mut taker_leg = match preflight(&maker_leg, &maker_rpc, &taker_rpc) {
        Ok(()) => {
            let invoice = maker_leg.create_hold_invoice(3_600, "lc dust egress swap").expect("create hold invoice");
            println!("[setup] maker hold invoice: {}\n", &invoice[..invoice.len().min(56)]);
            FiberLeg::taker(&taker_rpc, h, &invoice, fiber_amount, FIBER_TIMEOUT, secret.clone())
        }
        Err(e) => {
            eprintln!("preflight failed: {e}");
            std::process::exit(1);
        }
    };

    let mut maker = MakerDriver::new(terms, secret.clone(), POOL_FEE);
    let mut taker = TakerDriver::new(terms);
    let mut pool = LegState::Empty;
    let (mut maker_done, mut taker_done) = (false, false);
    let (mut said_settle, mut said_pay) = (false, false); // narrate each live-leg milestone once

    for tick in 1..=MAX_TICKS {
        let now = tick; // abstract clock, well below the (large) timeouts

        match maker.poll(&mut maker_acct, &mut maker_leg, &pool, now) {
            DriverStep::SubmitLock(l) => {
                apply(&mut st, &Batch { current_epoch: now, htlc_locks: vec![l], ..Default::default() }).expect("apply pool lock");
                pool = LegState::Locked { hashlock: terms.hashlock, amount: terms.dust, timeout: terms.pool_timeout };
                println!("[{tick:02}] maker: escrowed {dust} dust in the pool HTLC (H-locked)");
            }
            DriverStep::SubmitRefund(r) => {
                apply(&mut st, &Batch { current_epoch: now, htlc_refunds: vec![r], ..Default::default() }).expect("apply pool refund");
                pool = LegState::Refunded;
                println!("[{tick:02}] maker: refunded the pool dust (swap did not complete)");
            }
            DriverStep::Idle => {
                // Narrate the one interesting idle action once: the maker settling the Fiber invoice.
                if !said_settle && matches!(maker_leg.state(), LegState::Claimed { .. }) {
                    println!("[{tick:02}] maker: settled the Fiber invoice, secret revealed");
                    said_settle = true;
                }
            }
            DriverStep::Settled => {
                if !maker_done {
                    println!("[{tick:02}] maker: DONE (claimed the Fibt payment)");
                }
                maker_done = true;
            }
            DriverStep::Aborted(m) => {
                eprintln!("[{tick:02}] maker ABORTED: {m}");
                std::process::exit(2);
            }
            _ => {}
        }

        match taker.poll(&mut taker_leg, &pool, now) {
            DriverStep::SubmitClaim(c) => {
                apply(&mut st, &Batch { current_epoch: now, htlc_claims: vec![c], ..Default::default() }).expect("apply pool claim");
                pool = LegState::Claimed { preimage: secret.clone() };
                println!("[{tick:02}] taker: claimed the pool dust with the revealed secret");
            }
            DriverStep::Idle => {
                if !said_pay && matches!(taker_leg.state(), LegState::Locked { .. }) {
                    println!("[{tick:02}] taker: paid the Fiber invoice (HTLC in flight)");
                    said_pay = true;
                }
            }
            DriverStep::Settled => {
                if !taker_done {
                    println!("[{tick:02}] taker: DONE");
                }
                taker_done = true;
            }
            DriverStep::Aborted(m) => {
                eprintln!("[{tick:02}] taker ABORTED: {m}");
                std::process::exit(2);
            }
            _ => {}
        }

        if maker_done && taker_done {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(TICK_SECS));
    }

    println!();
    let lp_balance = st.get_leaf(&taker_key).balance;
    let maker_paid = matches!(maker_leg.state(), LegState::Claimed { .. });
    println!("pool: LP (taker) balance = {lp_balance} shannons  (expected {dust})");
    println!("fiber: maker invoice settled = {maker_paid}");

    if maker_done && taker_done && lp_balance == dust && maker_paid {
        println!("\nSWAP COMPLETE: live Fiber payment + in-pool dust egress, atomic under H = sha256(secret).");
    } else {
        eprintln!("\nSWAP INCOMPLETE (maker_done={maker_done} taker_done={taker_done} lp_balance={lp_balance} maker_paid={maker_paid})");
        std::process::exit(3);
    }
}

fn swap_pool_id() -> liquid_cells_stf::Hash {
    liquid_cells_stf::keccak(b"lc-swap-live-pool")
}

fn preflight(maker_leg: &FiberLeg, maker_rpc: &str, taker_rpc: &str) -> Result<(), String> {
    let mk = maker_leg.node_pubkey().map_err(|e| format!("maker node {maker_rpc}: {e}"))?;
    // A throwaway taker leg just to probe the payer node's identity.
    let probe = FiberLeg::taker(taker_rpc, [0u8; 32], "", 0, 0, Vec::new());
    let tk = probe.node_pubkey().map_err(|e| format!("taker node {taker_rpc}: {e}"))?;
    println!("[setup] maker node pubkey {}...  taker node pubkey {}...", &mk[..mk.len().min(16)], &tk[..tk.len().min(16)]);
    Ok(())
}
