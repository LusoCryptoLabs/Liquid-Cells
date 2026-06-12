//! # Liquid Cells — end-to-end demo (off-chain, runs in ~1s)
//!
//! Drives the WHOLE protocol surface that runs without the (slow) Groth16 prover:
//!
//!   genesis pool → deposit → client-signed transfers → sequencer seals checkpoints
//!   → publish DA → a fresh client recovers its balance from L1 data alone
//!   → builds a force-exit witness → witness verifies against the committed root
//!   → an over-balance transfer is rejected (no inflation), state left untouched.
//!
//! Every actor uses the *same* `liquid-cells-stf` the SP1 guest proves and the on-chain
//! anchor type script checks — that single-implementation discipline is why a client can
//! never disagree with the sequencer or the contract. The on-chain half (the BN254 proof
//! verified on live CKB-VM and three chained checkpoints) is already deployed on Pudge; see
//! DEPLOY.md. This demo is the off-chain story you can re-run in a second.
//!
//! Run:  cargo run -p liquid-cells-sequencer --example demo

use liquid_cells_client::{proof_from_da, Account};
use liquid_cells_sequencer::{chain_reconstructs_to, Sequencer};
use liquid_cells_stf::{keccak, verify_proof, Deposit, Hash};

const CHAIN_ID: u64 = 0x0043_4b42; // "CKB" — matches the deployed contract's baked chain id

fn ckb(n: u128) -> u128 {
    n * 100_000_000 // shannons per CKB
}

fn short(h: &Hash) -> String {
    let mut s = String::from("0x");
    for b in &h[..6] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('…');
    s
}

fn rule(title: &str) {
    println!("\n──────────────────────────────────────────────────────────────");
    println!("  {title}");
    println!("──────────────────────────────────────────────────────────────");
}

fn main() {
    println!("\n  LIQUID CELLS — pooled trustless payment rollup on Nervos CKB");
    println!("  off-chain end-to-end demo (same STF the zk-guest proves)\n");

    // The pool id is baked into the contract; clients and the sequencer all use it.
    let pool_id = keccak(b"sp1-pool");

    // ── actors: each is just a secp256k1 key + the canonical STF, nothing more ──
    let mut alice = Account::new(pool_id, CHAIN_ID, [0x0a; 32]);
    let bob = Account::new(pool_id, CHAIN_ID, [0x0b; 32]);
    let carol = Account::new(pool_id, CHAIN_ID, [0x0c; 32]);

    let mut seq = Sequencer::genesis(pool_id, CHAIN_ID);
    rule("1. Genesis — an empty pool, one on-chain anchor cell");
    println!("  pool_id        {}", short(&pool_id));
    println!("  empty root     {}", short(&seq.root()));
    println!("  seq {}   total {}   fee_acc {}", seq.seq(), seq.total(), seq.fee_acc());

    // ── checkpoint #1: Alice deposits 100 CKB into the pool ──
    rule("2. Checkpoint #1 — Alice deposits 100 CKB");
    seq.submit_deposit(Deposit { to_key: alice.key(), amount: ckb(100) });
    let cp1 = seq.seal_batch(/*epoch*/ 0, /*fee_withdrawal*/ 0).expect("seal cp1");
    println!("  +deposit 100 CKB → Alice ({})", short(&alice.key()));
    println!("  new root       {}", short(&cp1.new_root()));
    println!("  seq {}   total {} shannons (= 100 CKB)", seq.seq(), seq.total());

    // ── checkpoint #2: Alice tips Bob and Carol sub-CKB amounts, with fees ──
    // These are SIGNED by Alice's key, client-side. The sequencer only orders them; it
    // cannot move Alice's balance without her signature (the STF's first invariant).
    rule("3. Checkpoint #2 — Alice tips Bob 0.25 + Carol 0.10 CKB (micro-payments)");
    let to_bob = alice.transfer(bob.key(), ckb(25) / 100, /*fee*/ 100_000, /*expiry*/ 100);
    let to_carol = alice.transfer(carol.key(), ckb(10) / 100, /*fee*/ 100_000, /*expiry*/ 100);
    seq.submit_transfer(to_bob);
    seq.submit_transfer(to_carol);
    println!("  Alice signs 2 transfers (nonces advance locally → {})", alice.nonce());
    let cp2 = seq.seal_batch(/*epoch*/ 0, /*fee_withdrawal*/ 0).expect("seal cp2");
    println!("  new root       {}", short(&cp2.new_root()));
    println!("  seq {}   total {}   fee_acc {} (2 × 0.001 CKB collected)", seq.seq(), seq.total(), seq.fee_acc());

    // Each checkpoint published a DA blob; together they ARE the public state on L1.
    let blobs = vec![cp1.da_blob.clone(), cp2.da_blob.clone()];

    // ── value conservation (the second invariant the proof attests) ──
    rule("4. Value conservation — Σ balances + fees == total (no inflation)");
    let tree = liquid_cells_client::reconstruct_tree(&blobs).expect("reconstruct");
    let bal = |a: &Account| proof_from_da(&blobs, &a.key()).map(|(l, _)| l.balance).unwrap_or(0);
    let (ba, bb, bc) = (bal(&alice), bal(&bob), bal(&carol));
    println!("  Alice {:>12}   Bob {:>10}   Carol {:>10}  (shannons)", ba, bb, bc);
    println!("  Σ balances {} + fee_acc {} = {}  ==  total {}", ba + bb + bc, seq.fee_acc(), ba + bb + bc + seq.fee_acc(), seq.total());
    assert_eq!(ba + bb + bc + seq.fee_acc(), seq.total(), "conservation must hold");
    assert_eq!(tree.root(), seq.root(), "DA must rebuild the committed root");
    assert!(chain_reconstructs_to(&blobs, seq.root()));
    println!("  ✓ the published DA blobs alone rebuild the exact committed root");

    // ── trustless recovery: Bob, knowing ONLY his key + the public L1 blobs ──
    rule("5. Trustless exit — Bob recovers his balance from L1 with no help from the operator");
    let mut bob = bob; // make mutable for sync
    let proof = bob.sync_from_da(&blobs).expect("Bob has a leaf");
    println!("  Bob reconstructs his leaf from L1 DA: balance {} shannons, nonce {}", proof.leaf.balance, proof.leaf.nonce);
    let witness = bob.force_exit_witness(&blobs).expect("Bob can build an exit witness");
    println!("  Bob assembles a force-exit witness: {} bytes (pubkey‖balance‖nonce‖siblings)", witness.len());

    // Re-run the EXACT inclusion check the on-chain anchor type script's force-exit mode does.
    let (leaf, siblings) = proof_from_da(&blobs, &bob.key()).unwrap();
    let ok = verify_proof(&seq.root(), &bob.key(), &leaf.hash(), &siblings);
    assert!(ok, "the contract's inclusion check must accept Bob's witness");
    println!("  ✓ witness verifies against committed root {} — the contract would pay Bob,", short(&seq.root()));
    println!("    forced to his own secp lock, even if the operator vanished.");

    // ── safety: an over-balance transfer is rejected and changes nothing ──
    rule("6. No theft / no inflation — an invalid batch is simply rejected");
    let root_before = seq.root();
    let overspend = alice.transfer(bob.key(), ckb(1_000_000), 100_000, 100); // Alice can't afford this
    seq.submit_transfer(overspend);
    match seq.seal_batch(0, 0) {
        Ok(_) => panic!("an over-balance transfer must NOT be accepted"),
        Err(e) => println!("  seal rejected: {e:?}"),
    }
    assert_eq!(seq.root(), root_before, "a rejected batch must not move state");
    println!("  ✓ committed root unchanged {} — the operator cannot inflate balances.", short(&seq.root()));

    rule("DONE");
    println!("  Off-chain pipeline ran end-to-end: genesis → deposit → signed micro-payments");
    println!("  → 2 sealed checkpoints → L1 DA → trustless recovery + exit witness → safety.");
    println!("  The matching on-chain half (Groth16 proof verified on live CKB-VM, 3 chained");
    println!("  checkpoints) is deployed on Pudge testnet — see DEPLOY.md.\n");
}
