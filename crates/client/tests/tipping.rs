//! Worked tipping integration (the scryve flow), end-to-end against the real STF/sequencer:
//! a fan deposits, tips an author with a platform cut split, the checkpoint is sealed, and the
//! author's + platform's balances are **reconstructed from L1 DA alone** — the trust-minimized
//! replacement for a custodial tip ledger. See docs/INTEGRATION-TIPPING.md.
use liquid_cells_client::{latest_leaf, reconstruct_tree, Account};
use liquid_cells_sequencer::Sequencer;
use liquid_cells_stf::*;

const CHAIN: u64 = 0x434b_42;
fn pool() -> Hash {
    keccak(b"scryve-tips")
}
fn acct(n: u8) -> Account {
    let mut s = [0u8; 32];
    s[31] = n;
    Account::new(pool(), CHAIN, s)
}

#[test]
fn fan_tips_author_with_platform_split_reconstructable_from_l1() {
    let mut operator = Sequencer::genesis(pool(), CHAIN);
    let mut fan = acct(1);
    let author = acct(2);
    let platform = acct(3);

    // 1. Fan funds their tipping balance (operator credits the deposit cell to fan's key).
    const DEPOSIT: u128 = 100_000_000_000; // 1000 CKB
    operator.submit_deposit(Deposit { to_key: fan.key(), amount: DEPOSIT });
    let job1 = operator.seal_batch(0, 0).expect("deposit checkpoint");

    // 2. Fan tips a gross amount; 10% (1000 bps) to the platform, the rest to the author.
    const GROSS: u128 = 5_000_000_000; // 50 CKB tip
    const BPS: u16 = 1000;
    let [to_author, to_platform] = fan.split_tip(author.key(), platform.key(), GROSS, BPS, 1_000_000);
    // conservation at the SDK level:
    assert_eq!(to_author.amount + to_platform.amount, GROSS);
    assert_eq!(to_platform.amount, GROSS * BPS as u128 / 10_000);
    operator.submit_transfer(to_author);
    operator.submit_transfer(to_platform);
    let (job2, dropped) = operator.seal_resilient(0, 0).expect("tip checkpoint");
    assert!(dropped.is_empty(), "both legs of a valid split must seal");

    // 3. Reconstruct author + platform balances from the published DA blobs alone (no operator).
    let blobs = vec![job1.da_blob.clone(), job2.da_blob.clone()];
    assert_eq!(reconstruct_tree(&blobs).unwrap().root(), job2.new_root(), "L1 rebuild == anchor");
    let author_bal = latest_leaf(&blobs, &author.key()).unwrap().balance;
    let platform_bal = latest_leaf(&blobs, &platform.key()).unwrap().balance;
    let fan_bal = latest_leaf(&blobs, &fan.key()).unwrap().balance;
    assert_eq!(author_bal + platform_bal, GROSS, "split conserved on-ledger");
    assert_eq!(platform_bal, GROSS * BPS as u128 / 10_000, "platform got its 10%");
    assert_eq!(fan_bal, DEPOSIT - GROSS, "fan debited exactly the gross tip");
    // and the operator provably cannot have stolen: author can force-exit author_bal from L1.
    assert!(author.force_exit_witness(&blobs).is_some());
}
