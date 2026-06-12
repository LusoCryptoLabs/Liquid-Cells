//! Sign a Liquid Cells intent and print the JSON the demo server's API expects. Used to drive an
//! end-to-end test without a browser wallet, and as a reference oracle for the browser's JS
//! signing (which must produce byte-identical digests + signatures).
//!
//!   signintent pubkey   <secret_hex32>
//!   signintent tip      <secret_hex32> <to_key_hex32> <amount> <fee> <nonce> <expiry>
//!   signintent withdraw <secret_hex32> <target_lock_hash_hex32> <amount> <nonce> <expiry>

use liquid_cells_client::Account;
use liquid_cells_stf::{key_of_pubkey, keccak, sig, Hash};

const CHAIN_ID: u64 = 0x0043_4b42;
fn pool_id() -> Hash {
    keccak(b"sp1-pool")
}
fn hexs(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
fn secret(s: &str) -> [u8; 32] {
    let v = hex::decode(s.trim_start_matches("0x")).expect("secret hex");
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}
fn hash(s: &str) -> Hash {
    let v = hex::decode(s.trim_start_matches("0x")).expect("hash hex");
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("pubkey") => {
            let sk = secret(&a[2]);
            let pk = sig::pubkey(&sk);
            println!("{{\"pubkey\": \"{}\", \"key\": \"{}\"}}", hexs(&pk), hexs(&key_of_pubkey(&pk)));
        }
        Some("tip") => {
            let sk = secret(&a[2]);
            let to = hash(&a[3]);
            let amount: u128 = a[4].parse().unwrap();
            let fee: u128 = a[5].parse().unwrap();
            let nonce: u64 = a[6].parse().unwrap();
            let expiry: u64 = a[7].parse().unwrap();
            let mut acc = Account::new(pool_id(), CHAIN_ID, sk);
            acc.set_nonce(nonce);
            let t = acc.transfer(to, amount, fee, expiry);
            println!(
                "{{\"fromPubkey\": \"{}\", \"toKey\": \"{}\", \"amount\": \"{}\", \"fee\": \"{}\", \"nonce\": {}, \"expiry\": {}, \"sig\": \"{}\"}}",
                hexs(&t.from_pubkey), hexs(&t.to_key), t.amount, t.fee, t.nonce, t.expiry, hexs(&t.sig)
            );
        }
        Some("withdraw") => {
            let sk = secret(&a[2]);
            let tlh = hash(&a[3]);
            let amount: u128 = a[4].parse().unwrap();
            let nonce: u64 = a[5].parse().unwrap();
            let expiry: u64 = a[6].parse().unwrap();
            let mut acc = Account::new(pool_id(), CHAIN_ID, sk);
            acc.set_nonce(nonce);
            let w = acc.withdraw(tlh, amount, expiry);
            println!(
                "{{\"fromPubkey\": \"{}\", \"targetLockHash\": \"{}\", \"amount\": \"{}\", \"nonce\": {}, \"expiry\": {}, \"sig\": \"{}\"}}",
                hexs(&w.from_pubkey), hexs(&w.target_lock_hash), w.amount, w.nonce, w.expiry, hexs(&w.sig)
            );
        }
        _ => {
            eprintln!("usage: signintent pubkey|tip|withdraw ...");
            std::process::exit(2);
        }
    }
}
