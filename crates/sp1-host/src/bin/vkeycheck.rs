use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{Elf, HashableKey, ProvingKey};
fn main() {
    let elf = std::fs::read(std::env::args().nth(1).expect("elf path")).expect("read elf");
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(elf)).expect("setup");
    let vkey = pk.verifying_key().bytes32();
    const EXPECTED: &str = "0x00213af5b4cc8922754e5b8ee7e610de703d4cb17fabb0a187c95c37fe67c1e8";
    println!("vkey     = {vkey}");
    println!("expected = {EXPECTED}");
    println!("{}", if vkey == EXPECTED { "MATCH: reproduces the baked on-chain vkey" } else { "MISMATCH" });
}
