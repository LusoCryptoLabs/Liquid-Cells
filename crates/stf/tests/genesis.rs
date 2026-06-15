//! Pins the genesis (empty-tree) pool root, the value that goes on-chain in the genesis
//! anchor cell's data. Independent of pool_id/chain_id (it's just the empty SMT root).

use liquid_cells_stf::*;

#[test]
fn genesis_root_is_the_empty_smt_root() {
    let st = State::genesis(keccak(b"sp1-pool"), 0x434b_42);
    let mut hex = String::new();
    for b in st.pool.root {
        hex.push_str(&format!("{:02x}", b));
    }
    println!("GENESIS_ROOT=0x{hex}");
    assert_eq!(st.pool.seq, 0);
    assert_eq!(st.pool.total, 0);
    assert_eq!(st.pool.fee_acc, 0);
    // The empty SMT root equals the active scheme's `Smt::new().root()` (the depth-256
    // default node today; the zero constant under the staged `compact_smt`).
    assert_eq!(st.pool.root, Smt::new().root());
}
