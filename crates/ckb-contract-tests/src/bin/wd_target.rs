//! Compute the withdrawal target lock hash that the proof must commit, and write it to
//! fixtures/wd/target_lock_hash.bin. The host bakes this into the withdrawal it proves,
//! and tests/withdrawal.rs builds the identical lock (`withdraw_lock()`) for the
//! withdrawal output cell — so the recomputed `withdrawals_commitment` matches the proof.

use ckb_testtool::ckb_types::prelude::*;
use liquid_cells_ckb_tests::withdraw_lock;

fn main() {
    let h: [u8; 32] = withdraw_lock().calc_script_hash().unpack();
    std::fs::create_dir_all("../../fixtures/wd").expect("mkdir fixtures/wd");
    std::fs::write("../../fixtures/wd/target_lock_hash.bin", h).expect("write target_lock_hash");
    println!("withdraw target_lock_hash=0x{}", hex::encode(h));
}
