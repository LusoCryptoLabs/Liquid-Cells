//! Shared helpers for the integration tests + the `wd_target` helper bin.

use ckb_testtool::ckb_types::core::ScriptHashType;
use ckb_testtool::ckb_types::{bytes::Bytes, packed::Script, prelude::*};

/// A **deterministic** lock script with the given args. Used as the withdrawal target:
/// it is an output-cell lock in the checkpoint, so it never executes here, only its
/// script hash matters, and it must be byte-identical in the `wd_target` helper (which
/// the proof commits) and the withdrawal test (which builds the output). `Context::
/// build_script` is *not* usable for this: it deploys with a type-id, so its hash
/// varies per `Context`. The placeholder `code_hash` is intentional.
pub fn withdraw_lock_with(args: &[u8]) -> Script {
    Script::new_builder()
        .code_hash([0u8; 32].pack())
        .hash_type(ScriptHashType::Data.into())
        .args(Bytes::from(args.to_vec()).pack())
        .build()
}

/// The canonical withdrawal target lock.
pub fn withdraw_lock() -> Script {
    withdraw_lock_with(b"liquid-cells/withdraw-target")
}

// ---- shared byte/anchor helpers (used by the proof-based integration tests) ----

/// Read a big-endian u64 at offset `o`.
pub fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_be_bytes(a)
}

/// Read a big-endian u128 at offset `o`.
pub fn rd_u128(b: &[u8], o: usize) -> u128 {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    u128::from_be_bytes(a)
}

/// Build the 80-byte anchor cell data: `root(32) ‖ seq(8) ‖ total(16) ‖ fee_acc(16) ‖ last_epoch(8)`.
pub fn anchor(root: &[u8], seq: u64, total: u128, fee: u128, last_epoch: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(80);
    a.extend_from_slice(root);
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(&total.to_be_bytes());
    a.extend_from_slice(&fee.to_be_bytes());
    a.extend_from_slice(&last_epoch.to_be_bytes());
    a
}

/// A CKB `since` flagged absolute-epoch (`0x20` top byte) for whole-epoch `e`.
pub fn abs_epoch(e: u64) -> u64 {
    (0x20u64 << 56) | e
}
