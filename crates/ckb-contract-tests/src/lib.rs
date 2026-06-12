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
