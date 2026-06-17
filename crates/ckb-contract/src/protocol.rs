//! Cross-binary protocol constants shared by the anchor type script (`main.rs`) and the deposit /
//! upgrade locks (`deposit_lock.rs`, `upgrade_lock.rs`), which are SEPARATE binaries that would
//! otherwise each hard-code these magic numbers and silently drift (committee finding H). Each bin
//! pulls this in (`#[path = "protocol.rs"] mod protocol;`) and references the constant rather than a
//! literal; `main.rs` additionally `assert!`s at compile time that its derived `WITNESS_LEN` equals
//! [`CHECKPOINT_WITNESS_LEN`], so the deposit lock's checkpoint-mode gate cannot drift from the
//! anchor's actual checkpoint witness length.

/// The anchor's CHECKPOINT-mode witness `input_type` length = PROOF_LEN(356) + PV_LEN(288). It is the
/// discriminator the deposit lock uses to allow a sweep ONLY when the anchor input is a checkpoint
/// (which credits the depositor); a force-exit / force-refund anchor input has a different length, so
/// the deposit lock refuses to release into an escape tx (audit H-2). `main.rs` asserts
/// `WITNESS_LEN == CHECKPOINT_WITNESS_LEN`.
pub const CHECKPOINT_WITNESS_LEN: usize = 644;

/// Operator-silence window (in epochs, ~30 days at ~4h/epoch) before the unilateral force-exit /
/// force-refund escape hatch opens. The timelocked upgrade lock requires its `delay_epochs` to
/// EXCEED this, so a user can always force-exit BEFORE any announced code upgrade can land (the
/// "users can always escape a malicious upgrade" guarantee).
pub const FORCE_EXIT_TIMEOUT_EPOCHS: u64 = 180;
