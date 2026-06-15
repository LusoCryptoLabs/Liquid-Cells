//! Timelocked upgrade lock, caps the single-upgrade-key blast radius (ROADMAP / HARDENING).
//!
//! The anchor type script is deployed via type-id, so it is upgradable in place by spending its
//! **code cell**. If that code cell is locked by a plain key, that key can replace the verifier with
//! a malicious one and drain every pool **instantly**, with no window for users to force-exit first.
//! This lock removes the "instant" part: an upgrade may proceed only if it was **announced** at least
//! `delay` epochs earlier, giving every user a guaranteed window to exit before the new code takes
//! effect, turning a sudden rug into a slow, publicly-visible, exit-able event.
//!
//! Mechanism (commit-reveal with a consensus-enforced delay):
//!   * **Announce:** governance creates an *announcement* cell, locked by `governance_lock_hash`,
//!     whose data is the **data hash of the new code cell** it intends to deploy. This is public, so
//!     users see exactly what is coming.
//!   * **Execute (≥ `delay` epochs later):** a tx consumes the old code cell (this lock) **and** the
//!     announcement cell, and creates the new code cell. This lock requires that announcement input
//!     to be (a) locked by `governance_lock_hash`, (b) committing to the new code cell's data hash,
//!     and (c) spent with a **relative-epoch `since` ≥ `delay`**, which CKB consensus only permits
//!     `delay` epochs after the announcement cell was created. Relative since is measured from the
//!     cell's own block, so the delay cannot be backdated.
//!
//! `args` (40 bytes): `governance_lock_hash(32) ‖ delay_epochs(8 BE)`.
#![no_std]
#![no_main]

use ckb_std::ckb_constants::Source;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_data, load_cell_data_hash, load_cell_lock_hash, load_cell_type_hash, load_input_since,
    load_script,
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[path = "atomics.rs"]
mod atomics;

const ARGS_LEN: usize = 40; // governance_lock_hash(32) ‖ delay_epochs(8 BE)

/// Relative-epoch `since`: flagged `0xA0` in the top byte (relative + epoch metric). Returns the
/// relative epoch *number* (low 24 bits), or `None` if it is not a relative-epoch since.
fn rel_epoch(since: u64) -> Option<u64> {
    if (since >> 56) != 0xA0 {
        return None;
    }
    Some(since & 0x00FF_FFFF)
}

fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return 80,
    };
    let args = script.args().raw_data();
    if args.len() != ARGS_LEN {
        return 81;
    }
    let mut gov = [0u8; 32];
    gov.copy_from_slice(&args[0..32]);
    let mut db = [0u8; 8];
    db.copy_from_slice(&args[32..40]);
    let delay = u64::from_be_bytes(db);

    // The code cell being upgraded is identified by its type (the type-id, preserved across
    // upgrades). The new code cell is the OUTPUT carrying that same type.
    let code_type = match load_cell_type_hash(0, Source::GroupInput) {
        Ok(Some(t)) => t,
        _ => return 82, // a code cell must carry a (type-id) type script
    };
    let mut commitment: Option<[u8; 32]> = None;
    let mut j = 0usize;
    loop {
        match load_cell_type_hash(j, Source::Output) {
            Ok(t) => {
                if t.as_ref() == Some(&code_type) {
                    if commitment.is_some() {
                        return 83; // ambiguous: more than one new code cell
                    }
                    commitment = match load_cell_data_hash(j, Source::Output) {
                        Ok(h) => Some(h),
                        Err(_) => return 84,
                    };
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return 84,
        }
    }
    let commitment = match commitment {
        Some(c) => c,
        None => return 85, // no replacement code cell of this type-id in the outputs
    };

    // Require a governance-locked announcement input that committed to exactly this new code, and
    // that has aged ≥ `delay` epochs (relative-epoch since, consensus-enforced, the user window).
    let mut i = 0usize;
    loop {
        match load_cell_lock_hash(i, Source::Input) {
            Ok(lh) => {
                if lh == gov {
                    let data = load_cell_data(i, Source::Input).unwrap_or_default();
                    if data.len() == 32 && data[..] == commitment[..] {
                        let since = match load_input_since(i, Source::Input) {
                            Ok(s) => s,
                            Err(_) => return 86,
                        };
                        match rel_epoch(since) {
                            Some(e) if e >= delay => return 0, // announced, aged ≥ delay, by governance
                            _ => return 87, // announcement not yet matured (or since not relative-epoch)
                        }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return 86,
        }
    }
    88 // no matured governance announcement committing to this upgrade
}
