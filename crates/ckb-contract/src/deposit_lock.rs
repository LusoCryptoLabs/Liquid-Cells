//! Liquid Cells **deposit lock**.
//!
//! A deposit cell holds the CKB a user is paying into the pool, with `data[0..32] = to_key`
//! (the SMT key the capacity will credit). The anchor type script's `fold_cells` credits a
//! deposit by reading that `to_key` from the cell's data, *whoever* spends it. So the danger is
//! not mis-crediting, it is the deposit cell's **lock**: an always-success lock lets anyone
//! spend the deposited CKB to themselves before the sequencer sweeps it. This lock closes that
//! window. A deposit can move in exactly two ways:
//!
//!   * **Sweep** (no signature): the spending transaction also consumes a cell carrying this
//!     pool's anchor type script (`pool_type_hash`). That transaction *is* a checkpoint, and the
//!     anchor type script guarantees the deposit is credited to its `to_key`. Anyone may submit
//!     the checkpoint; the credit still goes to the depositor, because `to_key` is immutable cell
//!     data. This is what lets a permissionless sequencer include the deposit without the
//!     depositor's key.
//!   * **Refund** (no signature, after a timeout): if the deposit is never swept, then once the
//!     cell's input `since` reaches `timeout_epoch` (absolute epoch), it may be spent only if the
//!     transaction pays at least the deposited capacity to the depositor's own `refund_lock_hash`.
//!     So an abandoned deposit can always be recovered, and only ever by returning it to the
//!     depositor.
//!
//! Neither path can send the funds to an arbitrary third party. `args` (72 bytes):
//!   `pool_type_hash(32) ‖ refund_lock_hash(32) ‖ timeout_epoch(8 BE)`
//!
//! Note: `pool_type_hash` is the anchor type-script *hash*. It is pool-unique only if the anchor
//! carries a type-id in its args (recommended for mainnet). Under v1's empty-args pools all pools
//! of this contract share a type hash, so a deposit could in principle be swept into a different
//! pool of the same contract, still crediting the depositor's `to_key` there, recoverable by
//! force-exit. Binding to a type-id'd anchor removes even that. The theft window (funds to an
//! arbitrary party) is closed regardless.

#![no_std]
#![no_main]

use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_lock_hash, load_cell_type_hash, load_input_since, load_script,
};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

#[path = "atomics.rs"]
mod atomics;

const ARGS_LEN: usize = 72; // pool_type_hash(32) ‖ refund_lock_hash(32) ‖ timeout_epoch(8 BE)

/// Extract the epoch number from a CKB `since` flagged **absolute epoch** (`0x20` top byte).
/// Whole-epoch granularity (the index/length fraction is ignored). `None` if not absolute-epoch.
/// Matches `abs_epoch` in the anchor type script and the deposit test's `abs_epoch` helper.
fn abs_epoch(since: u64) -> Option<u64> {
    if (since >> 56) != 0x20 {
        return None;
    }
    Some(since & 0x00FF_FFFF)
}

fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return 90,
    };
    let args = script.args().raw_data();
    if args.len() != ARGS_LEN {
        return 91;
    }
    let mut pool_type_hash = [0u8; 32];
    pool_type_hash.copy_from_slice(&args[0..32]);
    let mut refund_lock_hash = [0u8; 32];
    refund_lock_hash.copy_from_slice(&args[32..64]);
    let mut tb = [0u8; 8];
    tb.copy_from_slice(&args[64..72]);
    let timeout = u64::from_be_bytes(tb);

    // --- Path A: sweep into a checkpoint of THIS pool. ---
    // Any input bearing the pool anchor type script means a checkpoint of this pool is running;
    // its anchor type script enforces that this deposit is credited to its `to_key`.
    let mut i = 0usize;
    loop {
        match load_cell_type_hash(i, Source::Input) {
            Ok(th) => {
                if th == Some(pool_type_hash) {
                    return 0;
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return 92,
        }
    }

    // --- Path B: refund to the depositor after the timeout. ---
    // Sum this lock group's input capacities, require every group input's `since` to be an
    // absolute epoch >= timeout, then require outputs to `refund_lock_hash` to cover the sum.
    let mut owed: u128 = 0;
    let mut g = 0usize;
    loop {
        match load_cell_capacity(g, Source::GroupInput) {
            Ok(cap) => {
                let since = match load_input_since(g, Source::GroupInput) {
                    Ok(s) => s,
                    Err(_) => return 92,
                };
                match abs_epoch(since) {
                    Some(e) if e >= timeout => {}
                    _ => return 93, // not yet refundable (or `since` not absolute-epoch)
                }
                owed = match owed.checked_add(cap as u128) {
                    Some(v) => v,
                    None => return 92,
                };
                g += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return 92,
        }
    }

    let mut paid: u128 = 0;
    let mut j = 0usize;
    loop {
        match load_cell_lock_hash(j, Source::Output) {
            Ok(lh) => {
                if lh == refund_lock_hash {
                    if let Ok(cap) = load_cell_capacity(j, Source::Output) {
                        paid = paid.saturating_add(cap as u128);
                    }
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return 92,
        }
    }

    if paid >= owed {
        0
    } else {
        94 // refund does not return the full deposit to the depositor's lock
    }
}
