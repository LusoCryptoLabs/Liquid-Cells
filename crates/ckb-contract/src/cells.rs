//! Checkpoint-mode cell logic, lifted from `main.rs` for readability: recompute the
//! deposits/withdrawals commitments from the real input/output cells, and pin the proven
//! public values to the input/output anchor cell data. Reaches `main.rs`'s constants and
//! shared helpers (keccak, rd_u64/rd_u128) via `use super::*`.

use super::*; // main.rs's constants, shared helpers, and ckb_std imports

/// Must match liquid_cells_stf::transition::fold_commit: keccak(acc ‖ key ‖ amount_be).
fn fold_commit(acc: &[u8; 32], key: &[u8; 32], amount: u128) -> [u8; 32] {
    let mut b = [0u8; 80];
    b[..32].copy_from_slice(acc);
    b[32..64].copy_from_slice(key);
    b[64..].copy_from_slice(&amount.to_be_bytes());
    keccak(&b)
}

/// A non-anchor OUTPUT whose data begins with this marker is a **sequencer reward** cell
/// (Phase 6b), not a user withdrawal. It is paid out of the proven `fee_withdrawal` (the rest
/// of which is the L1 miner fee), so it is excluded from the withdrawals commitment and bounded
/// by `fee_withdrawal` in `checkpoint()`. Marking a real withdrawal as reward (or vice versa)
/// breaks the withdrawals-commitment match, so the marking is self-enforcing.
static REWARD_MARKER: &[u8] = b"LIQUIDCELLS/v1/fee-reward";

/// Recompute the deposits/withdrawals commitments from the real cells, and sum their
/// amounts. Implicit format: a **deposit** is any non-anchor INPUT (credits
/// `data[0..32]` = to_key by its capacity); a **withdrawal** is any non-anchor OUTPUT
/// (pays its `lock_hash` its capacity) that is not a reward cell. Returns
/// `(deposits_commitment, withdrawals_commitment, sum_deposits, sum_withdrawals, sum_reward)`.
/// The anchor is the cell whose type script is this one.
pub(crate) fn fold_cells(self_hash: &[u8; 32]) -> Result<([u8; 32], [u8; 32], i128, i128, i128), i8> {
    let mut dep = keccak(b"LIQUIDCELLS/v1/deposits-commitment");
    let mut sum_dep: i128 = 0;
    let mut i = 0usize;
    loop {
        match load_cell_capacity(i, Source::Input) {
            Ok(cap) => {
                let th = load_cell_type_hash(i, Source::Input).map_err(|_| 50i8)?;
                if th.as_ref() != Some(self_hash) {
                    let data = load_cell_data(i, Source::Input).map_err(|_| 50i8)?;
                    if data.len() < 32 {
                        return Err(51);
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&data[..32]);
                    dep = fold_commit(&dep, &key, cap as u128);
                    sum_dep += cap as i128;
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(50),
        }
    }
    let mut wd = keccak(b"LIQUIDCELLS/v1/withdrawals-commitment");
    let mut sum_wd: i128 = 0;
    let mut sum_reward: i128 = 0;
    let mut j = 0usize;
    loop {
        match load_cell_capacity(j, Source::Output) {
            Ok(cap) => {
                let th = load_cell_type_hash(j, Source::Output).map_err(|_| 52i8)?;
                if th.as_ref() != Some(self_hash) {
                    let data = load_cell_data(j, Source::Output).map_err(|_| 52i8)?;
                    if data.len() >= REWARD_MARKER.len() && &data[..REWARD_MARKER.len()] == REWARD_MARKER
                    {
                        // Sequencer reward: paid out of fee_withdrawal, not a user withdrawal.
                        sum_reward += cap as i128;
                    } else {
                        let lh = load_cell_lock_hash(j, Source::Output).map_err(|_| 52i8)?;
                        wd = fold_commit(&wd, &lh, cap as u128);
                        sum_wd += cap as i128;
                    }
                }
                j += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(52),
        }
    }
    Ok((dep, wd, sum_dep, sum_wd, sum_reward))
}

/// Pin the public values to the anchor cells. Cheap; runs before the proof verify so
/// a tampered transaction is rejected without paying for the BN254 pairing.
pub(crate) fn bind(prev: &[u8], new: &[u8], pv: &[u8]) -> i8 {
    if pv.len() != PV_LEN || prev.len() != ANCHOR_LEN || new.len() != ANCHOR_LEN {
        return 30;
    }
    if pv[PV_POOL_ID..PV_POOL_ID + 32] != POOL_ID {
        return 31;
    }
    if rd_u64(pv, PV_CHAIN_ID) != CHAIN_ID {
        return 32;
    }
    let prev_seq = rd_u64(pv, PV_PREV_SEQ);
    let new_seq = rd_u64(pv, PV_NEW_SEQ);
    if prev_seq.checked_add(1) != Some(new_seq) {
        return 33;
    }
    // input anchor == prev_*
    if prev[A_ROOT..A_ROOT + 32] != pv[PV_PREV_ROOT..PV_PREV_ROOT + 32] {
        return 34;
    }
    if rd_u64(prev, A_SEQ) != prev_seq {
        return 35;
    }
    if rd_u128(prev, A_TOTAL) != rd_u128(pv, PV_PREV_TOTAL) {
        return 36;
    }
    // output anchor == new_*
    if new[A_ROOT..A_ROOT + 32] != pv[PV_NEW_ROOT..PV_NEW_ROOT + 32] {
        return 37;
    }
    if rd_u64(new, A_SEQ) != new_seq {
        return 38;
    }
    if rd_u128(new, A_TOTAL) != rd_u128(pv, PV_NEW_TOTAL) {
        return 39;
    }
    // fee accumulator continuity with the L1 fee draw:
    //   new_fee_acc == prev_fee_acc + fee_delta − fee_withdrawal,
    // and fee_withdrawal ≤ prev_fee_acc + fee_delta (no drawing from user balances).
    let fee_avail = match rd_u128(prev, A_FEE).checked_add(rd_u128(pv, PV_FEE_DELTA)) {
        Some(a) => a,
        None => return 43,
    };
    let fee_wd = rd_u128(pv, PV_FEE_WD);
    if fee_wd > fee_avail || fee_avail - fee_wd != rd_u128(new, A_FEE) {
        return 43;
    }
    // epoch continuity: the checkpoint records its epoch into the output anchor, this is
    // the clock the force-exit timeout reads. `new.last_epoch == current_epoch`, and
    // epochs never go backward. (The `since` check in `checkpoint` proves the recorded
    // epoch is not in the future.)
    let cur_epoch = rd_u64(pv, PV_CURRENT_EPOCH);
    if rd_u64(new, A_LAST_EPOCH) != cur_epoch || cur_epoch < rd_u64(prev, A_LAST_EPOCH) {
        return 44;
    }
    0
}
