//! The unilateral escape hatch, lifted from `main.rs`: `force_exit` (an ordinary account leaf)
//! and `force_refund` (a timed-out HTLC escrow), plus the keccak-SMT primitives they share. No
//! SP1 proof, an SMT inclusion path against the last committed root, gated on operator silence,
//! paying out only to the owner's own secp lock. Reaches `main.rs`'s constants and shared
//! helpers (keccak, rd_u64/rd_u128, abs_epoch) via `use super::*`.

use super::*; // main.rs's constants, shared helpers (keccak, rd_u64/rd_u128, abs_epoch), and ckb_std imports

// ---- force-exit primitives ----

/// Bit `i` of a 32-byte key, MSB-first (matches `liquid_cells_stf::smt::bit`).
#[inline]
fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

/// Leaf-content hash, matching `liquid_cells_stf::types::Leaf::hash`: empty `{0,0}` hashes
/// to the all-zero `EMPTY_LEAF`; otherwise keccak(balance(16 BE) ‖ nonce(8 BE)).
fn leaf_hash(balance: u128, nonce: u64) -> [u8; 32] {
    if balance == 0 && nonce == 0 {
        return [0u8; 32];
    }
    let mut enc = [0u8; 24];
    enc[..16].copy_from_slice(&balance.to_be_bytes());
    enc[16..].copy_from_slice(&nonce.to_be_bytes());
    keccak(&enc)
}

/// Reconstruct the SMT root from a single-leaf inclusion path, bottom-up, the exact walk
/// `liquid_cells_stf::smt::verify_proof` performs. `siblings` is 256 × 32 bytes top-down.
fn smt_root(key: &[u8; 32], leaf: &[u8; 32], siblings: &[u8]) -> [u8; 32] {
    let mut cur = *leaf;
    let mut depth = SMT_DEPTH;
    while depth > 0 {
        depth -= 1;
        let sib = &siblings[depth * 32..depth * 32 + 32];
        let mut buf = [0u8; 64];
        if bit(key, depth) == 0 {
            buf[..32].copy_from_slice(&cur);
            buf[32..].copy_from_slice(sib);
        } else {
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&cur);
        }
        cur = keccak(&buf);
    }
    cur
}

/// blake160(data) = first 20 bytes of CKB's default blake2b-256, the secp lock's args.
fn blake160(data: &[u8]) -> [u8; 20] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..20]);
    r
}

/// Is there an output paying exactly `amount` to the owner's canonical secp lock
/// (`code_hash == SECP_CODE_HASH`, hash_type == Type, `args == b160`)?
fn has_exit_output(b160: &[u8; 20], amount: u64) -> bool {
    let mut i = 0usize;
    loop {
        match load_cell_lock(i, Source::Output) {
            Ok(lock) => {
                if lock.code_hash().as_slice() == &SECP_CODE_HASH[..]
                    && lock.hash_type().as_slice()[0] == 1
                    && lock.args().raw_data().as_ref() == &b160[..]
                {
                    if let Ok(cap) = load_cell_capacity(i, Source::Output) {
                        if cap == amount {
                            return true;
                        }
                    }
                }
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => return false,
            Err(_) => return false,
        }
    }
}

/// Force-exit (escape hatch): a user unilaterally withdraws their leaf against the last
/// committed root after the operator has been silent for `FORCE_EXIT_TIMEOUT_EPOCHS`. No
/// SP1 proof; the witness carries `pubkey ‖ balance ‖ nonce ‖ siblings`. The payout is
/// forced to the owner's own secp lock, the leaf is nullified (balance→0, nonce kept), and
/// the anchor capacity/total drop by exactly the exited balance.
pub(crate) fn force_exit(prev: &[u8], new: &[u8], wb: &[u8]) -> i8 {
    let pubkey = &wb[0..33];
    let balance = rd_u128(wb, 33);
    let nonce = rd_u64(wb, 49);
    let siblings = &wb[57..57 + 32 * SMT_DEPTH];
    if balance == 0 {
        return 60; // nothing to exit
    }
    if balance > u64::MAX as u128 {
        return 61; // cannot be paid out as a single capacity
    }

    let key = keccak(pubkey);
    // Inclusion of {balance, nonce} against the committed (input) root.
    let leaf = leaf_hash(balance, nonce);
    if smt_root(&key, &leaf, siblings)[..] != prev[A_ROOT..A_ROOT + 32] {
        return 62;
    }
    // Nullified root: balance→0, nonce kept (replay-safe), same siblings ⇒ output root.
    let new_leaf = leaf_hash(0, nonce);
    if smt_root(&key, &new_leaf, siblings)[..] != new[A_ROOT..A_ROOT + 32] {
        return 63;
    }

    // Anchor continuity: seq / fee_acc / last_epoch unchanged; total -= balance.
    if rd_u64(prev, A_SEQ) != rd_u64(new, A_SEQ)
        || rd_u128(prev, A_FEE) != rd_u128(new, A_FEE)
        || rd_u64(prev, A_LAST_EPOCH) != rd_u64(new, A_LAST_EPOCH)
        || rd_u128(prev, A_TOTAL).checked_sub(balance) != Some(rd_u128(new, A_TOTAL))
    {
        return 64;
    }

    // Solvency: the anchor's real capacity drops by exactly the exited balance.
    let in_cap = match load_cell_capacity(0, Source::GroupInput) {
        Ok(c) => c,
        Err(_) => return 65,
    };
    let out_cap = match load_cell_capacity(0, Source::GroupOutput) {
        Ok(c) => c,
        Err(_) => return 65,
    };
    if in_cap.checked_sub(balance as u64) != Some(out_cap) {
        return 65;
    }

    // Timeout: only after operator silence. Input `since` (absolute epoch) must be at least
    // `last_epoch + TIMEOUT`; CKB consensus refuses to mine the tx any earlier.
    let since = match load_input_since(0, Source::GroupInput) {
        Ok(s) => s,
        Err(_) => return 66,
    };
    let since_epoch = match abs_epoch(since) {
        Some(e) => e,
        None => return 66,
    };
    let open_at = match rd_u64(prev, A_LAST_EPOCH).checked_add(FORCE_EXIT_TIMEOUT_EPOCHS) {
        Some(e) => e,
        None => return 66,
    };
    if since_epoch < open_at {
        return 66;
    }

    // Payout: an output paying exactly `balance` to the owner's canonical secp lock.
    if !has_exit_output(&blake160(pubkey), balance as u64) {
        return 67;
    }
    0
}

/// Recompute an HTLC escrow leaf's SMT key, byte-identical to
/// `liquid_cells_stf::types::htlc_id`:
///   keccak( keccak("LIQUIDCELLS/v1/htlc-id") ‖ POOL_ID ‖ sender_key ‖ receiver_key
///           ‖ amount(16 BE) ‖ hashlock ‖ timeout(8 BE) ‖ lock_nonce(8 BE) ).
/// Binding the key to every lock term is what lets the escrow only ever resolve to the
/// agreed parties on the agreed terms, so a force-refund must supply the real terms and
/// can only pay the real sender.
fn htlc_id(
    sender_key: &[u8; 32],
    receiver_key: &[u8],
    amount: u128,
    hashlock: &[u8],
    timeout: u64,
    lock_nonce: u64,
) -> [u8; 32] {
    let domain = keccak(b"LIQUIDCELLS/v1/htlc-id");
    let mut b = [0u8; 192]; // 32+32+32+32+16+32+8+8
    b[0..32].copy_from_slice(&domain);
    b[32..64].copy_from_slice(&POOL_ID);
    b[64..96].copy_from_slice(sender_key);
    b[96..128].copy_from_slice(receiver_key);
    b[128..144].copy_from_slice(&amount.to_be_bytes());
    b[144..176].copy_from_slice(hashlock);
    b[176..184].copy_from_slice(&timeout.to_be_bytes());
    b[184..192].copy_from_slice(&lock_nonce.to_be_bytes());
    keccak(&b)
}

/// Force-refund (escape hatch for a pending HTLC escrow): the *sender* unilaterally reclaims
/// a **timed-out** escrow leaf against the last committed root, after operator silence. The
/// witness carries the full lock terms; the script re-derives the escrow's `htlc_id`, proves
/// the `{balance = amount, nonce = 0}` escrow leaf is included under the committed root, then
/// nullifies it (→ empty) and forces the payout to the *sender's* own secp lock.
///
/// Two timeout gates, both required:
///   * `since ≥ timeout`, the HTLC's own deadline. After it, the receiver can no longer claim
///     (claim-after-timeout is invalid in the STF), so refund-to-sender is the *only* valid
///     resolution; refunding before it could rob a receiver who still holds a valid claim.
///   * `since ≥ last_epoch + FORCE_EXIT_TIMEOUT_EPOCHS`, operator silence, as for force-exit.
///     Any anchor-consuming op conflicts with a live operator's checkpoint, so the escape
///     hatch only opens once the operator is demonstrably dark; while it checkpoints, the
///     cooperative `htlc_refund` is the path. (Because the silence window ≫ a dust HTLC's
///     lifetime, the silence gate is the operative one here.)
///
/// Deliberately sender-only. The receiver's symmetric "force-claim" would need to fire
/// *before* the short `timeout`, but the silence gate cannot open that fast, so a receiver's
/// trustless on-chain claim is not expressible under a single anchor. That residual is
/// architectural (resolved by Phase 6 permissionless sequencing), not a gap in this code;
/// the swap counterparty mitigates it by only swapping while the operator is demonstrably
/// live. See docs/EGRESS.md.
pub(crate) fn force_refund(prev: &[u8], new: &[u8], wb: &[u8]) -> i8 {
    // sender_pubkey(33) ‖ receiver_key(32) ‖ amount(16) ‖ hashlock(32) ‖ timeout(8) ‖
    // lock_nonce(8) ‖ siblings(256·32)
    let sender_pubkey = &wb[0..33];
    let receiver_key = &wb[33..65];
    let amount = rd_u128(wb, 65);
    let hashlock = &wb[81..113];
    let timeout = rd_u64(wb, 113);
    let lock_nonce = rd_u64(wb, 121);
    let siblings = &wb[129..129 + 32 * SMT_DEPTH];

    if amount == 0 {
        return 80; // an escrow always holds a positive amount
    }
    if amount > u64::MAX as u128 {
        return 81; // cannot be paid out as a single capacity
    }

    let sender_key = keccak(sender_pubkey);
    let id = htlc_id(&sender_key, receiver_key, amount, hashlock, timeout, lock_nonce);

    // Inclusion of the escrow leaf {balance = amount, nonce = 0} at `id` vs the committed root.
    let leaf = leaf_hash(amount, 0);
    if smt_root(&id, &leaf, siblings)[..] != prev[A_ROOT..A_ROOT + 32] {
        return 82;
    }
    // Nullified: the escrow → empty {0, 0}; same siblings ⇒ the output root. A returning
    // operator that re-syncs to this root sees the escrow consumed (no double-refund), and
    // the same `htlc_id` cannot recur (it binds the sender's account nonce at lock time).
    let new_leaf = leaf_hash(0, 0);
    if smt_root(&id, &new_leaf, siblings)[..] != new[A_ROOT..A_ROOT + 32] {
        return 83;
    }

    // Anchor continuity: seq / fee_acc / last_epoch unchanged; total -= amount.
    if rd_u64(prev, A_SEQ) != rd_u64(new, A_SEQ)
        || rd_u128(prev, A_FEE) != rd_u128(new, A_FEE)
        || rd_u64(prev, A_LAST_EPOCH) != rd_u64(new, A_LAST_EPOCH)
        || rd_u128(prev, A_TOTAL).checked_sub(amount) != Some(rd_u128(new, A_TOTAL))
    {
        return 84;
    }

    // Solvency: the anchor's real capacity drops by exactly the refunded amount.
    let in_cap = match load_cell_capacity(0, Source::GroupInput) {
        Ok(c) => c,
        Err(_) => return 85,
    };
    let out_cap = match load_cell_capacity(0, Source::GroupOutput) {
        Ok(c) => c,
        Err(_) => return 85,
    };
    if in_cap.checked_sub(amount as u64) != Some(out_cap) {
        return 85;
    }

    // Timeout gates: the input `since` (absolute epoch) must be ≥ BOTH the HTLC's own
    // `timeout` and `last_epoch + FORCE_EXIT_TIMEOUT_EPOCHS` (operator silence).
    let since = match load_input_since(0, Source::GroupInput) {
        Ok(s) => s,
        Err(_) => return 86,
    };
    let since_epoch = match abs_epoch(since) {
        Some(e) => e,
        None => return 86,
    };
    if since_epoch < timeout {
        return 86;
    }
    let open_at = match rd_u64(prev, A_LAST_EPOCH).checked_add(FORCE_EXIT_TIMEOUT_EPOCHS) {
        Some(e) => e,
        None => return 86,
    };
    if since_epoch < open_at {
        return 86;
    }

    // Payout: an output paying exactly `amount` to the *sender's* canonical secp lock.
    if !has_exit_output(&blake160(sender_pubkey), amount as u64) {
        return 87;
    }
    0
}
