//! Data availability: the canonical, on-chain-published state diff that makes
//! Liquid Cells trustless against **data withholding**.
//!
//! Each checkpoint commits `da_commitment = keccak(da_blob)` in its public values,
//! computed *in-circuit* from the post-state of the leaves the batch touched (see
//! [`crate::transition`]). The anchor type script binds that commitment to the blob
//! bytes the checkpoint transaction carries in its witness. Because the commitment is
//! proven from the real post-states and keccak is collision-resistant, a valid
//! checkpoint is **forced to publish the true diff**, the operator cannot advance the
//! root while hiding what changed.
//!
//! That is exactly what unilateral exit needs: replaying every checkpoint's blob from
//! genesis (oldest first) rebuilds the *exact* tree, so any user can recover their leaf
//! and a force-exit inclusion proof from L1 data alone, with no cooperation from the
//! sequencer. [`reconstruct`] is that independent verifier.

use crate::hash::{keccak, Hash};
#[cfg(not(feature = "compact_smt"))]
use crate::smt::Smt;
#[cfg(feature = "compact_smt")]
use crate::smt_compact::Smt;
use crate::types::Leaf;

/// Bytes per leaf record in the **deployed fixed layout**: `key(32) ‖ balance(16 BE) ‖
/// nonce(8 BE)`. Under the staged `da_varint` feature, `balance`/`nonce` are LEB128
/// varint-encoded instead (the key stays a fixed 32-byte hash), so a record shrinks from 56
/// bytes to ~33-35 for typical small values; this is only a capacity hint then.
pub const DA_RECORD_LEN: usize = 32 + 16 + 8;

/// Canonical DA blob for one checkpoint: the post-state of the batch's touched leaves,
/// **sorted ascending by key**. `keccak` of this equals `PublicValues::da_commitment`. The
/// deployed layout is fixed-width; the staged `da_varint` feature varint-encodes the amounts
/// (smaller recurring on-chain footprint, re-bakes the vkey, so OFF in the deployed guest).
pub fn encode_da_blob(post_state_sorted: &[(Hash, Leaf)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(post_state_sorted.len() * DA_RECORD_LEN);
    for (k, leaf) in post_state_sorted {
        b.extend_from_slice(k);
        #[cfg(not(feature = "da_varint"))]
        b.extend_from_slice(&leaf.balance.to_be_bytes());
        #[cfg(not(feature = "da_varint"))]
        b.extend_from_slice(&leaf.nonce.to_be_bytes());
        #[cfg(feature = "da_varint")]
        write_uvarint(&mut b, leaf.balance);
        #[cfg(feature = "da_varint")]
        write_uvarint(&mut b, leaf.nonce as u128);
    }
    b
}

/// LEB128 unsigned varint append (canonical/minimal encoding; `0` is a single `0x00`).
#[cfg(feature = "da_varint")]
fn write_uvarint(out: &mut Vec<u8>, mut v: u128) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// LEB128 unsigned varint read at `*pos`, advancing it. `None` on truncation or an
/// over-wide encoding (never panics, so a malformed/adversarial blob just fails to parse,
/// and the root-equality check at the call site rejects it).
#[cfg(feature = "da_varint")]
fn read_uvarint(data: &[u8], pos: &mut usize) -> Option<u128> {
    let mut result: u128 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        let chunk = (byte & 0x7f) as u128;
        result = result.checked_add(chunk.checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift = shift.checked_add(7)?;
        if shift >= 128 {
            return None; // wider than u128
        }
    }
}

/// The DA commitment a checkpoint commits in its public values = `keccak(blob)`.
pub fn da_commitment(blob: &[u8]) -> Hash {
    keccak(blob)
}

/// One parsed `(key, post-state leaf)` record from a DA blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaRecord {
    pub key: Hash,
    pub leaf: Leaf,
}

/// Parse a DA blob into its leaf records. `None` on a malformed blob (a partial fixed
/// record, or a truncated/over-wide varint under `da_varint`). The inverse of
/// [`encode_da_blob`] under whichever layout is compiled.
pub fn parse_da_blob(blob: &[u8]) -> Option<Vec<DaRecord>> {
    #[cfg(not(feature = "da_varint"))]
    {
        if blob.len() % DA_RECORD_LEN != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(blob.len() / DA_RECORD_LEN);
        for rec in blob.chunks(DA_RECORD_LEN) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&rec[..32]);
            let mut bal = [0u8; 16];
            bal.copy_from_slice(&rec[32..48]);
            let mut non = [0u8; 8];
            non.copy_from_slice(&rec[48..56]);
            out.push(DaRecord {
                key,
                leaf: Leaf { balance: u128::from_be_bytes(bal), nonce: u64::from_be_bytes(non) },
            });
        }
        Some(out)
    }
    #[cfg(feature = "da_varint")]
    {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < blob.len() {
            if pos + 32 > blob.len() {
                return None; // partial key
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&blob[pos..pos + 32]);
            pos += 32;
            let balance = read_uvarint(blob, &mut pos)?;
            let nonce = read_uvarint(blob, &mut pos)?;
            if nonce > u64::MAX as u128 {
                return None; // nonce out of range
            }
            out.push(DaRecord { key, leaf: Leaf { balance, nonce: nonce as u64 } });
        }
        Some(out)
    }
}

/// Independently reconstruct the pool tree from an ordered sequence of checkpoint DA
/// blobs (**oldest first**), with no access to the sequencer. Replaying each blob's
/// post-state records yields the exact tree: `smt.root()` then equals the latest
/// on-chain anchor root, and `smt.proof(key)` is a force-exit-ready inclusion proof.
/// `None` if any blob is malformed.
pub fn reconstruct(blobs: &[Vec<u8>]) -> Option<Smt> {
    let mut smt = Smt::new();
    for blob in blobs {
        for rec in parse_da_blob(blob)? {
            smt.set_leaf_hash(rec.key, rec.leaf.hash());
        }
    }
    Some(smt)
}
