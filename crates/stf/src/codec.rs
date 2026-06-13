//! Manual canonical (de)serialization for guest I/O.
//!
//! No serde/bincode: explicit big-endian, length-prefixed bytes. This keeps the
//! "everything serialized has an explicit layout" discipline (same reason roots and
//! digests are hand-encoded), avoids the fixed-array (`[u8; 33]`/`[u8; 64]`) serde
//! friction, and is cheap to decode inside the zkVM.
//!
//! The host encodes `(prev, witness, batch)` into the guest's stdin; the guest
//! decodes it, runs [`crate::prove_transition`], and commits the public values,
//! which the host decodes back with [`decode_public_values`].

use crate::hash::Hash;
use crate::transition::Witness;
use crate::types::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    Eof,
    Trailing,
    TooLong,
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.p.checked_add(n).ok_or(CodecError::TooLong)?;
        if end > self.b.len() {
            return Err(CodecError::Eof);
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, CodecError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn a32(&mut self) -> Result<[u8; 32], CodecError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn a33(&mut self) -> Result<[u8; 33], CodecError> {
        Ok(self.take(33)?.try_into().unwrap())
    }
    fn a64(&mut self) -> Result<[u8; 64], CodecError> {
        Ok(self.take(64)?.try_into().unwrap())
    }
    fn finish(&self) -> Result<(), CodecError> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err(CodecError::Trailing)
        }
    }
}

fn put_len(o: &mut Vec<u8>, n: usize) {
    o.extend_from_slice(&(n as u32).to_be_bytes());
}

// ---- field encoders ----

fn enc_pool(o: &mut Vec<u8>, p: &PoolState) {
    o.extend_from_slice(&p.pool_id);
    o.extend_from_slice(&p.chain_id.to_be_bytes());
    o.extend_from_slice(&p.seq.to_be_bytes());
    o.extend_from_slice(&p.root);
    o.extend_from_slice(&p.total.to_be_bytes());
    o.extend_from_slice(&p.fee_acc.to_be_bytes());
}
fn dec_pool(r: &mut R) -> Result<PoolState, CodecError> {
    Ok(PoolState {
        pool_id: r.a32()?,
        chain_id: r.u64()?,
        seq: r.u64()?,
        root: r.a32()?,
        total: r.u128()?,
        fee_acc: r.u128()?,
    })
}

fn enc_leaf(o: &mut Vec<u8>, l: &Leaf) {
    o.extend_from_slice(&l.balance.to_be_bytes());
    o.extend_from_slice(&l.nonce.to_be_bytes());
}
fn dec_leaf(r: &mut R) -> Result<Leaf, CodecError> {
    Ok(Leaf { balance: r.u128()?, nonce: r.u64()? })
}

fn enc_witness(o: &mut Vec<u8>, w: &Witness) {
    put_len(o, w.leaves.len());
    for (k, l) in &w.leaves {
        o.extend_from_slice(k);
        enc_leaf(o, l);
    }
    put_len(o, w.siblings.len());
    for s in &w.siblings {
        o.extend_from_slice(s);
    }
}
fn dec_witness(r: &mut R) -> Result<Witness, CodecError> {
    let nl = r.u32()? as usize;
    let mut leaves = Vec::with_capacity(nl);
    for _ in 0..nl {
        let k: Hash = r.a32()?;
        leaves.push((k, dec_leaf(r)?));
    }
    let ns = r.u32()? as usize;
    let mut siblings = Vec::with_capacity(ns);
    for _ in 0..ns {
        siblings.push(r.a32()?);
    }
    Ok(Witness { leaves, siblings })
}

fn enc_htlc_ref(o: &mut Vec<u8>, h: &HtlcRef) {
    o.extend_from_slice(&h.sender_key);
    o.extend_from_slice(&h.receiver_key);
    o.extend_from_slice(&h.amount.to_be_bytes());
    o.extend_from_slice(&h.hashlock);
    o.extend_from_slice(&h.timeout.to_be_bytes());
    o.extend_from_slice(&h.lock_nonce.to_be_bytes());
}
fn dec_htlc_ref(r: &mut R) -> Result<HtlcRef, CodecError> {
    Ok(HtlcRef {
        sender_key: r.a32()?,
        receiver_key: r.a32()?,
        amount: r.u128()?,
        hashlock: r.a32()?,
        timeout: r.u64()?,
        lock_nonce: r.u64()?,
    })
}

fn enc_batch(o: &mut Vec<u8>, b: &Batch) {
    o.extend_from_slice(&b.current_epoch.to_be_bytes());
    o.extend_from_slice(&b.fee_withdrawal.to_be_bytes());
    put_len(o, b.deposits.len());
    for d in &b.deposits {
        o.extend_from_slice(&d.to_key);
        o.extend_from_slice(&d.amount.to_be_bytes());
    }
    put_len(o, b.transfers.len());
    for t in &b.transfers {
        o.extend_from_slice(&t.from_pubkey);
        o.extend_from_slice(&t.to_key);
        o.extend_from_slice(&t.amount.to_be_bytes());
        o.extend_from_slice(&t.fee.to_be_bytes());
        o.extend_from_slice(&t.nonce.to_be_bytes());
        o.extend_from_slice(&t.expiry.to_be_bytes());
        o.extend_from_slice(&t.sig);
    }
    put_len(o, b.htlc_locks.len());
    for l in &b.htlc_locks {
        o.extend_from_slice(&l.sender_pubkey);
        o.extend_from_slice(&l.receiver_key);
        o.extend_from_slice(&l.amount.to_be_bytes());
        o.extend_from_slice(&l.fee.to_be_bytes());
        o.extend_from_slice(&l.hashlock);
        o.extend_from_slice(&l.timeout.to_be_bytes());
        o.extend_from_slice(&l.nonce.to_be_bytes());
        o.extend_from_slice(&l.sig);
    }
    put_len(o, b.htlc_claims.len());
    for c in &b.htlc_claims {
        enc_htlc_ref(o, &c.htlc);
        put_len(o, c.preimage.len());
        o.extend_from_slice(&c.preimage);
    }
    put_len(o, b.htlc_refunds.len());
    for rf in &b.htlc_refunds {
        enc_htlc_ref(o, &rf.htlc);
    }
    put_len(o, b.withdrawals.len());
    for w in &b.withdrawals {
        o.extend_from_slice(&w.from_pubkey);
        o.extend_from_slice(&w.target_lock_hash);
        o.extend_from_slice(&w.amount.to_be_bytes());
        o.extend_from_slice(&w.nonce.to_be_bytes());
        o.extend_from_slice(&w.expiry.to_be_bytes());
        o.extend_from_slice(&w.sig);
    }
}
fn dec_batch(r: &mut R) -> Result<Batch, CodecError> {
    let current_epoch = r.u64()?;
    let fee_withdrawal = r.u128()?;
    let nd = r.u32()? as usize;
    let mut deposits = Vec::with_capacity(nd);
    for _ in 0..nd {
        deposits.push(Deposit { to_key: r.a32()?, amount: r.u128()? });
    }
    let nt = r.u32()? as usize;
    let mut transfers = Vec::with_capacity(nt);
    for _ in 0..nt {
        transfers.push(Transfer {
            from_pubkey: r.a33()?,
            to_key: r.a32()?,
            amount: r.u128()?,
            fee: r.u128()?,
            nonce: r.u64()?,
            expiry: r.u64()?,
            sig: r.a64()?,
        });
    }
    let nl = r.u32()? as usize;
    let mut htlc_locks = Vec::with_capacity(nl);
    for _ in 0..nl {
        htlc_locks.push(HtlcLock {
            sender_pubkey: r.a33()?,
            receiver_key: r.a32()?,
            amount: r.u128()?,
            fee: r.u128()?,
            hashlock: r.a32()?,
            timeout: r.u64()?,
            nonce: r.u64()?,
            sig: r.a64()?,
        });
    }
    let nc = r.u32()? as usize;
    let mut htlc_claims = Vec::with_capacity(nc);
    for _ in 0..nc {
        let href = dec_htlc_ref(r)?;
        let plen = r.u32()? as usize;
        let preimage = r.take(plen)?.to_vec();
        htlc_claims.push(HtlcClaim { htlc: href, preimage });
    }
    let nrf = r.u32()? as usize;
    let mut htlc_refunds = Vec::with_capacity(nrf);
    for _ in 0..nrf {
        htlc_refunds.push(HtlcRefund { htlc: dec_htlc_ref(r)? });
    }
    let nw = r.u32()? as usize;
    let mut withdrawals = Vec::with_capacity(nw);
    for _ in 0..nw {
        withdrawals.push(Withdrawal {
            from_pubkey: r.a33()?,
            target_lock_hash: r.a32()?,
            amount: r.u128()?,
            nonce: r.u64()?,
            expiry: r.u64()?,
            sig: r.a64()?,
        });
    }
    Ok(Batch {
        current_epoch,
        fee_withdrawal,
        deposits,
        transfers,
        htlc_locks,
        htlc_claims,
        htlc_refunds,
        withdrawals,
    })
}

// ---- public entry points ----

/// Encode the guest's full input bundle: `(prev, witness, batch)`.
pub fn encode_input(prev: &PoolState, witness: &Witness, batch: &Batch) -> Vec<u8> {
    let mut o = Vec::new();
    enc_pool(&mut o, prev);
    enc_witness(&mut o, witness);
    enc_batch(&mut o, batch);
    o
}

/// Decode the guest's input bundle.
pub fn decode_input(bytes: &[u8]) -> Result<(PoolState, Witness, Batch), CodecError> {
    let mut r = R::new(bytes);
    let prev = dec_pool(&mut r)?;
    let witness = dec_witness(&mut r)?;
    let batch = dec_batch(&mut r)?;
    r.finish()?;
    Ok((prev, witness, batch))
}

/// Encode a single [`Batch`] in the canonical layout (same bytes used inside
/// [`encode_input`]). Exposed so the sequencer's durability journal can persist a
/// sealed batch and replay it verbatim.
#[cfg(feature = "journal")]
pub fn encode_batch(batch: &Batch) -> Vec<u8> {
    let mut o = Vec::new();
    enc_batch(&mut o, batch);
    o
}

/// Decode a [`Batch`] produced by [`encode_batch`].
#[cfg(feature = "journal")]
pub fn decode_batch(bytes: &[u8]) -> Result<Batch, CodecError> {
    let mut r = R::new(bytes);
    let b = dec_batch(&mut r)?;
    r.finish()?;
    Ok(b)
}

/// Decode the public values the guest committed (layout matches
/// [`PublicValues::encode`]).
pub fn decode_public_values(bytes: &[u8]) -> Result<PublicValues, CodecError> {
    let mut r = R::new(bytes);
    let pv = PublicValues {
        pool_id: r.a32()?,
        chain_id: r.u64()?,
        prev_root: r.a32()?,
        prev_seq: r.u64()?,
        new_root: r.a32()?,
        new_seq: r.u64()?,
        deposits_commitment: r.a32()?,
        withdrawals_commitment: r.a32()?,
        prev_total: r.u128()?,
        new_total: r.u128()?,
        fee_delta: r.u128()?,
        current_epoch: r.u64()?,
        fee_withdrawal: r.u128()?,
        da_commitment: r.a32()?,
    };
    r.finish()?;
    Ok(pv)
}
