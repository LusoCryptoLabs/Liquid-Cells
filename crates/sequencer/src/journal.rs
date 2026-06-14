//! Durability for the sequencer: a crash-tolerant, event-sourced write-ahead log.
//!
//! The base [`Sequencer`] is pure in-memory: a restart loses both the committed root
//! and the un-sealed mempool. [`DurableSequencer`] wraps it with a [`Journal`] that
//! records every accepted intent and every sealed checkpoint, so [`DurableSequencer::
//! recover`] can **replay** the log and reconstruct a byte-identical sequencer, same
//! root, seq, total, fee_acc, leaves, last_epoch, and the same pending mempool.
//!
//! It is event-sourced, not a state snapshot: the log stores the *commands* the live
//! sequencer ran (`submit_*` and `seal_batch`), and recovery re-executes them through
//! the identical deterministic STF. That keeps the journal tiny and immune to the
//! "snapshot encodes a stale view" class of bug, the replayed state is computed by the
//! same code that produced it.
//!
//! ### Crash semantics
//!
//! * Intents are journaled **before** they enter the mempool (write-ahead), so the
//!   mempool never holds an intent the log lacks.
//! * A seal is applied first (it can fail with [`StfError`], in which case nothing is
//!   journaled) and the `Seal` marker is written on success. A crash after the apply
//!   but before the marker leaves the recovered state one checkpoint behind the
//!   in-memory one. [`DurableSequencer::recover`] replays this **local** log to restore the
//!   unsealed mempool and the last locally-sealed state; it does *not* itself talk to L1.
//!   Reconciling against the chain — the crash-gap above, or a deposit/checkpoint reorg — is the
//!   operator's job and uses the *consensus* source of truth (the on-chain anchor + L1 DA) via
//!   [`Sequencer::resume`], since this local log is a mempool-durability aid, **not** the ledger
//!   of record. (Deposit-reorg specifically is gated before it can seal by
//!   [`crate::PendingDeposits`].)
//!
//! A torn trailing frame (process killed mid-write) is detected and ignored on read.

use crate::{CheckpointJob, Sequencer};
use liquid_cells_stf::{
    codec, Batch, Deposit, HtlcClaim, HtlcLock, HtlcRefund, StfError, Transfer, Withdrawal,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const TAG_INTENT: u8 = 0x01;
const TAG_SEAL: u8 = 0x02;

/// One submitted intent (mempool command). Mirrors the six `Sequencer::submit_*` calls.
#[derive(Clone, Debug, PartialEq)]
pub enum IntentRecord {
    Deposit(Deposit),
    Transfer(Transfer),
    HtlcLock(HtlcLock),
    HtlcClaim(HtlcClaim),
    HtlcRefund(HtlcRefund),
    Withdrawal(Withdrawal),
}

/// A single journal entry: either an accepted intent or a sealed checkpoint marker.
#[derive(Clone, Debug, PartialEq)]
pub enum JournalRecord {
    Intent(IntentRecord),
    Seal { current_epoch: u64, fee_withdrawal: u128 },
}

impl IntentRecord {
    fn into_batch(self) -> Batch {
        let mut b = Batch::default();
        match self {
            IntentRecord::Deposit(d) => b.deposits.push(d),
            IntentRecord::Transfer(t) => b.transfers.push(t),
            IntentRecord::HtlcLock(l) => b.htlc_locks.push(l),
            IntentRecord::HtlcClaim(c) => b.htlc_claims.push(c),
            IntentRecord::HtlcRefund(r) => b.htlc_refunds.push(r),
            IntentRecord::Withdrawal(w) => b.withdrawals.push(w),
        }
        b
    }

    /// Recover the intent from a decoded single-op batch.
    fn from_batch(mut b: Batch) -> Option<IntentRecord> {
        if let Some(d) = b.deposits.pop() {
            return Some(IntentRecord::Deposit(d));
        }
        if let Some(t) = b.transfers.pop() {
            return Some(IntentRecord::Transfer(t));
        }
        if let Some(l) = b.htlc_locks.pop() {
            return Some(IntentRecord::HtlcLock(l));
        }
        if let Some(c) = b.htlc_claims.pop() {
            return Some(IntentRecord::HtlcClaim(c));
        }
        if let Some(r) = b.htlc_refunds.pop() {
            return Some(IntentRecord::HtlcRefund(r));
        }
        if let Some(w) = b.withdrawals.pop() {
            return Some(IntentRecord::Withdrawal(w));
        }
        None
    }
}

impl JournalRecord {
    /// Canonical frame: `tag(1) ‖ len(4 BE) ‖ batch_bytes`. The batch reuses the exact
    /// `codec` layout the guest input uses, so there is one serialization to trust.
    pub fn encode(&self) -> Vec<u8> {
        let (tag, batch) = match self {
            JournalRecord::Intent(i) => (TAG_INTENT, i.clone().into_batch()),
            JournalRecord::Seal { current_epoch, fee_withdrawal } => (
                TAG_SEAL,
                Batch { current_epoch: *current_epoch, fee_withdrawal: *fee_withdrawal, ..Default::default() },
            ),
        };
        let body = codec::encode_batch(&batch);
        let mut out = Vec::with_capacity(5 + body.len());
        out.push(tag);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn from_frame(tag: u8, body: &[u8]) -> Option<JournalRecord> {
        let batch = codec::decode_batch(body).ok()?;
        match tag {
            TAG_INTENT => IntentRecord::from_batch(batch).map(JournalRecord::Intent),
            TAG_SEAL => Some(JournalRecord::Seal {
                current_epoch: batch.current_epoch,
                fee_withdrawal: batch.fee_withdrawal,
            }),
            _ => None,
        }
    }
}

/// Append-only persistence for journal records. `replay` returns them oldest-first.
pub trait Journal {
    fn append(&mut self, rec: &JournalRecord) -> io::Result<()>;
    fn replay(&self) -> io::Result<Vec<JournalRecord>>;
}

/// File-backed journal: one append-only file of framed records, `fsync`ed per append so a
/// recorded intent or seal survives a power loss. A partially-written trailing frame from a
/// crash is silently dropped on read.
pub struct FileJournal {
    path: PathBuf,
    file: File,
}

impl FileJournal {
    /// Open (creating if absent) the journal at `path` for appending.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).read(true).open(&path)?;
        Ok(Self { path, file })
    }

    /// Read and decode every intact frame from `path`, tolerating a torn trailing frame.
    pub fn read_all(path: impl AsRef<Path>) -> io::Result<Vec<JournalRecord>> {
        let mut bytes = Vec::new();
        match File::open(&path) {
            Ok(mut f) => {
                f.read_to_end(&mut bytes)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        Ok(decode_frames(&bytes))
    }
}

/// Decode as many complete frames as the buffer holds; stop at the first short/torn frame.
fn decode_frames(bytes: &[u8]) -> Vec<JournalRecord> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < bytes.len() {
        if p + 5 > bytes.len() {
            break; // torn header
        }
        let tag = bytes[p];
        let len = u32::from_be_bytes(bytes[p + 1..p + 5].try_into().unwrap()) as usize;
        let body_start = p + 5;
        let body_end = match body_start.checked_add(len) {
            Some(e) => e,
            None => break,
        };
        if body_end > bytes.len() {
            break; // torn body
        }
        match JournalRecord::from_frame(tag, &bytes[body_start..body_end]) {
            Some(rec) => out.push(rec),
            None => break, // corrupt frame, stop rather than misread the rest
        }
        p = body_end;
    }
    out
}

impl Journal for FileJournal {
    fn append(&mut self, rec: &JournalRecord) -> io::Result<()> {
        let frame = rec.encode();
        self.file.write_all(&frame)?;
        self.file.flush()?;
        self.file.sync_all()?; // durability: the frame is on disk before we proceed
        Ok(())
    }
    fn replay(&self) -> io::Result<Vec<JournalRecord>> {
        FileJournal::read_all(&self.path)
    }
}

/// In-memory journal for tests (and for a deliberately non-durable run). `replay` returns the
/// records appended so far.
#[derive(Default, Clone)]
pub struct MemJournal {
    records: Vec<JournalRecord>,
}

impl MemJournal {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Round-trip every record through the on-disk frame encoding, so a `MemJournal` test
    /// exercises the same (de)serialization a `FileJournal` would.
    pub fn records_via_frames(&self) -> Vec<JournalRecord> {
        let mut buf = Vec::new();
        for r in &self.records {
            buf.extend_from_slice(&r.encode());
        }
        decode_frames(&buf)
    }
}

impl Journal for MemJournal {
    fn append(&mut self, rec: &JournalRecord) -> io::Result<()> {
        self.records.push(rec.clone());
        Ok(())
    }
    fn replay(&self) -> io::Result<Vec<JournalRecord>> {
        Ok(self.records_via_frames())
    }
}

/// Error from a durable seal: either the batch was invalid ([`StfError`]) or the journal write
/// failed ([`io::Error`]).
#[derive(Debug)]
pub enum SealError {
    Stf(StfError),
    Io(io::Error),
}
impl From<io::Error> for SealError {
    fn from(e: io::Error) -> Self {
        SealError::Io(e)
    }
}
impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Stf(e) => write!(f, "seal rejected by STF: {e:?}"),
            SealError::Io(e) => write!(f, "journal write failed: {e}"),
        }
    }
}
impl std::error::Error for SealError {}

/// A [`Sequencer`] whose intents and seals are persisted to a [`Journal`] for crash recovery.
pub struct DurableSequencer<J: Journal> {
    inner: Sequencer,
    journal: J,
}

impl<J: Journal> DurableSequencer<J> {
    /// Start a fresh durable sequencer over an empty pool. The journal should be empty.
    pub fn genesis(pool_id: liquid_cells_stf::Hash, chain_id: u64, journal: J) -> Self {
        Self { inner: Sequencer::genesis(pool_id, chain_id), journal }
    }

    /// Replay `journal` into a reconstructed sequencer, then keep it for future appends. The
    /// result is byte-identical to the sequencer whose commands produced the log.
    pub fn recover(pool_id: liquid_cells_stf::Hash, chain_id: u64, journal: J) -> Result<Self, SealError> {
        let records = journal.replay().map_err(SealError::Io)?;
        let mut inner = Sequencer::genesis(pool_id, chain_id);
        for rec in records {
            match rec {
                JournalRecord::Intent(i) => submit_into(&mut inner, i),
                JournalRecord::Seal { current_epoch, fee_withdrawal } => {
                    // Deterministic: a seal that was journaled succeeded once, so it succeeds
                    // again over the identical replayed mempool.
                    inner.seal_batch(current_epoch, fee_withdrawal).map_err(SealError::Stf)?;
                }
            }
        }
        Ok(Self { inner, journal })
    }

    /// Read-only access to the underlying sequencer (root, seq, total, anchor, state, ...).
    pub fn inner(&self) -> &Sequencer {
        &self.inner
    }

    /// Read-only access to the journal (e.g. to clone it for a recovery test).
    pub fn journal(&self) -> &J {
        &self.journal
    }

    // --- journaled mempool submissions (write-ahead: log, then enqueue) ---

    pub fn submit_deposit(&mut self, d: Deposit) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::Deposit(d)))?;
        self.inner.submit_deposit(d);
        Ok(())
    }
    pub fn submit_transfer(&mut self, t: Transfer) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::Transfer(t.clone())))?;
        self.inner.submit_transfer(t);
        Ok(())
    }
    pub fn submit_htlc_lock(&mut self, l: HtlcLock) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::HtlcLock(l.clone())))?;
        self.inner.submit_htlc_lock(l);
        Ok(())
    }
    pub fn submit_htlc_claim(&mut self, c: HtlcClaim) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::HtlcClaim(c.clone())))?;
        self.inner.submit_htlc_claim(c);
        Ok(())
    }
    pub fn submit_htlc_refund(&mut self, r: HtlcRefund) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::HtlcRefund(r)))?;
        self.inner.submit_htlc_refund(r);
        Ok(())
    }
    pub fn submit_withdrawal(&mut self, w: Withdrawal) -> io::Result<()> {
        self.journal.append(&JournalRecord::Intent(IntentRecord::Withdrawal(w.clone())))?;
        self.inner.submit_withdrawal(w);
        Ok(())
    }

    /// Seal a checkpoint, then journal the seal marker. Applies first so an invalid batch is
    /// rejected without writing anything (the inner sequencer leaves its state and mempool
    /// intact on `StfError`, so a retry is safe).
    pub fn seal_batch(
        &mut self,
        current_epoch: u64,
        fee_withdrawal: u128,
    ) -> Result<CheckpointJob, SealError> {
        let job = self.inner.seal_batch(current_epoch, fee_withdrawal).map_err(SealError::Stf)?;
        self.journal.append(&JournalRecord::Seal { current_epoch, fee_withdrawal })?;
        Ok(job)
    }
}

impl DurableSequencer<FileJournal> {
    /// Open a file-backed durable sequencer at `path`, replaying any existing journal. This is
    /// the production entry point: call it on startup and you transparently resume.
    pub fn open(
        pool_id: liquid_cells_stf::Hash,
        chain_id: u64,
        path: impl AsRef<Path>,
    ) -> Result<Self, SealError> {
        let journal = FileJournal::open(&path).map_err(SealError::Io)?;
        Self::recover(pool_id, chain_id, journal)
    }
}

fn submit_into(seq: &mut Sequencer, intent: IntentRecord) {
    match intent {
        IntentRecord::Deposit(d) => seq.submit_deposit(d),
        IntentRecord::Transfer(t) => seq.submit_transfer(t),
        IntentRecord::HtlcLock(l) => seq.submit_htlc_lock(l),
        IntentRecord::HtlcClaim(c) => seq.submit_htlc_claim(c),
        IntentRecord::HtlcRefund(r) => seq.submit_htlc_refund(r),
        IntentRecord::Withdrawal(w) => seq.submit_withdrawal(w),
    }
}
