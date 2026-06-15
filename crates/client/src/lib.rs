//! # liquid-cells-client
//!
//! The client side of Liquid Cells: hold an account, build and sign intents, and recover your
//! own balance + a unilateral-exit proof from Layer-1 data, all on the **exact**
//! [`liquid_cells_stf`] the sequencer and SP1 guest run.
//!
//! That reuse is the whole point. A client must sign over the same canonical byte layouts and
//! rebuild the same keccak SMT the contract checks; reimplementing any of it (in this or any
//! other language) would reintroduce the "divergent root" class of bugs the protocol is built
//! to avoid. So this crate is deliberately thin, it wires the STF's primitives into an
//! account-shaped API and adds nothing cryptographic of its own.
//!
//! What it does:
//!   * **Identity**, a secp256k1 secret → compressed pubkey → SMT key (`keccak(pubkey)`), plus
//!     the CKB `secp256k1_blake160` lock args a force-exit must pay to.
//!   * **Signed intents**, [`Account::transfer`], [`Account::withdraw`], [`Account::htlc_lock`]
//!     (sign over the STF's `*_msg` digests), and the unsigned [`htlc_claim`]/[`htlc_refund`].
//!   * **Local nonce tracking**, each spend advances the account nonce; [`Account::sync_from_da`]
//!     resyncs it to the authoritative L1 value.
//!   * **Trustless recovery**, [`proof_from_da`] rebuilds your `{balance, nonce}` and an SMT
//!     inclusion proof from the published DA blobs, with no help from the sequencer, and
//!     [`Account::force_exit_witness`] / [`Account::force_refund_witness`] assemble the exact
//!     witness bytes the on-chain anchor type script's escape-hatch modes consume.
//!
//! ```
//! use liquid_cells_client::Account;
//! use liquid_cells_stf::keccak;
//! let pool_id = keccak(b"sp1-pool");
//! let mut alice = Account::new(pool_id, 0x434b42, [7u8; 32]);
//! let bob = Account::new(pool_id, 0x434b42, [9u8; 32]);
//! // Pay Bob 1000 (fee 10), valid through epoch 100. Signed under Alice's current nonce.
//! let t = alice.transfer(bob.key(), 1000, 10, 100);
//! assert_eq!(alice.nonce(), 1); // advanced locally
//! # let _ = t;
//! ```

use liquid_cells_stf::da::parse_da_blob;
use liquid_cells_stf::{
    htlc_id, htlc_lock_msg, key_of_pubkey, reconstruct, sig, transfer_msg, withdraw_msg, Hash,
    HtlcClaim, HtlcLock, HtlcRef, HtlcRefund, Leaf, Smt, Transfer, Withdrawal,
};

pub mod fees;
pub use fees::FeeSchedule;

pub mod swap;

/// Canonical JSON wire format for intents (shared by the WASM SDK and the sequencer service).
/// Behind `--features wire`.
#[cfg(feature = "wire")]
pub mod wire;

/// fnn-backed counterparty leg (the live Fiber adapter for [`swap`]). Behind `--features fiber`.
#[cfg(feature = "fiber")]
pub mod fiber;

/// SMT depth (matches `liquid_cells_stf::smt` and the on-chain contract).
const SMT_DEPTH: usize = 256;

/// Force-exit witness `input_type` length: `pubkey(33) ‖ balance(16) ‖ nonce(8) ‖ siblings`.
/// Matches the contract's `FORCEEXIT_LEN`.
pub const FORCE_EXIT_WITNESS_LEN: usize = 33 + 16 + 8 + 32 * SMT_DEPTH; // 8249
/// Force-refund witness `input_type` length: `sender_pubkey(33) ‖ receiver_key(32) ‖ amount(16)
/// ‖ hashlock(32) ‖ timeout(8) ‖ lock_nonce(8) ‖ siblings`. Matches the contract's
/// `FORCEREFUND_LEN`. Under `htlc_keyspace` (audit H-1) the witness also carries the actual committed
/// escrow balance (16 bytes after lock_nonce) so the contract can sweep a balance-altered escrow.
#[cfg(not(feature = "htlc_keyspace"))]
pub const FORCE_REFUND_WITNESS_LEN: usize = 33 + 32 + 16 + 32 + 8 + 8 + 32 * SMT_DEPTH; // 8321
#[cfg(feature = "htlc_keyspace")]
pub const FORCE_REFUND_WITNESS_LEN: usize = 33 + 32 + 16 + 32 + 8 + 8 + 16 + 32 * SMT_DEPTH; // 8337

/// `blake160(data)` = first 20 bytes of CKB's default blake2b-256, the args of a
/// `secp256k1_blake160` lock. A force-exit/refund payout is forced to the lock with
/// `args = blake160(pubkey)`, so it can only ever reach the owner's own address.
pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut h = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-default-hash").build();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..20]);
    r
}

/// A leaf recovered from L1 data, with its inclusion path, everything a unilateral exit needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafProof {
    pub leaf: Leaf,
    /// 256 sibling hashes, top-down (the order `Smt::proof` returns and the contract walks).
    pub siblings: Vec<Hash>,
}

/// The latest `{balance, nonce}` recorded for `key` across an ordered (oldest-first) sequence of
/// DA blobs, the post-state the most recent checkpoint published. `Leaf::default()` (`{0,0}`) if
/// the key never appears. `None` only if a blob is malformed.
pub fn latest_leaf(blobs: &[Vec<u8>], key: &Hash) -> Option<Leaf> {
    let mut leaf = Leaf::default();
    for blob in blobs {
        for rec in parse_da_blob(blob)? {
            if &rec.key == key {
                leaf = rec.leaf;
            }
        }
    }
    Some(leaf)
}

/// Rebuild the tree from the published DA blobs (oldest-first) and return `key`'s current leaf
/// plus its inclusion proof, the trust-minimised recovery path: no sequencer cooperation, just
/// L1 data. The returned proof verifies against the latest on-chain anchor root
/// (`liquid_cells_stf::verify_proof`), and is exactly what a force-exit consumes. `None` if any
/// blob is malformed.
pub fn proof_from_da(blobs: &[Vec<u8>], key: &Hash) -> Option<(Leaf, Vec<Hash>)> {
    let leaf = latest_leaf(blobs, key)?;
    let smt = reconstruct(blobs)?;
    Some((leaf, smt.proof(key)))
}

/// Rebuild the whole tree from DA blobs (re-exported convenience; same as
/// [`liquid_cells_stf::reconstruct`]).
pub fn reconstruct_tree(blobs: &[Vec<u8>]) -> Option<Smt> {
    reconstruct(blobs)
}

/// Restore the tree from a full-state **snapshot** blob plus the DA blobs of the checkpoints *after*
/// it (`tail`, oldest-first), the O(snapshot+tail) recovery path. `snapshot_root` is the on-chain
/// anchor root at the snapshot's seq (your trusted reference); the snapshot is rejected (`None`) if
/// it does not reconstruct to exactly that root, so a malicious snapshot that omits or forges a leaf
/// cannot be used. Folding the tail then advances to the current state. Equivalent to a full-history
/// `reconstruct`, but bounded by the tail length, not all checkpoints since genesis.
pub fn reconstruct_from_snapshot(snapshot: &[u8], snapshot_root: &Hash, tail: &[Vec<u8>]) -> Option<Smt> {
    if reconstruct(&[snapshot.to_vec()])?.root() != *snapshot_root {
        return None;
    }
    let mut blobs = Vec::with_capacity(1 + tail.len());
    blobs.push(snapshot.to_vec());
    blobs.extend_from_slice(tail);
    reconstruct(&blobs)
}

/// Build a claim for a pending HTLC by revealing its preimage. Unsigned, knowledge of the
/// preimage is the authority, and the receiver is fixed by the escrow's `htlc_id`. Anyone can
/// build it, so it is a free function, not an [`Account`] method.
pub fn htlc_claim(htlc: HtlcRef, preimage: Vec<u8>) -> HtlcClaim {
    HtlcClaim { htlc, preimage }
}

/// Build a refund for a timed-out HTLC. Unsigned, the timeout is the authority and the sender
/// is fixed by `htlc_id`.
pub fn htlc_refund(htlc: HtlcRef) -> HtlcRefund {
    HtlcRefund { htlc }
}

/// A Liquid Cells account: a secp256k1 identity scoped to one pool, with a local view of its
/// own account nonce. Building a spending intent advances that nonce; [`Account::sync_from_da`]
/// resets it to the authoritative L1 value.
#[derive(Clone)]
pub struct Account {
    secret: [u8; 32],
    pubkey: [u8; 33],
    key: Hash,
    pool_id: Hash,
    chain_id: u64,
    nonce: u64,
}

impl Account {
    /// Derive an account from a secret key, scoped to `(pool_id, chain_id)`. Nonce starts at 0;
    /// call [`Account::sync_from_da`] (or [`Account::set_nonce`]) to align with L1 before signing.
    pub fn new(pool_id: Hash, chain_id: u64, secret: [u8; 32]) -> Self {
        let pubkey = sig::pubkey(&secret);
        let key = key_of_pubkey(&pubkey);
        Self { secret, pubkey, key, pool_id, chain_id, nonce: 0 }
    }

    /// The account's SMT key (`keccak(pubkey)`), its identity in the pool, and where others
    /// address payments.
    pub fn key(&self) -> Hash {
        self.key
    }
    pub fn pubkey(&self) -> [u8; 33] {
        self.pubkey
    }
    pub fn pool_id(&self) -> Hash {
        self.pool_id
    }
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Overwrite the local nonce (e.g. from a sequencer ack).
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }
    /// The CKB `secp256k1_blake160` lock args (`blake160(pubkey)`), the only lock a force-exit
    /// or force-refund of this account may pay out to.
    pub fn ckb_lock_args(&self) -> [u8; 20] {
        blake160(&self.pubkey)
    }

    /// Build and sign a transfer of `amount` (+ `fee`) to `to_key`, valid through `expiry`
    /// (epochs). Uses the current nonce, then advances it.
    pub fn transfer(&mut self, to_key: Hash, amount: u128, fee: u128, expiry: u64) -> Transfer {
        let nonce = self.nonce;
        let msg = transfer_msg(
            self.chain_id, &self.pool_id, &self.key, &to_key, amount, fee, nonce, expiry,
        );
        let (_pk, sig) = sig::sign(&self.secret, &msg);
        self.nonce += 1;
        Transfer { from_pubkey: self.pubkey, to_key, amount, fee, nonce, expiry, sig }
    }

    /// Build and sign a transfer whose fee follows a [`FeeSchedule`] (`max(floor, bps%)`) instead
    /// of a flat fee, so clients can price by amount: tiny payments pay the floor, large ones a
    /// basis-point share. Equivalent to [`transfer`](Self::transfer) with `fee =
    /// schedule.fee_for(amount)`.
    pub fn transfer_scheduled(
        &mut self,
        to_key: Hash,
        amount: u128,
        schedule: &FeeSchedule,
        expiry: u64,
    ) -> Transfer {
        self.transfer(to_key, amount, schedule.fee_for(amount), expiry)
    }

    /// Like [`htlc_lock`](Self::htlc_lock) but with the fee priced by a [`FeeSchedule`].
    pub fn htlc_lock_scheduled(
        &mut self,
        receiver_key: Hash,
        amount: u128,
        schedule: &FeeSchedule,
        hashlock: Hash,
        timeout: u64,
    ) -> (HtlcLock, HtlcRef) {
        self.htlc_lock(receiver_key, amount, schedule.fee_for(amount), hashlock, timeout)
    }

    /// **Fee sponsorship**: a transfer of exactly `fee` to `beneficiary_key`, with this (sponsor)
    /// account paying no protocol fee of its own. Submit it **ordered before** the beneficiary's
    /// payment in the same checkpoint, so the beneficiary can afford a fee larger than their
    /// (sub-cent) payment: the platform absorbs the per-leaf floor and the user's marginal cost is
    /// just the tip, the thing that makes micro-tips viable. Pure composition over [`transfer`], no
    /// protocol notion of a sponsor. (A platform that wants to charge its own fee can use
    /// [`transfer`](Self::transfer) with a non-zero fee instead.)
    pub fn sponsor_fee(&mut self, beneficiary_key: Hash, fee: u128, expiry: u64) -> Transfer {
        self.transfer(beneficiary_key, fee, 0, expiry)
    }

    /// Build N signed transfers from this account in one call, a batch payment / fan-out
    /// (payroll, treasury disbursement, multi-recipient split). The transfers carry **consecutive
    /// nonces** and are meant to be sealed in **one checkpoint**; submit them all.
    ///
    /// This is the SDK answer to "atomic multi-output transfer" without a protocol change: because
    /// every leg shares this payer and chains nonces, in a single checkpoint they settle
    /// **together**, either the payer can fund all of them (all land) or an underfunded leg and
    /// every later leg **defer together** under [`Sequencer::seal_resilient`]. That is de-facto
    /// per-payer atomicity over the existing `Transfer` primitive (no vkey-baked STF change). `fee`
    /// is charged per output (pass 0 for none); total debit is `Σ amount + N·fee`.
    pub fn batch_transfer(
        &mut self,
        outputs: &[(Hash, u128)],
        fee: u128,
        expiry: u64,
    ) -> Vec<Transfer> {
        outputs.iter().map(|(to, amount)| self.transfer(*to, *amount, fee, expiry)).collect()
    }

    /// Split one gross payment into two signed transfers, `cut_bps`/10000 of it to
    /// `cut_recipient_key`, the remainder to `recipient_key`, a generic "pay X, route a basis-point
    /// cut to Y" recipe. Conservation is exact: the cut is `floor(gross·bps/10000)` and the main
    /// recipient gets `gross − cut`, so `recipient + cut == gross`. The two transfers carry
    /// consecutive nonces and are meant to be sealed in the same checkpoint; submit both.
    ///
    /// This is pure client-side composition (two ordinary [`transfer`]s), the protocol has no
    /// notion of "platform", "author", or a cut. It serves any fee-split use case: creator tipping
    /// (author + platform), marketplace (seller + marketplace), affiliate/referral, treasury rake,
    /// etc. (For a protocol fee that accrues to the pool's `fee_acc` instead of a recipient, pass a
    /// non-zero per-transfer `fee` via [`transfer`].)
    pub fn split_payment(
        &mut self,
        recipient_key: Hash,
        cut_recipient_key: Hash,
        gross: u128,
        cut_bps: u16,
        expiry: u64,
    ) -> [Transfer; 2] {
        let cut = gross / 10_000 * cut_bps as u128 + (gross % 10_000) * cut_bps as u128 / 10_000;
        let recipient_amount = gross - cut;
        let to_recipient = self.transfer(recipient_key, recipient_amount, 0, expiry);
        let to_cut = self.transfer(cut_recipient_key, cut, 0, expiry);
        [to_recipient, to_cut]
    }

    /// Deprecated tipping-flavored alias for [`split_payment`]. `author_key`→`recipient_key`,
    /// `platform_key`→`cut_recipient_key`, `platform_bps`→`cut_bps`. Kept for the tipping
    /// integration; new code should use the generic [`split_payment`].
    #[deprecated(note = "use `split_payment`, the mechanism is a generic fee-split, not tipping-specific")]
    pub fn split_tip(
        &mut self,
        author_key: Hash,
        platform_key: Hash,
        gross: u128,
        platform_bps: u16,
        expiry: u64,
    ) -> [Transfer; 2] {
        self.split_payment(author_key, platform_key, gross, platform_bps, expiry)
    }

    /// Build and sign a withdrawal of `amount` to the on-chain `target_lock_hash`, valid through
    /// `expiry`. Uses the current nonce, then advances it.
    pub fn withdraw(&mut self, target_lock_hash: Hash, amount: u128, expiry: u64) -> Withdrawal {
        let nonce = self.nonce;
        let msg = withdraw_msg(
            self.chain_id, &self.pool_id, &self.key, &target_lock_hash, amount, nonce, expiry,
        );
        let (_pk, sig) = sig::sign(&self.secret, &msg);
        self.nonce += 1;
        Withdrawal { from_pubkey: self.pubkey, target_lock_hash, amount, nonce, expiry, sig }
    }

    /// Build and sign an HTLC lock escrowing `amount` (+ `fee`) to `receiver_key` under
    /// `hashlock` until `timeout` (epochs). Returns the lock to submit and the [`HtlcRef`] terms
    /// (so the sender can later refund, or coordinate the counterparty claim). Uses the current
    /// nonce, then advances it.
    pub fn htlc_lock(
        &mut self,
        receiver_key: Hash,
        amount: u128,
        fee: u128,
        hashlock: Hash,
        timeout: u64,
    ) -> (HtlcLock, HtlcRef) {
        let nonce = self.nonce;
        let msg = htlc_lock_msg(
            self.chain_id, &self.pool_id, &self.key, &receiver_key, amount, fee, &hashlock,
            timeout, nonce,
        );
        let (_pk, sig) = sig::sign(&self.secret, &msg);
        self.nonce += 1;
        let lock = HtlcLock {
            sender_pubkey: self.pubkey,
            receiver_key,
            amount,
            fee,
            hashlock,
            timeout,
            nonce,
            sig,
        };
        let r = HtlcRef {
            sender_key: self.key,
            receiver_key,
            amount,
            hashlock,
            timeout,
            lock_nonce: nonce,
        };
        (lock, r)
    }

    /// Recover this account's `{balance, nonce}` and inclusion proof from L1 DA, and resync the
    /// local nonce to the recovered value. `None` if a blob is malformed.
    pub fn sync_from_da(&mut self, blobs: &[Vec<u8>]) -> Option<LeafProof> {
        let (leaf, siblings) = proof_from_da(blobs, &self.key)?;
        self.nonce = leaf.nonce;
        Some(LeafProof { leaf, siblings })
    }

    /// Assemble the **force-exit** witness for this account against L1 DA:
    /// `pubkey ‖ balance ‖ nonce ‖ siblings`. This is the exact `input_type` the anchor type
    /// script's force-exit mode consumes to pay the account's balance to its own secp lock after
    /// operator silence. `None` if blobs are malformed or the balance is zero (nothing to exit).
    pub fn force_exit_witness(&self, blobs: &[Vec<u8>]) -> Option<Vec<u8>> {
        let (leaf, siblings) = proof_from_da(blobs, &self.key)?;
        if leaf.balance == 0 {
            return None;
        }
        let mut w = Vec::with_capacity(FORCE_EXIT_WITNESS_LEN);
        w.extend_from_slice(&self.pubkey);
        w.extend_from_slice(&leaf.balance.to_be_bytes());
        w.extend_from_slice(&leaf.nonce.to_be_bytes());
        for s in &siblings {
            w.extend_from_slice(s);
        }
        debug_assert_eq!(w.len(), FORCE_EXIT_WITNESS_LEN);
        Some(w)
    }

    /// Assemble the **force-refund** witness for a timed-out HTLC *this account sent* (terms in
    /// `r`): `sender_pubkey ‖ receiver_key ‖ amount ‖ hashlock ‖ timeout ‖ lock_nonce ‖ siblings`.
    /// The exact `input_type` the anchor type script's force-refund mode consumes. `None` if
    /// `r` is not this account's escrow, the escrow is absent from the published state, or blobs
    /// are malformed.
    pub fn force_refund_witness(&self, blobs: &[Vec<u8>], r: &HtlcRef) -> Option<Vec<u8>> {
        if r.sender_key != self.key {
            return None;
        }
        let id =
            htlc_id(&self.pool_id, &r.sender_key, &r.receiver_key, r.amount, &r.hashlock, r.timeout, r.lock_nonce);
        let (leaf, siblings) = proof_from_da(blobs, &id)?;
        // Deployed: the escrow holds exactly `amount`. Under `htlc_keyspace` it may hold a hostile
        // surplus (a top-up); the witness then carries the actual committed balance so the contract
        // reconstructs and sweeps the real leaf. Either way the escrow must hold at least `amount`.
        #[cfg(not(feature = "htlc_keyspace"))]
        if leaf.balance != r.amount {
            return None; // escrow not present (or already claimed/refunded)
        }
        #[cfg(feature = "htlc_keyspace")]
        if leaf.balance < r.amount {
            return None; // escrow not present (or already claimed/refunded)
        }
        let mut w = Vec::with_capacity(FORCE_REFUND_WITNESS_LEN);
        w.extend_from_slice(&self.pubkey);
        w.extend_from_slice(&r.receiver_key);
        w.extend_from_slice(&r.amount.to_be_bytes());
        w.extend_from_slice(&r.hashlock);
        w.extend_from_slice(&r.timeout.to_be_bytes());
        w.extend_from_slice(&r.lock_nonce.to_be_bytes());
        #[cfg(feature = "htlc_keyspace")]
        w.extend_from_slice(&leaf.balance.to_be_bytes()); // actual committed balance (swept by the contract)
        for s in &siblings {
            w.extend_from_slice(s);
        }
        debug_assert_eq!(w.len(), FORCE_REFUND_WITNESS_LEN);
        Some(w)
    }
}
