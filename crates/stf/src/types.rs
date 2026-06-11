//! Canonical types and the byte layouts that get hashed or signed.
//!
//! Everything that is hashed uses an explicit, fixed-width big-endian layout — no
//! serde, no molecule — so independent implementations (sequencer, guest, on-chain
//! verifier, client SDK) recompute byte-identical roots and message digests. This
//! is the defence against the "divergent root" class of disputes.

use crate::hash::{keccak, Hash};

/// Domain-separation tags. Distinct per message/commitment kind, all bound to a
/// protocol version. Prevents a signature or commitment for one purpose being
/// replayed as another.
pub fn domain_transfer() -> Hash {
    keccak(b"LIQUIDCELLS/v1/transfer")
}
pub fn domain_withdraw() -> Hash {
    keccak(b"LIQUIDCELLS/v1/withdraw")
}
pub fn domain_deposits() -> Hash {
    keccak(b"LIQUIDCELLS/v1/deposits-commitment")
}
pub fn domain_withdrawals() -> Hash {
    keccak(b"LIQUIDCELLS/v1/withdrawals-commitment")
}

/// SMT key of an account = keccak(compressed secp256k1 pubkey).
pub fn key_of_pubkey(pubkey: &[u8; 33]) -> Hash {
    keccak(pubkey)
}

/// A pool account. The owner identity is the SMT key (= keccak(pubkey)); ownership
/// is proven only when spending, so receiving needs no pre-registration and the
/// leaf stores no pubkey. A zero-balance leaf with nonce > 0 is retained (its nonce
/// is live replay-protection); only `{0, 0}` is treated as absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Leaf {
    pub balance: u128,
    pub nonce: u64,
}

impl Leaf {
    pub fn is_empty(&self) -> bool {
        self.balance == 0 && self.nonce == 0
    }

    /// Canonical 24-byte layout: balance(16) || nonce(8).
    pub fn encode(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[..16].copy_from_slice(&self.balance.to_be_bytes());
        b[16..].copy_from_slice(&self.nonce.to_be_bytes());
        b
    }

    /// Leaf-content hash stored in the SMT. Empty leaves hash to `EMPTY_LEAF`.
    pub fn hash(&self) -> Hash {
        if self.is_empty() {
            crate::smt::EMPTY_LEAF
        } else {
            keccak(&self.encode())
        }
    }
}

/// A signed payer intent moving `amount` (+ `fee`) to `to_key`. The recipient does
/// not sign. The signature is the *only* authority to debit the payer.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub from_pubkey: [u8; 33],
    pub to_key: Hash,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub expiry: u64,
    pub sig: [u8; 64],
}

/// A signed exit debiting the owner and binding an on-chain `target_lock_hash`
/// (the L1 cell lock, or an atomic-swap leg) that the checkpoint tx must honor.
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub from_pubkey: [u8; 33],
    pub target_lock_hash: Hash,
    pub amount: u128,
    pub nonce: u64,
    pub expiry: u64,
    pub sig: [u8; 64],
}

/// A credit authorized by an on-chain deposit cell (bound via the deposits
/// commitment). Needs no signature — its authority is the consumed L1 cell.
#[derive(Clone, Copy, Debug)]
pub struct Deposit {
    pub to_key: Hash,
    pub amount: u128,
}

/// One batch = one root transition = one checkpoint.
#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub current_epoch: u64,
    pub deposits: Vec<Deposit>,
    pub transfers: Vec<Transfer>,
    pub withdrawals: Vec<Withdrawal>,
}

/// On-chain anchor cell contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolState {
    pub pool_id: Hash,
    pub chain_id: u64,
    pub seq: u64,
    pub root: Hash,
    pub total: u128,
    pub fee_acc: u128,
}

impl PoolState {
    pub fn genesis(pool_id: Hash, chain_id: u64, empty_root: Hash) -> Self {
        Self { pool_id, chain_id, seq: 0, root: empty_root, total: 0, fee_acc: 0 }
    }
}

/// Values the SP1 guest commits and the on-chain type script pins to chain facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicValues {
    pub pool_id: Hash,
    pub chain_id: u64,
    pub prev_root: Hash,
    pub prev_seq: u64,
    pub new_root: Hash,
    pub new_seq: u64,
    /// keccak fold over the ordered deposits credited this batch; the type script
    /// recomputes it from the deposit cells consumed by the checkpoint tx.
    pub deposits_commitment: Hash,
    /// keccak fold over the ordered withdrawals; the type script recomputes it from
    /// the output cells (lock hash + amount) the checkpoint tx creates.
    pub withdrawals_commitment: Hash,
    pub prev_total: u128,
    pub new_total: u128,
    pub fee_delta: u128,
    pub current_epoch: u64,
}

impl PublicValues {
    /// Canonical byte encoding (what the guest commits as public input).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + 8 + 32 + 8 + 32 + 8 + 32 + 32 + 16 + 16 + 16 + 8);
        b.extend_from_slice(&self.pool_id);
        b.extend_from_slice(&self.chain_id.to_be_bytes());
        b.extend_from_slice(&self.prev_root);
        b.extend_from_slice(&self.prev_seq.to_be_bytes());
        b.extend_from_slice(&self.new_root);
        b.extend_from_slice(&self.new_seq.to_be_bytes());
        b.extend_from_slice(&self.deposits_commitment);
        b.extend_from_slice(&self.withdrawals_commitment);
        b.extend_from_slice(&self.prev_total.to_be_bytes());
        b.extend_from_slice(&self.new_total.to_be_bytes());
        b.extend_from_slice(&self.fee_delta.to_be_bytes());
        b.extend_from_slice(&self.current_epoch.to_be_bytes());
        b
    }
}

/// The keccak digest a payer signs to authorize a transfer.
#[allow(clippy::too_many_arguments)]
pub fn transfer_msg(
    chain_id: u64,
    pool_id: &Hash,
    from_key: &Hash,
    to_key: &Hash,
    amount: u128,
    fee: u128,
    nonce: u64,
    expiry: u64,
) -> Hash {
    let mut b = Vec::with_capacity(32 + 8 + 32 + 32 + 32 + 16 + 16 + 8 + 8);
    b.extend_from_slice(&domain_transfer());
    b.extend_from_slice(&chain_id.to_be_bytes());
    b.extend_from_slice(pool_id);
    b.extend_from_slice(from_key);
    b.extend_from_slice(to_key);
    b.extend_from_slice(&amount.to_be_bytes());
    b.extend_from_slice(&fee.to_be_bytes());
    b.extend_from_slice(&nonce.to_be_bytes());
    b.extend_from_slice(&expiry.to_be_bytes());
    keccak(&b)
}

/// The keccak digest an owner signs to authorize a withdrawal.
pub fn withdraw_msg(
    chain_id: u64,
    pool_id: &Hash,
    from_key: &Hash,
    target_lock_hash: &Hash,
    amount: u128,
    nonce: u64,
    expiry: u64,
) -> Hash {
    let mut b = Vec::with_capacity(32 + 8 + 32 + 32 + 32 + 16 + 8 + 8);
    b.extend_from_slice(&domain_withdraw());
    b.extend_from_slice(&chain_id.to_be_bytes());
    b.extend_from_slice(pool_id);
    b.extend_from_slice(from_key);
    b.extend_from_slice(target_lock_hash);
    b.extend_from_slice(&amount.to_be_bytes());
    b.extend_from_slice(&nonce.to_be_bytes());
    b.extend_from_slice(&expiry.to_be_bytes());
    keccak(&b)
}
