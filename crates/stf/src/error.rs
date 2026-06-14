//! State-transition errors. Any error means the whole batch is invalid and the
//! root does not advance, there are no partial applications.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StfError {
    /// Payer/withdrawer nonce did not match the leaf's current nonce (replay or gap).
    BadNonce,
    /// Intent expired at or before the batch's current epoch.
    Expired,
    /// Leaf balance is too small for amount (+ fee).
    InsufficientBalance,
    /// The batch's `fee_withdrawal` exceeds the pool's accumulated fees
    /// (`prev.fee_acc + fee_delta`), the sequencer may only draw L1 fees from fee
    /// revenue, never from user balances.
    InsufficientFees,
    /// Signature did not verify for the claimed pubkey/message.
    BadSignature,
    /// `from == to` is not a meaningful transfer.
    SelfTransfer,
    /// Arithmetic overflow in balances/totals/fees.
    Overflow,
    /// The value-conservation invariant did not hold after applying the batch.
    ConservationViolation,
    /// The witness did not provide exactly the leaves the batch touches, or its
    /// frontier siblings were the wrong length.
    MalformedWitness,
    /// The witness leaves + siblings did not reconstruct the claimed `prev_root`.
    PrevRootMismatch,
    /// The batch touches more leaves than [`crate::transition::MAX_LEAVES_PER_BATCH`].
    BatchTooLarge,
    /// An HTLC lock targeted an `htlc_id` that is already occupied (would clobber escrow).
    HtlcExists,
    /// A claim/refund referenced an HTLC that isn't escrowed with the claimed amount.
    HtlcMissing,
    /// The revealed preimage did not hash to the HTLC's hashlock.
    BadPreimage,
    /// A claim arrived at/after the HTLC timeout (only refund is valid then).
    HtlcExpired,
    /// A refund arrived at/before the HTLC timeout (only claim is valid then).
    HtlcNotExpired,
    /// (`min_fee` feature only) A signed fee-paying intent (transfer / HTLC-lock) paid below
    /// the protocol per-intent fee floor [`crate::MIN_FEE_PER_LEAF`]. Gated with the feature so
    /// the deployed guest's enum (and vkey) is unchanged while the floor is staged for upgrade.
    #[cfg(feature = "min_fee")]
    FeeBelowMinimum,
}
