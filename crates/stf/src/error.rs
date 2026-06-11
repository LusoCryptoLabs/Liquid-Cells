//! State-transition errors. Any error means the whole batch is invalid and the
//! root does not advance — there are no partial applications.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StfError {
    /// Payer/withdrawer nonce did not match the leaf's current nonce (replay or gap).
    BadNonce,
    /// Intent expired at or before the batch's current epoch.
    Expired,
    /// Leaf balance is too small for amount (+ fee).
    InsufficientBalance,
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
}
