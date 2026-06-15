//! # liquid-cells-stf
//!
//! Deterministic state-transition function for **Liquid Cells**, a trustless
//! pooled-balance rollup on Nervos CKB.
//!
//! This crate is the protocol's keystone: the same code is
//!
//!   * executed natively by the off-chain sequencer to advance the pool root, and
//!   * proven verbatim by the SP1 zkVM guest, whose Groth16 proof the on-chain
//!     anchor type script verifies.
//!
//! Because both sides run identical bytes, they can never disagree on a root, and
//! the proof attests the two safety invariants enforced in [`transition::apply`]:
//! *no debit without a signature* and *value conservation*.
//!
//! See `docs/ARCHITECTURE.md` and `docs/THREAT-MODEL.md` in the repository root.

pub mod codec;
pub mod da;
pub mod error;
pub mod hash;
pub mod sig;
pub mod smt;
/// The compact (pass-through) SMT staged for the post-audit vkey re-bake. Present only
/// under `compact_smt`; OFF in the deployed guest so its vkey (`0x00213af5…`) is
/// unchanged. See [`smt_compact`] and `tests/compact_smt.rs`.
#[cfg(feature = "compact_smt")]
pub mod smt_compact;
pub mod transition;
pub mod types;

pub use da::{encode_da_blob, parse_da_blob, reconstruct};
pub use error::StfError;
pub use hash::{keccak, Hash};
#[cfg(not(feature = "compact_smt"))]
pub use smt::{root_from_witness, verify_proof, Smt};
#[cfg(feature = "compact_smt")]
pub use smt_compact::{root_from_witness, verify_proof, Smt};
pub use transition::{apply, prove_transition, touched_keys, State, Witness};
#[cfg(feature = "min_fee")]
pub use transition::MIN_FEE_PER_LEAF;
pub use types::*;
