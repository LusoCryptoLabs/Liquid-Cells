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
pub mod error;
pub mod hash;
pub mod sig;
pub mod smt;
pub mod transition;
pub mod types;

pub use error::StfError;
pub use hash::{keccak, Hash};
pub use smt::{root_from_witness, verify_proof, Smt};
pub use transition::{apply, prove_transition, touched_keys, State, Witness};
pub use types::*;
