//! Liquid Cells SP1 guest.
//!
//! Reads the input bundle `(prev, witness, batch)`, runs the exact same
//! `prove_transition` the sequencer runs, and commits the resulting `PublicValues`.
//! The committed bytes are what the on-chain anchor type script will pin to chain
//! facts (anchor cell data, deposit cells, withdrawal outputs).

#![no_main]
sp1_zkvm::entrypoint!(main);

use liquid_cells_stf::{codec, prove_transition};

pub fn main() {
    // Host wrote the bundle via `stdin.write_slice(&bytes)`.
    let input = sp1_zkvm::io::read_vec();
    let (prev, witness, batch) = codec::decode_input(&input).expect("malformed guest input");

    // The whole protocol's safety check, in-circuit.
    let pv = prove_transition(&prev, &witness, &batch).expect("invalid transition");

    sp1_zkvm::io::commit_slice(&pv.encode());
}
