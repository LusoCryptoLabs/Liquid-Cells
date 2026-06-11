#!/usr/bin/env bash
# Generate + verify a Groth16-wrapped proof of the Liquid Cells transition and
# refresh the on-chain fixtures under fixtures/.
#
# Requires (all present in the ChiralSP1 WSL distro): the SP1 toolchain, Go + cc
# (for the native gnark FFI), and the cached groth16 circuit at
# ~/.sp1/circuits/groth16/<SP1_CIRCUIT_VERSION>/.
#
# Two non-obvious requirements learned the hard way:
#   * `ulimit -s unlimited` — the gnark constraint solver overflows the default
#     8 MB stack and the process dies silently (exit 253, no output) without it.
#   * the host must be built with sp1-sdk feature `native-gnark`, otherwise the
#     default path shells out to Docker (`docker info`), which isn't wired into
#     this distro.
set -e
ulimit -s unlimited
export HOME=/root
export PATH=/root/.sp1/bin:/root/.cargo/bin:/usr/local/go/bin:$PATH
export SP1_PROVER=cpu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
ELF="$REPO/crates/sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/liquid-cells-guest"

[ -f "$ELF" ] || ( cd crates/sp1-guest && cargo prove build )
( cd crates/sp1-host && cargo build --release )

N="${1:-1}"
exec "$REPO/crates/sp1-host/target/release/liquid-cells-host" "$ELF" "$N" groth16
