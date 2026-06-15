#!/bin/bash
# Build the Liquid Cells browser/JS SDK: compile the wasm32 cdylib, then run wasm-bindgen to emit
# the JS glue + TypeScript types. Produces two packages from the one .wasm:
#   pkg-node/  (--target nodejs, CommonJS)  -> the node smoke test + server-side use
#   pkg-web/   (--target web, ES module)    -> browsers / bundlers (import init + the API)
# Requires: rustup target add wasm32-unknown-unknown ; cargo install wasm-bindgen-cli --version 0.2.125
set -euo pipefail
cd "$(dirname "$0")"

WASM=target/wasm32-unknown-unknown/release/liquid_cells_wasm.wasm
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --target nodejs --out-dir pkg-node "$WASM"
wasm-bindgen --target web    --out-dir pkg-web  "$WASM"
echo "ok: pkg-node/ (CommonJS, node) and pkg-web/ (ES module, browser)"
