# liquid-cells-wasm

The Liquid Cells client SDK for the browser and JavaScript, the **same** `liquid-cells-stf`
compiled to WebAssembly, not a reimplementation.

That distinction is the whole point. A JS client must sign over the exact canonical byte layouts and
rebuild the exact keccak SMT that the sequencer seals and the on-chain anchor type script verifies. A
hand-written JS port would reintroduce the "divergent root" class of bug the protocol is built to
avoid; compiling the Rust cannot. The smoke test demonstrates this: the empty-tree root computed in
WASM is `0xa7ff9e28...`, byte-identical to the `EMPTY_ROOT` baked into the deployed contract, and the
`sha256` swap hashlock matches node's own `crypto`.

## API

```ts
import init, { WasmAccount, swap_hashlock_sha256, reconstruct_root, leaf_from_da,
                htlc_claim, htlc_refund } from "liquid-cells-wasm"; // pkg-web (browser)
await init();

const alice = new WasmAccount(poolIdHex, 0x434b42n, secretHex);   // u64 args are BigInt
alice.key();            // SMT key keccak(pubkey), 0x-hex
alice.ckb_lock_args();  // blake160(pubkey): the only lock a force-exit may pay to

const transfer = JSON.parse(alice.transfer(bobKeyHex, "1000", "10", 100n)); // signed; submit to a sequencer
const lock     = JSON.parse(alice.htlc_lock(lpKeyHex, "5000", "1", H, 50n)); // includes lock.htlc_ref

// Trust-minimised recovery from L1 alone (no sequencer):
const root    = reconstruct_root(JSON.stringify(daBlobsHex)); // must equal the on-chain anchor root
const me      = JSON.parse(leaf_from_da(JSON.stringify(daBlobsHex), alice.key()));
const witness = alice.force_exit_witness(JSON.stringify(daBlobsHex)); // 0x-hex input_type for the contract
```

Conventions at the JS boundary: 32-byte values / the 33-byte pubkey / 64-byte signatures are
`0x`-hex strings; `u128` amounts are **decimal strings** (JS numbers cannot hold 128 bits); `u64`
arguments and returns (`chain_id`, `expiry`, `timeout`, `nonce`) are **BigInt**; signed intents come
back as JSON strings ready to submit to a sequencer; DA blobs go in as a JSON array of hex strings.

## Build

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.125
./build.sh        # emits pkg-node/ (CommonJS) and pkg-web/ (ES module) from one .wasm
node test/smoke.js
```

`build.sh` runs `wasm-bindgen` twice on the one cdylib: `--target nodejs` (`pkg-node/`, for node /
the smoke test) and `--target web` (`pkg-web/`, for browsers and bundlers). The generated packages
are build artifacts (gitignored); the SDK source is `src/lib.rs`.

## Notes

* Signing is deterministic (RFC 6979), so no runtime randomness is used; `getrandom`'s `js` backend
  is pulled in only to satisfy the wasm build of the k256 dependency.
* The `.wasm` is ~700 KB (release, `opt-level = "s"`); `wasm-opt` (binaryen) shrinks it further.
* The signed-intent JSON is the wire shape a JS app POSTs to a sequencer; the unsigned
  `htlc_claim` / `htlc_refund` and the force-exit/refund witnesses are submitted as-is.
