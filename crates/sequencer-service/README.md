# liquid-cells-sequencer-service

The off-chain Liquid Cells sequencer behind a tiny HTTP front: the link between "a client signs an
intent" and "the intent lands in a checkpoint". A client POSTs a signed intent, the service parses
it with `liquid_cells_client::wire` (the **same** definitions the WASM SDK serializes with, so the
encoding cannot drift), submits it to the `Sequencer`, and a seal advances the committed root.

The heavy Groth16 proving and on-chain (Pudge) submission of a sealed checkpoint stay the separate
driver they already are; `/seal` returns the `sp1_input` for that driver to pick up. This service is
the off-chain half: mempool, seal, query, DA.

## Endpoints (all JSON)

| Method + path        | Body / query                              | Returns |
|----------------------|-------------------------------------------|---------|
| `GET  /` `/info`     | -                                         | pool id, chain id, seq, root, total, fee_acc, pending, checkpoints |
| `POST /submit`       | a tagged intent JSON (the SDK `wire` form)| `{ ok, accepted, pending }` |
| `POST /seal`         | `{ "current_epoch": N, "fee_withdrawal": "0" }` | seq, root, new_anchor, da_blob, sp1_input, total, fee_acc |
| `GET  /leaf?key=0x..`| -                                         | `{ key, balance, nonce }` |
| `GET  /da`           | -                                         | `{ blobs: [0x..] }` (every published DA blob) |

Single-threaded (one request at a time), which is all a local / demo sequencer needs.

## Run

```
cargo run -p liquid-cells-sequencer-service --bin lc-sequencer-service -- --port 8910
#   --pool-id 0x..32B   (default keccak("lc-service-pool"))
#   --chain-id 0x434b42
```

## Demos

* `curl-smoke.sh`, drives `submit -> seal -> leaf -> da` over `curl` against a fresh service.
* `demo/wasm-e2e.js`, the full stack: the **WASM SDK signs a payment and submits it over HTTP**.
  Start the service, then `node demo/wasm-e2e.js` (needs the SDK built: `crates/wasm/build.sh`). It
  funds an account, signs a transfer in the SDK, POSTs it, seals, checks the recipient balance, and
  rebuilds the root from `/da` in the SDK to confirm it equals the service root, trustless
  verification end to end. The service runs in WSL; the node demo runs on the host and reaches it via
  localhost.
