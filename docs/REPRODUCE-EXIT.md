# Reproduce a unilateral exit from L1 alone

This is the runnable proof of the non-custody claim: **rebuild a depositor's balance and the exact
force-exit witness from on-chain data only, with no sequencer, no operator API, and no receipt
server.** The tool is [`lc-exit`](../crates/client/src/bin/lc-exit.rs); the only trusted input is the
on-chain anchor root.

## What it proves (and what it assumes)

- **Safety (on-chain enforced):** every checkpoint must publish its full state diff
  (`key ‖ balance ‖ nonce` per touched leaf) in the checkpoint transaction's witness. The validity
  proof commits `keccak(da_blob)` in-circuit and the anchor type script rejects any checkpoint whose
  witness does not carry that exact blob (reject code 59, see [DA.md](DA.md)). So the operator cannot
  advance the root while withholding or altering what changed.
- **The data source is checked, not trusted.** `lc-exit` folds the published blobs, rebuilds the
  sparse Merkle tree, and **asserts the rebuilt root equals the live on-chain anchor root**. A node
  or indexer that omits, reorders, or corrupts checkpoints produces a root **MISMATCH** (exit code 3)
  and is caught. It can deny service; it cannot forge a balance.
- **The one residual is data-availability liveness, not the operator.** Reconstruction needs every
  historical checkpoint's witness, retrieved from an **archival** CKB node. CKB full nodes do not
  prune block bodies by default, so an ordinary from-genesis node retains every witness, and *you can
  be that node*. This is the standard rollup DA-liveness assumption (>=1 honest archival node), shared
  by all rollups; it does not route through us.

## Prerequisites

- A CKB **testnet** JSON-RPC + indexer endpoint. The public `https://testnet.ckb.dev` works out of
  the box. **For a fully independent check, run your own node** (`ckb run` synced from genesis, with
  the built-in indexer enabled via `--indexer`) and pass it with `--rpc`.
- You also need the pool's **anchor type identity** out of band, the same way you need a token's
  contract address: the deployed anchor `code_hash` (the `lc-exit` default) and the pool's type-id
  `args`. The type-id is unforgeable, and the root-check binds you to the genuine cell.

## Build

```
cargo build -p liquid-cells-client --features cli --release
```

## Run it against the live Pudge pool (read-only)

This recovers the demo depositor's leaf on the live type-id'd pool. The key below is the public
testnet demo key (also pinned in `crates/client/tests/reconstruct.rs`):

```
./target/release/lc-exit \
  --args 0x06865b65f867970c6d89f5e82ed530362f00e5051ea7265556646e7835b63295 \
  --key  0x61da078bba9223fb5955014bd3a9fa814d210e89add2c31039a1cf04eb598536
```

(`--code-hash` defaults to the deployed anchor `0x83158549…`; `--rpc` defaults to
`https://testnet.ckb.dev`. Pass your own node to either to remove all third-party infrastructure.)

Expected output:

```
live anchor : 0x332e49ff…:0
on-chain    : root=0x00b5dbaf… seq=1
checkpoints : N tx(s), M DA blob(s) folded
reconstructed: root=0x00b5dbaf…  [MATCH]
your key    : 0x61da078b…
your balance: 19998900000 shannons (199.989 CKB), nonce 1
```

The `[MATCH]` line is the integrity guarantee: the tree rebuilt purely from L1 witnesses equals the
root the chain is enforcing.

## Recover your own balance and emit the force-exit witness

Pass your 32-byte account secret instead of a bare key. In addition to your balance, `lc-exit` emits
the exact 8249-byte force-exit witness (`pubkey ‖ balance ‖ nonce ‖ 256 siblings`) the anchor type
script consumes, ready to drop into a force-exit transaction that pays your
`secp256k1_blake160` lock:

```
./target/release/lc-exit \
  --args   0x06865b65f867970c6d89f5e82ed530362f00e5051ea7265556646e7835b63295 \
  --secret 0x<your-32-byte-account-secret>
```

The only secret you supply is your own key; balance, nonce, and the inclusion path all come from L1.

## Offline regression (no RPC)

The same reconstruction, against a pinned fixture of the live pool, runs as a test with no network:

```
cargo test -p liquid-cells-client --test reconstruct
```

It asserts the root rebuilt from the published DA blob equals the on-chain anchor root and that the
depositor's leaf (199.989 CKB, nonce 1) is recovered from L1 data alone.
