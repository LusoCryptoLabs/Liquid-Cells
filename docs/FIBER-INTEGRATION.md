# Fiber egress: live integration

This is the live counterpart to [EGRESS.md](EGRESS.md). The dust-egress swap moves a sub-61-CKB
in-pool balance to a liquidity provider in exchange for a Fiber payment, atomically, via one shared
`sha256` preimage. The Liquid Cells side is complete and in-process tested (the `htlc_sha256` pool
hashlock, the swap coordinator `crates/client/src/swap.rs`, and the runnable drivers). This doc
records the **live Fiber side**: that a real Fiber node locks to the *same* `H` the pool leg does.

## The crux, validated live

An atomic swap is only trustless if both legs lock to the **same** `H = hash(secret)`. Liquid Cells
hashlocks with `sha256` (the `htlc_sha256` staged change); Fiber's invoice `hash_algorithm` is
`ckb_hash` or `sha256` (never keccak), and Fiber supports **hold invoices** (supply `payment_hash`,
withhold the preimage, settle later). So the maker creates a `sha256` hold invoice whose
`payment_hash` is exactly `sha256(secret)`, the same `H` it locks the pool leg to.

Validated against a live `fnn` v0.8.1 testnet node (June 2026):

```
secret      = liquid-cells/fiber-swap/demo-secret
H=sha256(s) = 0x092bd75192e4858f5c2507ff54c02136b97c22b4250d5986c5f954254cc87a45

new_invoice { amount, currency:"Fibt", hash_algorithm:"sha256", payment_hash:H } =>
  invoice_address: fibt1000000001pcv7vx0fwe2gfw0pmm6vkxhvntj9wxt3g...
  invoice.data.payment_hash: 0x092bd75192e4858f5c2507ff54c02136b97c22b4250d5986c5f954254cc87a45   <= our H
  invoice.data.attrs:        hash_algorithm: sha256
```

The Fiber node accepted our `sha256(secret)` as the invoice payment hash. **The pool leg and the
Fiber leg lock to the same `H`**, so revealing `secret` on one network opens the other. The only
crypto unknown in the egress is now closed, against a real node, not a mock.

## RPC method ↔ swap-coordinator mapping

Wire method names have no module prefix (`fnn`'s JSON-RPC, default `127.0.0.1:8227`). The
[`CounterpartyLeg`](../crates/client/src/swap.rs) trait the drivers call maps to two `fnn` nodes:

| Coordinator step (`swap.rs`)        | Fiber RPC (who)                                   |
|-------------------------------------|---------------------------------------------------|
| maker proposes terms (`H`)          | maker: `new_invoice { hash_algorithm:"sha256", payment_hash:H }` (hold) |
| `TakerDriver` → `LockCounterparty`  | taker: `send_payment { invoice }` (pays the hold invoice; HTLC in-flight) |
| `state()` observed by maker         | maker: `get_invoice` (status: received / held)    |
| `MakerDriver` → `ClaimCounterparty` | maker: `settle_invoice { payment_hash:H, payment_preimage:secret }` (reveals `s`, gets paid) |
| `state()` observed by taker         | taker: `get_payment` (status success; preimage now known) |
| `TakerDriver` → `RefundCounterparty`| taker: payment HTLC times out / `cancel_invoice` (maker side) |

Then the taker, knowing `s`, submits the LC `htlc_claim` the `TakerDriver` already emits, and the
pool dust settles to the LP. Timeout ordering: the Fiber invoice `expiry` / `final_htlc_minimum_
expiry_delta` must be shorter than the pool `T_pool`, as `SwapTerms::validate` enforces abstractly.

## Runbook

**1. Run a node (no build needed):**
```
curl -sL -o fnn.tar.gz \
  https://github.com/nervosnetwork/fiber/releases/download/v0.8.1/fnn_v0.8.1-x86_64-linux-portable.tar.gz
mkdir node && tar -xzf fnn.tar.gz -C node && cd node
cp config/testnet/config.yml .
mkdir ckb && python3 -c "import secrets;open('ckb/key','w').write(secrets.token_hex(32)+'\n')"
FIBER_SECRET_KEY_PASSWORD=swappw RUST_LOG=info ./fnn -c config.yml -d .
```
The testnet config points CKB at `https://testnet.ckbapp.dev/`, RPC at `127.0.0.1:8227`, p2p at
`:8228`, and dials the testnet bootnodes. `node_info` confirms `peers_count > 0`.

**2. Create the swap's `sha256` hold invoice** (no funds needed): `scripts/fiber/new-sha256-invoice.sh`.

**3. Fund + channel (needs testnet CKB).** Derive the node's funding address with
`scripts/fiber/ckb-address.py` from `node_info.default_funding_lock_script`, fund it from the Nervos
Pudge faucet, then `open_channel` (or `connect_peer` to an LP with inbound liquidity). A second local
node on ports `8237/8238` is the simplest counterparty for an end-to-end demo.

## Status

* ✅ **Hash compatibility, live.** A real Fiber node locks to `H = sha256(secret)`, identical to the
  LC pool leg's hashlock (this doc).
* ✅ **LC side complete + tested in-process.** `htlc_sha256` hashlock, swap coordinator, and runnable
  Maker/Taker drivers (`crates/client/tests/swap.rs` settles a full swap through the real STF).
* ◻ **Funded live swap.** Fund a node, open a channel, run the drivers against an `fnn`-backed
  `CounterpartyLeg`. This is the remaining operational wiring (no protocol/code blockers): a Fiber
  node + LP liquidity, the trait impl over the RPC above, and the timeout mapping.
* The receiver-side force-claim residual ([EGRESS.md](EGRESS.md)) is a priced LP risk, mitigated by
  short-lived dust swaps while the operator is live, not a blocker for v1.
