# Fiber egress: live integration

This is the live counterpart to [EGRESS.md](EGRESS.md). The dust-egress swap moves a sub-61-CKB
in-pool balance to a liquidity provider in exchange for a Fiber payment, atomically, via one shared
`sha256` preimage. The Liquid Cells side is complete and in-process tested (the `htlc_sha256` pool
hashlock, the swap coordinator `crates/client/src/swap.rs`, and the runnable drivers). This doc
records the **live Fiber side**: that a real Fiber node locks to the *same* `H` the pool leg does.

## The crux, validated live

An atomic swap is only trustless if both legs lock to the **same** `H = hash(preimage)`. Liquid
Cells hashlocks with `sha256` (the `htlc_sha256` staged change); Fiber's invoice `hash_algorithm` is
`ckb_hash` or `sha256` (never keccak), and Fiber supports **hold invoices** (supply `payment_hash`,
withhold the preimage, settle later). So the maker creates a `sha256` hold invoice whose
`payment_hash` is exactly the `H` it locks the pool leg to, settles it with the preimage to get paid,
and that reveal lets the taker pull the pool leg under the same `H`.

One integration detail, learned live: Fiber (like Lightning) requires the preimage to be **exactly 32
bytes**, with `payment_hash = sha256(preimage)`. We therefore use a deterministic 32-byte preimage,
`sha256("liquid-cells/fiber-swap/demo-secret")`, and lock to `H = sha256(preimage)`:

```
preimage (32B)  = 0x092bd75192e4858f5c2507ff54c02136b97c22b4250d5986c5f954254cc87a45
H = sha256(pre) = 0x4a7c1118c01e0f7cd488185180c2bcefa79bf3928eb638191890398200332f36
```

## Live funded swap (end to end)

Run against two local `fnn` v0.8.1 testnet nodes (June 2026), a funded channel between them, driven
by `/root/fnn-run/swap-run.py`:

* **node1** (taker, port `8227`, pubkey `022a6991...`): channel funder, ~2401 CKB local balance.
* **node2** (maker, port `8237`, pubkey `02b90ee1...`): holds the `sha256` hold invoice, settles it.
* **Channel** `0x84f600a6e13af904b906084525e55e61803414204e6312f2ee8fe94042d4763e`, state `ChannelReady`.

The transcript, every step a live RPC call:

```
[1] maker new_invoice { hash_algorithm:"sha256", payment_hash:H, amount:1 CKB } (HOLD)
      invoice_address = fibt1000000001peqmuswpnckgfw0pnm6vks6akpgs4p9jxcgrld5hvuxpsuxmx05k944...
[2] taker send_payment { invoice } -> payment_hash = 0x4a7c1118...332f36  (== H), status Created
[3] maker get_invoice -> Open -> Received           (HTLC held, awaiting the preimage)
[4] maker settle_invoice { payment_hash:H, payment_preimage:0x092bd751...4cc87a45 }  -> OK
[5] taker get_payment -> Inflight -> Success        ;  maker get_invoice -> Paid
```

`settle_invoice` is the on-network reveal: fnn rejects any preimage whose `sha256` is not the
invoice's `payment_hash` (it rejected a 34-byte preimage during bring-up), so a HOLD invoice reaching
`Paid` / a payment reaching `Success` is cryptographic proof the correct 32-byte preimage was
revealed. (fnn v0.8.1's `get_payment` does not surface the preimage value over RPC; the node uses it
internally to fulfill the HTLC. The value is the deterministic preimage above, and
`sha256(preimage) == payment_hash == H` is verifiable on both legs.)

**Both legs, one secret.** The same 32-byte preimage that settled the live Fiber payment claims the
pool leg, pinned in `crates/stf/tests/htlc_sha256.rs::live_fiber_preimage_claims_the_pool_leg`: it
asserts `sha256(preimage) == 0x4a7c1118...332f36` (the exact live `payment_hash`) and then opens an
in-pool dust HTLC locked to that `H` by revealing the preimage. Revealing the secret on Fiber and on
the pool are one and the same act. The only crypto unknown in the egress is now closed, end to end,
against real nodes and a funded channel, not a mock.

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

**3. Fund + channel (needs testnet CKB).** Derive each node's funding address with
`scripts/fiber/ckb-address.py` from `node_info.default_funding_lock_script`, fund it from the Nervos
Pudge faucet, then `open_channel`. **Both** parties must be funded: the opener posts the
`funding_amount`, but the acceptor must also post its own ~99 CKB channel reserve, so an unfunded
counterparty fails funding with `capacity not enough ... value=99.0`. A second local node on ports
`8237/8238` is the simplest counterparty for an end-to-end demo.

## Status

* ✅ **Funded live swap, end to end.** Two funded `fnn` nodes, a `ChannelReady` channel, a `sha256`
  hold invoice, a real `send_payment`, `settle_invoice` revealing the 32-byte preimage, payment
  `Success` / invoice `Paid` (the "Live funded swap" section above).
* ✅ **Hash compatibility, live.** Both legs lock to one `H = sha256(preimage)`; the exact live
  preimage and `payment_hash` are pinned in `crates/stf/tests/htlc_sha256.rs`.
* ✅ **LC side complete + tested in-process.** `htlc_sha256` hashlock, swap coordinator, and runnable
  Maker/Taker drivers (`crates/client/tests/swap.rs` settles a full swap through the real STF).
* The receiver-side force-claim residual ([EGRESS.md](EGRESS.md)) is a priced LP risk, mitigated by
  short-lived dust swaps while the operator is live, not a blocker for v1.
