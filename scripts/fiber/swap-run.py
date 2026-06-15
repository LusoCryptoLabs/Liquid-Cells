#!/usr/bin/env python3
"""
Drive a live atomic swap across two fnn nodes, both legs locked to H = sha256(preimage).

  MAKER (default port 8237): knows the 32-byte preimage, creates a sha256 HOLD invoice, settles it
                             with the preimage to claim the Fibt payment (the on-network reveal).
  TAKER (default port 8227): pays the invoice; its payment reaches Success once the maker settles.

Fiber (like Lightning) requires the preimage to be exactly 32 bytes with payment_hash = sha256(pre).
We derive a deterministic 32-byte preimage = sha256(LABEL) so the same value can be replayed into the
Liquid Cells htlc_sha256 pool leg (see crates/stf/tests/htlc_sha256.rs). Prereq: a ChannelReady
channel funded from the taker toward the maker (see docs/FIBER-INTEGRATION.md, runbook step 3).

Usage: swap-run.py [maker_port] [taker_port] [label]
"""
import json, time, hashlib, urllib.request, sys

MAKER = int(sys.argv[1]) if len(sys.argv) > 1 else 8237
TAKER = int(sys.argv[2]) if len(sys.argv) > 2 else 8227
LABEL = (sys.argv[3] if len(sys.argv) > 3 else "liquid-cells/fiber-swap/demo-secret").encode()

PREIMAGE_BYTES = hashlib.sha256(LABEL).digest()           # 32 bytes
PREIMAGE = "0x" + PREIMAGE_BYTES.hex()                     # fnn Hash256 preimage
H = "0x" + hashlib.sha256(PREIMAGE_BYTES).hexdigest()      # payment_hash = sha256(preimage)
AMOUNT = "0x5f5e100"                                       # 100,000,000 shannons = 1 CKB (Fibt)

def rpc(port, method, params):
    body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=12))
    if r.get("error") is not None:
        raise RuntimeError(f"{method} -> {json.dumps(r['error'])}")
    return r["result"]

print(f"label           = {LABEL.decode()}")
print(f"preimage (32B)  = {PREIMAGE}")
print(f"H = sha256(pre) = {H}")
print("=" * 72)

# 1) MAKER creates a sha256 HOLD invoice locked to H (payment_hash supplied, no preimage stored).
inv = rpc(MAKER, "new_invoice", [{
    "amount": AMOUNT, "currency": "Fibt", "hash_algorithm": "sha256",
    "payment_hash": H, "expiry": "0xe10", "description": "lc dust egress swap"}])
invoice_addr = inv["invoice_address"]
print(f"[1] maker hold invoice created (payment_hash={H})")
print(f"    invoice_address = {invoice_addr}")

# 2) TAKER pays the invoice (async; the HTLC is HELD by the maker, not auto-settled).
pay = rpc(TAKER, "send_payment", [{"invoice": invoice_addr}])
pph = pay["payment_hash"]
print(f"[2] taker send_payment -> payment_hash={pph} status={pay.get('status')}")
assert pph.lower() == H.lower(), f"payment_hash {pph} != H {H}"

# 3) Poll the MAKER invoice until the HTLC is Received (held, awaiting settle).
print("[3] polling maker invoice for Received (HTLC held)...")
for i in range(30):
    st = rpc(MAKER, "get_invoice", [{"payment_hash": H}]).get("status")
    print(f"    [{i:02d}] invoice status = {st}")
    if st == "Received":
        break
    if st in ("Cancelled", "Expired", "Paid"):
        sys.exit(f"unexpected invoice status {st}")
    time.sleep(4)
else:
    sys.exit("invoice never reached Received")

# 4) MAKER settles with the 32-byte preimage -> claims Fibt and reveals the preimage on the network.
rpc(MAKER, "settle_invoice", [{"payment_hash": H, "payment_preimage": PREIMAGE}])
print(f"[4] maker settle_invoice OK (revealed preimage {PREIMAGE})")

# 5) TAKER payment goes Success; maker invoice goes Paid. Success on a HOLD invoice is proof the
#    correct preimage (sha256(preimage) == H) was revealed: fnn rejects any other preimage at settle.
print("[5] polling taker payment for Success...")
for i in range(30):
    st = rpc(TAKER, "get_payment", [{"payment_hash": H}]).get("status")
    print(f"    [{i:02d}] payment status = {st}")
    if st == "Success":
        break
    if st == "Failed":
        sys.exit("payment Failed")
    time.sleep(4)
else:
    sys.exit("payment never reached Success")

inv_final = rpc(MAKER, "get_invoice", [{"payment_hash": H}]).get("status")
print("=" * 72)
print(f"SWAP COMPLETE. taker payment Success, maker invoice {inv_final}.")
print(f"  H        = {H}")
print(f"  preimage = {PREIMAGE}  (sha256(preimage) == H verified by fnn's settle_invoice)")
print("  replay this preimage into the LC pool leg: crates/stf/tests/htlc_sha256.rs")
