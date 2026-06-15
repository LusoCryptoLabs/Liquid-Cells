#!/bin/bash
# Create a Fiber `sha256` hold invoice whose payment_hash = sha256(SECRET), the same H the Liquid
# Cells pool leg locks to. Validates that the Fiber leg and the pool leg share one hashlock.
#
#   ./new-sha256-invoice.sh [SECRET] [AMOUNT_HEX] [RPC_URL]
#
# Defaults: a demo secret, 1 CKB (0x5f5e100 shannons), the local testnet node.
set -e
SECRET="${1:-liquid-cells/fiber-swap/demo-secret}"
AMOUNT="${2:-0x5f5e100}"
RPC="${3:-http://127.0.0.1:8227}"

H="0x$(python3 -c "import hashlib;print(hashlib.sha256(b'$SECRET').hexdigest())")"
echo "secret      = $SECRET"
echo "H=sha256(s) = $H"

REQ=$(python3 - "$H" "$AMOUNT" <<'PY'
import json,sys
h,amount=sys.argv[1],sys.argv[2]
print(json.dumps({"id":1,"jsonrpc":"2.0","method":"new_invoice","params":[{
  "amount":amount,"currency":"Fibt","hash_algorithm":"sha256","payment_hash":h,
  "expiry":"0xe10","description":"lc dust egress"}]}))
PY
)
curl -s -m 8 -X POST "$RPC" -H "content-type: application/json" -d "$REQ" | python3 -m json.tool
