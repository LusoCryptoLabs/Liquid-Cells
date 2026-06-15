#!/usr/bin/env python3
# Derive the CKB testnet (ckb2021 full) address for an fnn node's funding lock, so it can be funded
# from the Pudge faucet. Read code_hash + args from `node_info.default_funding_lock_script`.
#
#   python3 ckb-address.py <code_hash_hex> <args_hex> [hash_type=type]
#
# Example (a node's default secp256k1 funding lock):
#   python3 ckb-address.py 9bd7e06f...3cce8 328ee966...82b1 type
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
HASH_TYPE = {"data": 0x00, "type": 0x01, "data1": 0x02, "data2": 0x04}

def polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def checksum(hrp, data):  # bech32m
    vals = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data + [0] * 6
    pm = polymod(vals) ^ 0x2bc830a3
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data):
    acc = bits = 0; ret = []
    for b in data:
        acc = (acc << 8) | b; bits += 8
        while bits >= 5:
            bits -= 5; ret.append((acc >> bits) & 31)
    if bits:
        ret.append((acc << (5 - bits)) & 31)
    return ret

def encode(hrp, payload):
    data = convertbits(payload)
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum(hrp, data))

if __name__ == "__main__":
    code_hash = bytes.fromhex(sys.argv[1].removeprefix("0x"))
    args = bytes.fromhex(sys.argv[2].removeprefix("0x"))
    ht = HASH_TYPE[sys.argv[3] if len(sys.argv) > 3 else "type"]
    payload = bytes([0x00]) + code_hash + bytes([ht]) + args  # 0x00 = full address format
    print(encode("ckt", payload))  # "ckb" for mainnet
