#!/usr/bin/env bash
# Reproducibility check for the SP1 guest verifying key.
#
# The vkey (0x00213af5…c1e8) binds the on-chain verifier to EXACTLY this STF. It is pinned in
# three places that must never drift:
#   * crates/ckb-contract/src/main.rs   static VKEY_HASH  (baked into the deployed code cell)
#   * fixtures/vkey.txt                                   (the value the prover emitted)
#   * crates/sp1-host/src/bin/prove_one.rs EXPECTED_VKEY  (asserted on every proof)
#
# This script asserts all three agree (catches the "changed the STF, forgot to re-bake" bug
# cheaply). The full reproducibility check (rebuild the guest ELF and recompute the vkey from
# it) is heavier and needs the SP1 toolchain; the command is printed at the end.
set -euo pipefail
cd "$(dirname "$0")/.."

FIX="$(tr -d '[:space:]' < fixtures/vkey.txt)"
EXPECT="$(grep -oE '0x[0-9a-f]{64}' crates/sp1-host/src/bin/prove_one.rs | head -1)"
# Reconstruct VKEY_HASH from the contract's byte-array literal (the two lines between the
# `static VKEY_HASH` declaration and its closing `];`).
BAKED="0x$(awk '/static VKEY_HASH/{f=1;next} f&&/\];/{exit} f{print}' crates/ckb-contract/src/main.rs \
  | grep -oE '0x[0-9a-f]{2}' | sed 's/0x//' | tr -d '\n')"

echo "fixtures/vkey.txt  : $FIX"
echo "prove_one EXPECTED : $EXPECT"
echo "contract VKEY_HASH : $BAKED"
echo

fail=0
[ "$FIX" = "$EXPECT" ] || { echo "MISMATCH: fixtures/vkey.txt != prove_one EXPECTED_VKEY"; fail=1; }
[ "$FIX" = "$BAKED" ]  || { echo "MISMATCH: fixtures/vkey.txt != contract VKEY_HASH"; fail=1; }
if [ "$fail" -ne 0 ]; then
  echo "FAIL: the vkey pin sites disagree. The STF and the deployed verifier are out of sync."
  exit 1
fi

echo "OK: all three vkey pin sites agree."
echo

# The guest ELF (hence the vkey) must compile the STF with NO vkey-affecting features. `journal`
# (codec helpers), `min_fee` (the in-proof fee floor), `compact_smt` (the compact tree's node-hash
# rules), `reject_high_s` (high-S signature rejection), `da_varint` (varint DA-blob layout),
# `htlc_sha256` (the SHA-256 HTLC hashlock), `htlc_keyspace` (the H-1 escrow keyspace fix),
# `ecrecover` (the pubkey-recovery signature scheme) and
# `hash_count` (the keccak counter) all change the guest if enabled, so the guest's stf dependency
# must pull default features only. Catch an accidental feature leak cheaply. (`htlc_sha256 =
# ["dep:sha2"]` so a leak would also pull sha2.)
GUEST_STF_LINE="$(grep -E 'liquid-cells-stf' crates/sp1-guest/Cargo.toml || true)"
echo "guest stf dep      : $GUEST_STF_LINE"
if echo "$GUEST_STF_LINE" | grep -qE 'journal|min_fee|compact_smt|reject_high_s|da_varint|htlc_sha256|htlc_keyspace|ecrecover|hash_count'; then
  echo "FAIL: crates/sp1-guest enables a vkey-affecting stf feature (journal/min_fee/compact_smt/"
  echo "      reject_high_s/da_varint/htlc_sha256/htlc_keyspace/ecrecover/hash_count). The deployed vkey is for the feature-OFF guest."
  exit 1
fi
# And the STF must not turn any of them on by default. (Each must be `name = [...]`, possibly empty.)
if grep -E '^(journal|min_fee|compact_smt|reject_high_s|da_varint|htlc_sha256|htlc_keyspace|ecrecover|hash_count)\s*=' crates/stf/Cargo.toml | grep -qvE '=\s*\[[^]]*\]'; then
  echo "FAIL: a vkey-affecting stf feature has non-list defaults in crates/stf."
  exit 1
fi
echo "OK: guest compiles the STF with journal + min_fee + compact_smt + reject_high_s + da_varint + htlc_sha256 + htlc_keyspace + ecrecover + hash_count OFF (vkey-neutral)."
echo
echo "Pinned build inputs (ALL must match to reproduce the vkey byte-for-byte):"
echo "  succinct rustc   1.94.0   (cargo-prove's toolchain; == the ghcr.io/succinctlabs/sp1:v6.2.4 image)"
echo "  sp1-zkvm/sdk     6.2.4    (crates/sp1-guest, crates/sp1-host)"
echo "  guest features   journal + min_fee + compact_smt + reject_high_s + da_varint + htlc_sha256 + htlc_keyspace + ecrecover + hash_count OFF (default)"
echo "  build path       \$HOME/liquid-cells   (SP1 embeds the absolute source path in the guest ELF,"
echo "                   so the rebuild must run from the SAME path the deploy used, with HOME=/root)"
echo
echo "Full rebuild check (heavy, needs the SP1 toolchain in the build env):"
echo "  (cd crates/sp1-guest && cargo prove build) && scripts/groth16.sh 1"
echo "rebuilds the guest ELF and a proof; the host/prove_one assert the recomputed vkey == the"
echo "value above, so a clean run proves the deployed verifier is bound to exactly this STF."
