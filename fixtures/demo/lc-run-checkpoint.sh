#!/usr/bin/env bash
# Prove (WSL) then submit (Windows node.exe) one demo checkpoint. Spawned by the demo server.
#   lc-run-checkpoint.sh <jobname>
# Reads  fixtures/demo/<jobname>/sp1_input.bin, writes groth16_proof.bin + public_values.bin there,
# then runs the CCC submit driver which lands the checkpoint on Pudge and writes result.json.
set -u
source "$HOME/.cargo/env" 2>/dev/null
export PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:$PATH"
JOBNAME="${1:?usage: lc-run-checkpoint.sh <jobname>}"
ROOT=/root/liquid-cells
JOB="$ROOT/fixtures/demo/$JOBNAME"
ELF="$ROOT/crates/sp1-guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/liquid-cells-guest"
PROVER="$ROOT/crates/sp1-host/target/release/prove_one"
LOG="$JOB/run.log"
NODE="/mnt/c/Program Files/nodejs/node.exe"
CCC="/mnt/c/Users/telmo/Downloads/cellswap/cellswap-complete"

echo "=== prove $JOBNAME $(date) ===" > "$LOG"
cd "$ROOT/crates/sp1-host" || { echo "no sp1-host" >> "$LOG"; exit 1; }
"$PROVER" "$ELF" "$JOB/sp1_input.bin" "$JOB" >> "$LOG" 2>&1
PEX=$?
echo "prove exit=$PEX $(date)" >> "$LOG"
if [ $PEX -ne 0 ]; then echo "PROVE_FAILED" >> "$LOG"; exit $PEX; fi

echo "=== submit $JOBNAME $(date) ===" >> "$LOG"
cd "$CCC" || { echo "no ccc dir" >> "$LOG"; exit 1; }
"$NODE" lc-demo-checkpoint.mjs "$JOBNAME" >> "$LOG" 2>&1
SEX=$?
echo "submit exit=$SEX $(date)" >> "$LOG"
if [ $SEX -ne 0 ]; then echo "SUBMIT_FAILED" >> "$LOG"; exit $SEX; fi
echo "CHECKPOINT_DONE" >> "$LOG"
