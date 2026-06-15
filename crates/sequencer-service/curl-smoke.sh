#!/bin/bash
# Live HTTP smoke test of lc-sequencer-service: start it, drive submit -> seal -> query over curl.
set -e
BIN=/root/liquid-cells/crates/sequencer-service/target/debug/lc-sequencer-service
"$BIN" --port 8910 >/tmp/lc-svc.log 2>&1 &
PID=$!
trap "kill $PID 2>/dev/null" EXIT
sleep 1
B=http://127.0.0.1:8910
KEY=0x1111111111111111111111111111111111111111111111111111111111111111
cut() { head -c 360; echo; }

echo "=== GET /info ===";          curl -s $B/info | cut
echo "=== POST /submit deposit ==="; curl -s -X POST $B/submit -d "{\"type\":\"deposit\",\"to_key\":\"$KEY\",\"amount\":\"1000000\"}" | cut
echo "=== POST /seal ===";         curl -s -X POST $B/seal -d '{"current_epoch":1,"fee_withdrawal":"0"}' | cut
echo "=== GET /leaf ===";          curl -s "$B/leaf?key=$KEY" | cut
echo "=== GET /da ===";            curl -s $B/da | cut
echo "=== GET /info (after) ===";  curl -s $B/info | cut
