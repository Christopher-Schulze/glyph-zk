#!/bin/bash
# Bench GLYPHVerifier gas on a local Anvil node.
# Measures full transaction gas (intrinsic + calldata + execution) for full and truncated layouts.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_evm_artifact.sh

Optional env:
  TIMEOUT
  ANVIL_PORT
  ANVIL_CHAIN_ID
  ANVIL_MNEMONIC
  DEPLOYER_PRIVATE_KEY
  FROM_ADDR
  ROUNDS
  COMMITMENT
  POINT
  CLAIM
  OUT_DIR
  OUT_JSON
  OUT_LOG
  OUT_META

Outputs:
  Writes bench_v1 JSON to OUT_JSON and a log to OUT_LOG.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

# Stabilize terminal size in non-interactive shells to avoid "bogus screen size" warnings.
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if [ -t 1 ]; then
    stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

# Timeout (default 5 minutes)
TIMEOUT="${TIMEOUT:-0}"
TIMEOUT_PID=""
if [ "${TIMEOUT}" -gt 0 ]; then
    (sleep "$TIMEOUT" && echo "FATAL: Timeout ($TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
    TIMEOUT_PID=$!
    trap "if [ -n "${TIMEOUT_PID:-}" ]; then kill $TIMEOUT_PID 2>/dev/null; fi" EXIT
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_glyph_evm_artifact.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_evm_artifact"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd anvil
require_cmd cast
require_cmd forge
require_cmd python3
require_cmd cargo

bench_anvil_defaults

ROUNDS="${ROUNDS:-5}"
COMMITMENT="${COMMITMENT:-0x1111111111111111111111111111111111111111111111111111111111111111}"
POINT="${POINT:-0x2222222222222222222222222222222222222222222222222222222222222222}"
CLAIM="${CLAIM:-0x000000000000000000000000000000000000000000000000000000000000007b}"

bench_setup_logs "$OUT_DIR/bench_glyph_evm_artifact.log"
bench_log_basic
bench_log_kv "rpc_url" "$RPC_URL"
bench_log_kv "chain_id" "$ANVIL_CHAIN_ID"
bench_log_kv "rounds" "$ROUNDS"
bench_log_kv "commitment" "$COMMITMENT"
bench_log_kv "point" "$POINT"
bench_log_kv "claim" "$CLAIM"
bench_log_kv "out_json" "$OUT_JSON"
bench_log_kv "out_log" "$OUT_LOG"
echo ""

cleanup() {
    if [ -n "${ANVIL_PID:-}" ] && kill -0 "$ANVIL_PID" >/dev/null 2>&1; then
        kill "$ANVIL_PID" >/dev/null 2>&1 || true
        wait "$ANVIL_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

RESULTS_TMP="$(mktemp)"

echo "=== GLYPHVerifier Bench (Anvil, GLYPH artifact-poly) ==="
echo "rpc=${RPC_URL} chain_id=${ANVIL_CHAIN_ID}"
echo ""

anvil --port "$ANVIL_PORT" --chain-id "$ANVIL_CHAIN_ID" --mnemonic "$ANVIL_MNEMONIC" --silent >/dev/null 2>&1 &
ANVIL_PID=$!

for _ in $(seq 1 50); do
    if cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    echo "ERROR: anvil did not start on ${RPC_URL}"
    exit 1
fi

echo "Building gen_glyph_gkr_proof..."
cd "$PROJECT_ROOT"
cargo build --release --bin gen_glyph_gkr_proof >/dev/null

echo "Deploying GLYPHVerifier..."
cd "$PROJECT_ROOT/scripts/tests/foundry"
DEPLOY_JSON="$(forge create ./GLYPHVerifier.sol:GLYPHVerifier --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast --json)"
CONTRACT_ADDR="$(printf '%s' "$DEPLOY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deployedTo",""))')"
cd "$PROJECT_ROOT"

if [ -z "$CONTRACT_ADDR" ]; then
    echo "ERROR: failed to deploy GLYPHVerifier via forge create"
    echo "$DEPLOY_JSON"
    exit 1
fi

echo "contract=${CONTRACT_ADDR}"
echo ""

bench_case() {
    local name="$1"
    shift

    local out
    out="$(target/release/gen_glyph_gkr_proof --artifact-poly --commitment "$COMMITMENT" --point "$POINT" --claim "$CLAIM" --rounds "$ROUNDS" --chainid "$ANVIL_CHAIN_ID" --verifier "$CONTRACT_ADDR" "$@" --json)"
    local calldata
    calldata="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata"])')"
    local calldata_len
    calldata_len="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata_len"])')"

    local tx_hash
    tx_hash="$(cast rpc --rpc-url "$RPC_URL" eth_sendTransaction --raw "[{\"from\":\"$FROM_ADDR\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"$calldata\"}]" | tr -d '\" \\n\\r')"
    if [ -z "$tx_hash" ] || [ "$tx_hash" = "null" ]; then
        echo "ERROR: could not send tx for case=${name}"
        exit 1
    fi

    local gas_used
    gas_used="$(cast receipt "$tx_hash" --rpc-url "$RPC_URL" --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("gasUsed"))')"

    local gas_breakdown
    gas_breakdown="$(python3 - <<'PY' "$calldata" "$gas_used"
import sys
calldata = sys.argv[1].lower().removeprefix("0x")
gas_used = int(sys.argv[2], 0) if sys.argv[2].startswith("0x") else int(sys.argv[2])
base_tx_gas = 21000
zero_bytes = 0
nonzero_bytes = 0
for i in range(0, len(calldata), 2):
  byte = calldata[i:i+2]
  if byte == "00":
    zero_bytes += 1
  else:
    nonzero_bytes += 1
calldata_gas = zero_bytes * 4 + nonzero_bytes * 16
execution_gas = max(gas_used - base_tx_gas - calldata_gas, 0)
print(f"{calldata_gas},{base_tx_gas},{execution_gas}")
PY
)"
    IFS="," read -r calldata_gas base_tx_gas execution_gas <<< "$gas_breakdown"
    printf "%-22s %8s %10s\\n" "$name" "$calldata_len" "$gas_used"
    printf '{"case":"%s","calldata_bytes":%s,"calldata_gas":%s,"base_tx_gas":%s,"execution_gas":%s,"tx_gas":"%s"}\n' "$name" "$calldata_len" "$calldata_gas" "$base_tx_gas" "$execution_gas" "$gas_used" >> "$RESULTS_TMP"
}

printf "%-22s %8s %10s\\n" "case" "bytes" "tx_gas"
printf "%-22s %8s %10s\\n" "----------------------" "--------" "----------"

bench_case "artifact_full" --full
bench_case "artifact_truncated" --truncated

echo ""
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$RESULTS_TMP" "$OUT_JSON" "$CONTRACT_ADDR" "$ANVIL_CHAIN_ID" "$RPC_URL" "$GIT_COMMIT" "$TIMESTAMP" <<'PY'
import json
import sys

tmp, out, contract, chain_id, rpc_url, git_commit, timestamp = sys.argv[1:]
cases = []
with open(tmp, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        cases.append(json.loads(line))

doc = {
    "bench": "bench_glyph_evm_artifact",
    "timestamp": timestamp,
    "git_commit": git_commit,
    "chain_id": chain_id,
    "rpc_url": rpc_url,
    "contract": contract,
    "cases": cases,
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2, sort_keys=True)
print(f"json_out={out}")
PY

cat > "$OUT_META" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "git_commit": "$GIT_COMMIT",
  "script": "$(basename "$0")",
  "json_out": "$(basename "$OUT_JSON")"
}
EOF

echo "Done."
bench_finalize
