#!/bin/bash
# Bench GLYPHVerifier gas using a real GLYPH-Prover pipeline (hash adapter).

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_evm_realproof.sh

Optional env:
  TIMEOUT
  ANVIL_PORT
  ANVIL_CHAIN_ID
  ANVIL_MNEMONIC
  DEPLOYER_PRIVATE_KEY
  FROM_ADDR
  FAMILY
  LEFT_HEX
  RIGHT_HEX
  RECEIPT_PATH
  RECEIPT_HEX
  RECEIPT_HEX_PATH
  SEED
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

# Timeout (default 15 minutes)
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
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_glyph_evm_realproof.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_evm_realproof"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd anvil
require_cmd cast
require_cmd forge
require_cmd python3
require_cmd cargo

bench_anvil_defaults

# Ensure Foundry binaries are discoverable in non-interactive shells.
export PATH="$HOME/.foundry/bin:$PATH"

# Adapter family for the real proof bench.
FAMILY="${FAMILY:-hash}"

# Hash adapter inputs.
LEFT_HEX="${LEFT_HEX:-0x1111111111111111111111111111111111111111111111111111111111111111}"
RIGHT_HEX="${RIGHT_HEX:-0x2222222222222222222222222222222222222222222222222222222222222222}"

# STARK adapter inputs.
RECEIPT_PATH="${RECEIPT_PATH:-}"
RECEIPT_HEX="${RECEIPT_HEX:-}"
RECEIPT_HEX_PATH="${RECEIPT_HEX_PATH:-}"
SEED="${SEED:-glyph-stark-seed}"

bench_setup_logs "$OUT_DIR/bench_glyph_evm_realproof.log"
bench_log_basic
bench_log_kv "rpc_url" "$RPC_URL"
bench_log_kv "chain_id" "$ANVIL_CHAIN_ID"
bench_log_kv "family" "$FAMILY"
if [ "$FAMILY" = "hash" ]; then
    bench_log_kv "left_hex" "$LEFT_HEX"
    bench_log_kv "right_hex" "$RIGHT_HEX"
else
    bench_log_kv "receipt_path" "$RECEIPT_PATH"
    bench_log_kv "receipt_hex_path" "$RECEIPT_HEX_PATH"
    bench_log_kv "receipt_hex_len" "${#RECEIPT_HEX}"
    bench_log_kv "seed" "$SEED"
fi
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

echo "=== GLYPHVerifier Real-Proof Bench (Anvil) ==="
echo "rpc=${RPC_URL} chain_id=${ANVIL_CHAIN_ID}"
echo "family=${FAMILY}"
if [ "$FAMILY" = "hash" ]; then
    echo "left=${LEFT_HEX}"
    echo "right=${RIGHT_HEX}"
else
    echo "receipt=${RECEIPT_PATH}"
    if [ -n "$RECEIPT_HEX_PATH" ]; then
        echo "receipt_hex_path=${RECEIPT_HEX_PATH}"
    fi
    if [ -n "$RECEIPT_HEX" ]; then
        echo "receipt_hex_len=${#RECEIPT_HEX}"
    fi
    echo "seed=${SEED}"
fi
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

echo "Building glyph_prover..."
cargo build --release --bin glyph_prover >/dev/null

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

if [ "$FAMILY" = "hash" ]; then
    DIGEST_HEX="$(cast keccak 0x${LEFT_HEX#0x}${RIGHT_HEX#0x} | tr -d '\r\n')"
    echo "contract=${CONTRACT_ADDR}"
    echo "digest=${DIGEST_HEX}"
    echo ""
    out="$(target/release/glyph_prover --family hash --mode fast --left "$LEFT_HEX" --right "$RIGHT_HEX" --digest "$DIGEST_HEX" --chain-id "$ANVIL_CHAIN_ID" --verifier "$CONTRACT_ADDR" --calldata-only --json)"
else
    if [ -n "$RECEIPT_HEX_PATH" ] && [ -z "$RECEIPT_HEX" ]; then
        receipt_hex="$(tr -d '\r\n' < "$RECEIPT_HEX_PATH")"
        receipt_hex="${receipt_hex#receipt_hex=}"
        if [ -n "$receipt_hex" ] && [[ "$receipt_hex" != 0x* ]]; then
            receipt_hex="0x${receipt_hex}"
        fi
        RECEIPT_HEX="$receipt_hex"
    fi

    if [ -n "$RECEIPT_HEX" ]; then
        out="$(target/release/glyph_prover --family "$FAMILY" --mode fast --receipt-hex "$RECEIPT_HEX" --seed "$SEED" --chain-id "$ANVIL_CHAIN_ID" --verifier "$CONTRACT_ADDR" --calldata-only --json)"
    else
        if [ -z "$RECEIPT_PATH" ]; then
            echo "ERROR: RECEIPT_PATH or RECEIPT_HEX/RECEIPT_HEX_PATH is required for FAMILY=${FAMILY}"
            exit 1
        fi
        out="$(target/release/glyph_prover --family "$FAMILY" --mode fast --receipt "$RECEIPT_PATH" --seed "$SEED" --chain-id "$ANVIL_CHAIN_ID" --verifier "$CONTRACT_ADDR" --calldata-only --json)"
    fi
    echo "contract=${CONTRACT_ADDR}"
    echo ""
fi
calldata="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata"])')"
calldata_len="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata_len"])')"

if [ -z "$calldata" ]; then
    echo "ERROR: glyph_prover did not emit calldata"
    exit 1
fi

rounds=$(( (calldata_len - 64) / 32 ))

if ! cast call "$CONTRACT_ADDR" --data "$calldata" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    echo "ERROR: eth_call failed for real-proof calldata"
    exit 1
fi

tx_hash="$(cast rpc --rpc-url "$RPC_URL" eth_sendTransaction --raw "[{\"from\":\"$FROM_ADDR\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"$calldata\"}]" | tr -d '\" \n\r')"
if [ -z "$tx_hash" ] || [ "$tx_hash" = "null" ]; then
    echo "ERROR: could not send tx for real-proof calldata"
    exit 1
fi

receipt_json="$(cast receipt "$tx_hash" --rpc-url "$RPC_URL" --json)"
gas_used="$(printf '%s' "$receipt_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("gasUsed"))')"
status="$(printf '%s' "$receipt_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')"
if [ "$status" != "1" ] && [ "$status" != "0x1" ]; then
    echo "ERROR: tx status != 1 for real-proof calldata"
    exit 1
fi

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

printf "%-16s %s\n" "calldata_bytes" "$calldata_len"
printf "%-16s %s\n" "rounds" "$rounds"
printf "%-16s %s\n" "tx_gas" "$gas_used"

echo ""

GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$OUT_JSON" "$calldata_len" "$rounds" "$gas_used" "$CONTRACT_ADDR" "$ANVIL_CHAIN_ID" "$RPC_URL" "$FAMILY" "$GIT_COMMIT" "$TIMESTAMP" "$calldata_gas" "$base_tx_gas" "$execution_gas" <<'PY'
import json
import sys

args = sys.argv[1:]
out, calldata_len, rounds, gas_used, contract, chain_id, rpc_url, family, git_commit, timestamp = args[:10]
extra = args[10:]
calldata_gas = int(extra[0]) if len(extra) > 0 else None
base_tx_gas = int(extra[1]) if len(extra) > 1 else None
execution_gas = int(extra[2]) if len(extra) > 2 else None
doc = {
    "bench": "bench_glyph_evm_realproof",
    "timestamp": timestamp,
    "git_commit": git_commit,
    "chain_id": chain_id,
    "rpc_url": rpc_url,
    "contract": contract,
    "family": family,
    "calldata_bytes": int(calldata_len),
    "rounds": int(rounds),
    "tx_gas": gas_used,
    "calldata_gas": calldata_gas,
    "base_tx_gas": base_tx_gas,
    "execution_gas": execution_gas,
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
