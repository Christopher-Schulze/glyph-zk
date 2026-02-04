#!/bin/bash
# Bench Groth16 verifier gas on Ethereum Hoodi.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_groth16_hoodi.sh

Required env:
  HOODI_RPC_URL

Optional env:
  TIMEOUT
  HOODI_CHAIN_ID
  DEPLOY_FILE
  WALLET_ENV_FILE
  ARTIFACT_DIR
  GROTH16_SOL_PATH
  GROTH16_CONTRACT
  GROTH16_SIG
  FORCE_DEPLOY
  SEND_TX
  FOUNDRY_BIN
  OUT_DIR
  OUT_LOG (alias: OUT_FILE_LOG)
  OUT_JSON
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

export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if [ -t 1 ]; then
    stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

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
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_groth16_hoodi.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "groth16_hoodi"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd cast
require_cmd forge
require_cmd python3

HOODI_CHAIN_ID="${HOODI_CHAIN_ID:-560048}"
DEPLOY_FILE="${DEPLOY_FILE:-$PROJECT_ROOT/deployments/hoodi_groth16.json}"
WALLET_ENV_FILE="${WALLET_ENV_FILE:-$PROJECT_ROOT/docs/wallet/.env.wallet}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$PROJECT_OUT/benchmarks/groth16_compare/artifacts}"
GROTH16_SOL_PATH="${GROTH16_SOL_PATH:-Groth16Verifier.sol}"
GROTH16_CONTRACT="${GROTH16_CONTRACT:-Groth16Verifier}"
GROTH16_SIG="${GROTH16_SIG:-auto}"

FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.foundry/bin}"
if [ -d "$FOUNDRY_BIN" ]; then
    export PATH="$FOUNDRY_BIN:$PATH"
fi

RPC_URL="${HOODI_RPC_URL:-}"
if [ -z "$RPC_URL" ]; then
    die_input "HOODI_RPC_URL not set"
fi

RPC_HOST="$(printf '%s' "$RPC_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"

if [ ! -f "$WALLET_ENV_FILE" ]; then
    die_input "$WALLET_ENV_FILE not found"
fi

# shellcheck disable=SC1090
source "$WALLET_ENV_FILE"

if [ -z "${DEPLOYER_ADDRESS:-}" ] || [ -z "${DEPLOYER_PRIVATE_KEY:-}" ]; then
    die_input "DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY not set in $WALLET_ENV_FILE"
fi

CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" | tr -d '\r\n')"
if [ "$CHAIN_ID" != "$HOODI_CHAIN_ID" ]; then
    die_input "rpc chain-id=$CHAIN_ID expected=$HOODI_CHAIN_ID"
fi

if [ ! -f "$ARTIFACT_DIR/calldata.txt" ]; then
    die_input "missing calldata.txt in $ARTIFACT_DIR"
fi

bench_setup_logs "$OUT_DIR/bench_groth16_hoodi.log"
bench_log_basic
bench_log_kv "rpc_host" "$RPC_HOST"
bench_log_kv "chain_id" "$CHAIN_ID"
bench_log_kv "deployer" "$DEPLOYER_ADDRESS"
bench_log_kv "out_json" "$OUT_JSON"
bench_log_kv "out_log" "$OUT_LOG"
echo ""

echo "Checking balance..."
BALANCE="$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")"
echo "balance_wei=${BALANCE}"
if [ "$BALANCE" = "0" ]; then
    echo ""
    die_runtime "No Hoodi ETH in wallet"
fi
echo ""

CONTRACT_ADDR=""
if [ -f "$DEPLOY_FILE" ] && [ -z "${FORCE_DEPLOY:-}" ]; then
    CONTRACT_ADDR="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("contract",""))' < "$DEPLOY_FILE" 2>/dev/null || true)"
    if [ -n "$CONTRACT_ADDR" ]; then
        CODE="$(cast code "$CONTRACT_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0x")"
        if [ "$CODE" = "0x" ]; then
            echo "WARN: deployment file present but no code at $CONTRACT_ADDR, redeploying"
            CONTRACT_ADDR=""
        else
            echo "Using existing deployment: $CONTRACT_ADDR"
            echo ""
        fi
    fi
fi

if [ -z "$CONTRACT_ADDR" ]; then
    echo "Deploying Groth16Verifier..."
    cd "$PROJECT_ROOT/scripts/tests/foundry"
    DEPLOY_JSON="$(forge create "$GROTH16_SOL_PATH:$GROTH16_CONTRACT" --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast --json)"
    CONTRACT_ADDR="$(printf '%s' "$DEPLOY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deployedTo",""))')"
    DEPLOY_TX="$(printf '%s' "$DEPLOY_JSON" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j.get("transactionHash") or j.get("deploymentTransactionHash") or "")')"
    cd "$PROJECT_ROOT"

    if [ -z "$CONTRACT_ADDR" ]; then
        echo "$DEPLOY_JSON"
        die_runtime "failed to deploy Groth16Verifier"
    fi

    DEPLOY_GAS="(unknown)"
    if [ -n "$DEPLOY_TX" ]; then
        DEPLOY_GAS="$(cast receipt "$DEPLOY_TX" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || echo "(unknown)")"
    fi

    cat > "$DEPLOY_FILE" <<EOF
{
  "network": "hoodi",
  "contract": "$CONTRACT_ADDR",
  "deploy_tx": "$DEPLOY_TX",
  "deploy_gas": "$DEPLOY_GAS",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

    echo "contract=${CONTRACT_ADDR}"
    echo "deploy_tx=${DEPLOY_TX:-"(unknown)"}"
    echo "deploy_gas=${DEPLOY_GAS}"
    echo ""
fi

mapfile -t CALLDATA_ARGS < <(python3 - "$ARTIFACT_DIR/calldata.txt" <<'PY'
import ast
import sys

def fmt(value):
    if isinstance(value, list):
        return "[" + ",".join(fmt(v) for v in value) + "]"
    return str(value)

raw = open(sys.argv[1], "r", encoding="utf-8").read().strip()
data = ast.literal_eval(f"[{raw}]")
for item in data:
    print(fmt(item))
PY
)

if [ "$GROTH16_SIG" = "auto" ]; then
    PUB_LEN="$(python3 - "$ARTIFACT_DIR/calldata.txt" <<'PY'
import ast
import sys

raw = open(sys.argv[1], "r", encoding="utf-8").read().strip()
items = ast.literal_eval(f"[{raw}]")
last = items[-1]
print(len(last))
PY
)"
    SIG="verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[$PUB_LEN])"
else
    SIG="$GROTH16_SIG"
fi
CALLDATA="$(cast calldata "$SIG" "${CALLDATA_ARGS[@]}")"

if ! cast call "$CONTRACT_ADDR" --data "$CALLDATA" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
    echo "ERROR: eth_call failed"
    exit 1
fi

PARAMS="[{\"from\":\"$DEPLOYER_ADDRESS\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"$CALLDATA\"}]"
GAS_HEX="$(cast rpc --rpc-url "$RPC_URL" eth_estimateGas --raw "$PARAMS" | tr -d '\" \n\r')"
CALLDATA_BYTES=$(( (${#CALLDATA} - 2) / 2 ))
gas_breakdown="$(python3 - <<'PY' "$CALLDATA" "$GAS_HEX"
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

printf "%-20s %8s %12s\\n" "case" "bytes" "estimate_gas"
printf "%-20s %8s %12s\\n" "--------------------" "--------" "------------"
printf "%-20s %8s %12s\\n" "groth16_verify" "$CALLDATA_BYTES" "$GAS_HEX"

SEND_TX="${SEND_TX:-0}"
TX_HASH=""
TX_GAS=""
if [ "$SEND_TX" = "1" ]; then
    echo ""
    echo "Sending on-chain transaction..."
    TX_JSON="$(cast send --json "$CONTRACT_ADDR" "$SIG" "${CALLDATA_ARGS[@]}" --private-key "$DEPLOYER_PRIVATE_KEY" --rpc-url "$RPC_URL")"
    TX_HASH="$(printf '%s' "$TX_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("transactionHash",""))')"
    if [ -n "$TX_HASH" ]; then
        TX_GAS="$(cast receipt "$TX_HASH" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || echo "")"
        echo "tx_hash=${TX_HASH}"
        echo "tx_gas=${TX_GAS:-"(unknown)"}"
    else
        echo "WARN: failed to parse tx hash"
    fi
fi

GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "$OUT_JSON" "$CONTRACT_ADDR" "$CHAIN_ID" "$RPC_HOST" "$GIT_COMMIT" "$TIMESTAMP" "$CALLDATA_BYTES" "$GAS_HEX" "$TX_HASH" "$TX_GAS" "$calldata_gas" "$base_tx_gas" "$execution_gas" <<'PY'
import json
import sys

out, contract, chain_id, rpc_host, git_commit, timestamp, calldata_bytes, gas_hex, tx_hash, tx_gas, calldata_gas, base_tx_gas, execution_gas = sys.argv[1:]
doc = {
    "bench": "bench_groth16_hoodi",
    "timestamp": timestamp,
    "git_commit": git_commit,
    "chain_id": chain_id,
    "rpc_host": rpc_host,
    "contract": contract,
    "case": {
        "name": "groth16_verify",
        "calldata_bytes": int(calldata_bytes),
        "estimate_gas": gas_hex,
        "calldata_gas": int(calldata_gas),
        "base_tx_gas": int(base_tx_gas),
        "execution_gas": int(execution_gas),
    },
}
if tx_hash:
    doc["case"]["tx_hash"] = tx_hash
if tx_gas:
    doc["case"]["tx_gas"] = tx_gas
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
