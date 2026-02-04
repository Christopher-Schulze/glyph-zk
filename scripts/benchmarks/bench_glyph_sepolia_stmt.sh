#!/bin/bash
# Bench GLYPHVerifier gas on Ethereum Sepolia with artifact-poly layout.
# Measures full transaction gas via eth_estimateGas for full and truncated layouts.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_sepolia_stmt.sh

Required env:
  SEPOLIA_RPC_URL

Optional env:
  TIMEOUT
  SEPOLIA_CHAIN_ID
  DEPLOY_FILE
  WALLET_ENV_FILE
  FORCE_DEPLOY
  ROUNDS
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
if command -v stty >/dev/null 2>&1; then
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
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_glyph_sepolia_stmt.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_sepolia_stmt"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd cast
require_cmd forge
require_cmd jq
require_cmd python3
require_cmd cargo

SEPOLIA_CHAIN_ID="${SEPOLIA_CHAIN_ID:-11155111}"
DEPLOY_FILE="${DEPLOY_FILE:-$PROJECT_ROOT/deployments/sepolia.json}"
WALLET_ENV_FILE="${WALLET_ENV_FILE:-$PROJECT_ROOT/docs/wallet/.env.wallet}"

RPC_URL="${SEPOLIA_RPC_URL:-}"
if [ -z "$RPC_URL" ]; then
    die_input "SEPOLIA_RPC_URL not set"
fi

RPC_HOST="$(printf '%s' "$RPC_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"

if [ ! -f "$WALLET_ENV_FILE" ]; then
    die_input "$WALLET_ENV_FILE not found. Create docs/wallet/.env.wallet and fill in deployer credentials."
fi

# shellcheck disable=SC1090
source "$WALLET_ENV_FILE"

if [ -z "${DEPLOYER_ADDRESS:-}" ] || [ -z "${DEPLOYER_PRIVATE_KEY:-}" ]; then
    die_input "DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY not set in $WALLET_ENV_FILE"
fi

CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" | tr -d '\\r\\n')"
if [ "$CHAIN_ID" != "$SEPOLIA_CHAIN_ID" ]; then
    die_input "rpc chain-id=$CHAIN_ID expected=$SEPOLIA_CHAIN_ID"
fi

ROUNDS="${ROUNDS:-5}"

RESULTS_TMP="$(mktemp)"
cleanup_tmp() {
    if [ -n "${RESULTS_TMP:-}" ] && [ -f "$RESULTS_TMP" ]; then
        rm -f "$RESULTS_TMP"
    fi
}
trap cleanup_tmp EXIT

bench_setup_logs "$OUT_DIR/bench_glyph_sepolia_stmt.log"
bench_log_basic
bench_log_kv "rpc_host" "$RPC_HOST"
bench_log_kv "chain_id" "$CHAIN_ID"
bench_log_kv "deployer" "$DEPLOYER_ADDRESS"
bench_log_kv "rounds" "$ROUNDS"
bench_log_kv "out_json" "$OUT_JSON"
bench_log_kv "out_log" "$OUT_LOG"
echo ""

echo "Checking balance..."
BALANCE="$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")"
echo "balance_wei=${BALANCE}"
if [ "$BALANCE" = "0" ]; then
    echo ""
    echo "ERROR: No Sepolia ETH in wallet!"
    echo "Send Sepolia ETH to: $DEPLOYER_ADDRESS"
    exit 1
fi
echo ""

echo "Building gen_glyph_gkr_proof..."
cd "$PROJECT_ROOT"
cargo build --release --bin gen_glyph_gkr_proof >/dev/null
echo ""

CONTRACT_ADDR=""
if [ -f "$DEPLOY_FILE" ] && [ -z "${FORCE_DEPLOY:-}" ]; then
    CONTRACT_ADDR="$(jq -r '.contract // empty' "$DEPLOY_FILE" 2>/dev/null || true)"
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
    echo "Deploying GLYPHVerifier..."
    cd "$PROJECT_ROOT/scripts/tests/foundry"
    DEPLOY_JSON="$(forge create ../../../contracts/GLYPHVerifier.sol:GLYPHVerifier --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PRIVATE_KEY" --broadcast --json)"
    CONTRACT_ADDR="$(printf '%s' "$DEPLOY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deployedTo", ""))')"
    DEPLOY_TX="$(printf '%s' "$DEPLOY_JSON" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j.get("transactionHash") or j.get("deploymentTransactionHash") or "")')"
    cd "$PROJECT_ROOT"

    if [ -z "$CONTRACT_ADDR" ]; then
        echo "ERROR: failed to deploy GLYPHVerifier via forge create"
        echo "$DEPLOY_JSON"
        exit 1
    fi

    DEPLOY_GAS="(unknown)"
    if [ -n "$DEPLOY_TX" ]; then
        DEPLOY_GAS="$(cast receipt "$DEPLOY_TX" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || echo "(unknown)")"
    fi
    BYTECODE="$(cast code "$CONTRACT_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0x")"
    CODE_LEN=0
    if [ -n "$BYTECODE" ] && [ "$BYTECODE" != "0x" ]; then
        CODE_LEN=$(( (${#BYTECODE} - 2) / 2 ))
    fi

    echo "contract=${CONTRACT_ADDR}"
    echo "deploy_tx=${DEPLOY_TX:-"(unknown)"}"
    echo "deploy_gas=${DEPLOY_GAS}"
    echo ""

    DEPLOY_OUT="$DEPLOY_FILE"
    if [ -f "$DEPLOY_OUT" ]; then
        TS="$(date -u +%Y%m%dT%H%M%SZ)"
        DEPLOY_OUT="${DEPLOY_FILE%.json}_${TS}.json"
    fi

    cat > "$DEPLOY_OUT" <<EOF
{
  "network": "sepolia",
  "chain_id": "$CHAIN_ID",
  "rpc_host": "$RPC_HOST",
  "deployer": "$DEPLOYER_ADDRESS",
  "contract": "$CONTRACT_ADDR",
  "deploy_tx": "$DEPLOY_TX",
  "deploy_gas": "$DEPLOY_GAS",
  "code_bytes": $CODE_LEN,
  "verify_result": "skipped",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    echo "deployment_file=$(basename "$DEPLOY_OUT")"
    echo ""
fi


bench_case() {
    local name="$1"
    shift

    local out
    out="$(target/release/gen_glyph_gkr_proof --hash-merge --rounds "$ROUNDS" --chainid "$SEPOLIA_CHAIN_ID" --verifier "$CONTRACT_ADDR" "$@" --json)"
    local calldata
    calldata="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata"])')"
    local calldata_len
    calldata_len="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata_len"])')"

    if ! cast call "$CONTRACT_ADDR" --data "$calldata" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
        echo "ERROR: eth_call failed for case=${name}"
        return 1
    fi

    local gas_hex
    local params
    params="[{\"from\":\"$DEPLOYER_ADDRESS\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"$calldata\"}]"
    gas_hex="$(cast rpc --rpc-url "$RPC_URL" eth_estimateGas --raw "$params" | tr -d '\" \\n\\r')"

    local gas_breakdown
    gas_breakdown="$(python3 - <<'PY' "$calldata" "$gas_hex"
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
    printf "%-26s %8s %12s\\n" "$name" "$calldata_len" "$gas_hex"
    printf '{"case":"%s","calldata_bytes":%s,"estimate_gas":"%s","calldata_gas":%s,"base_tx_gas":%s,"execution_gas":%s}\n' "$name" "$calldata_len" "$gas_hex" "$calldata_gas" "$base_tx_gas" "$execution_gas" >> "$RESULTS_TMP"
}

printf "%-26s %8s %12s\\n" "case" "bytes" "estimate_gas"
printf "%-26s %8s %12s\\n" "--------------------------" "--------" "------------"

bench_case "artifact_full"
bench_case "artifact_truncated" --truncated

echo ""
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$RESULTS_TMP" "$OUT_JSON" "$CONTRACT_ADDR" "$CHAIN_ID" "$RPC_HOST" "$GIT_COMMIT" "$TIMESTAMP" <<'PY'
import json
import sys

tmp, out, contract, chain_id, rpc_host, git_commit, timestamp = sys.argv[1:]
cases = []
with open(tmp, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        cases.append(json.loads(line))

doc = {
    "bench": "bench_glyph_sepolia_stmt",
    "timestamp": timestamp,
    "git_commit": git_commit,
    "chain_id": chain_id,
    "rpc_host": rpc_host,
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
