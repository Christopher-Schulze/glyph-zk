#!/bin/bash
# Bench GLYPHVerifier gas on Hoodi (truncated layout).
# Measures full transaction gas via eth_estimateGas for truncated layout only.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_hoodi_artifact_truncated.sh

Optional env:
  TIMEOUT
  RPC_URL
  HOODI_RPC_URL
  HOODI_CHAIN_ID
  DEPLOY_FILE
  WALLET_ENV_FILE
  FOUNDRY_BIN
  CAST_BIN
  SEND_TX
  ROUNDS
  COMMITMENT
  POINT
  CLAIM
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
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_glyph_hoodi_artifact_truncated.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_hoodi_artifact_truncated"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd python3
require_cmd cargo

HOODI_CHAIN_ID="${HOODI_CHAIN_ID:-560048}"
DEPLOY_FILE="${DEPLOY_FILE:-$PROJECT_ROOT/deployments/hoodi.json}"
WALLET_ENV_FILE="${WALLET_ENV_FILE:-$PROJECT_ROOT/docs/wallet/.env.wallet}"

RPC_URL="${RPC_URL:-${HOODI_RPC_URL:-}}"
if [ -z "$RPC_URL" ]; then
    die_input "RPC_URL or HOODI_RPC_URL must be set"
fi

# Ensure Foundry binaries are discoverable in non-interactive shells.
FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.foundry/bin}"
if [ -d "$FOUNDRY_BIN" ]; then
    export PATH="$FOUNDRY_BIN:$PATH"
fi
if [ -n "${CAST_BIN:-}" ]; then
    if [ ! -x "$CAST_BIN" ]; then
        die_input "cast not found at $CAST_BIN"
    fi
else
    if [ -x "$FOUNDRY_BIN/cast" ]; then
        CAST_BIN="$FOUNDRY_BIN/cast"
    elif command -v cast >/dev/null 2>&1; then
        CAST_BIN="$(command -v cast)"
    else
        die_input "cast not found in PATH"
    fi
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

CHAIN_ID="$("$CAST_BIN" chain-id --rpc-url "$RPC_URL" | tr -d '\\r\\n')"
if [ "$CHAIN_ID" != "$HOODI_CHAIN_ID" ]; then
    die_input "rpc chain-id=$CHAIN_ID expected=$HOODI_CHAIN_ID"
fi

ROUNDS="${ROUNDS:-5}"
COMMITMENT="${COMMITMENT:-0x1111111111111111111111111111111111111111111111111111111111111111}"
POINT="${POINT:-0x2222222222222222222222222222222222222222222222222222222222222222}"
CLAIM="${CLAIM:-0x000000000000000000000000000000000000000000000000000000000000007b}"
SEND_TX="${SEND_TX:-0}"

RESULTS_TMP="$(mktemp)"
cleanup_tmp() {
    if [ -n "${RESULTS_TMP:-}" ] && [ -f "$RESULTS_TMP" ]; then
        rm -f "$RESULTS_TMP"
    fi
}
trap cleanup_tmp EXIT

bench_setup_logs "$OUT_DIR/bench_glyph_hoodi_artifact_truncated.log"
bench_log_basic
bench_log_kv "rpc_host" "$RPC_HOST"
bench_log_kv "chain_id" "$CHAIN_ID"
bench_log_kv "deployer" "$DEPLOYER_ADDRESS"
bench_log_kv "rounds" "$ROUNDS"
bench_log_kv "commitment" "$COMMITMENT"
bench_log_kv "point" "$POINT"
bench_log_kv "claim" "$CLAIM"
bench_log_kv "out_json" "$OUT_JSON"
bench_log_kv "out_log" "$OUT_LOG"
echo ""

echo "Checking balance..."
BALANCE="$("$CAST_BIN" balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")"
echo "balance_wei=${BALANCE}"
if [ "$BALANCE" = "0" ]; then
    echo ""
    die_runtime "No Hoodi ETH in wallet. Send Hoodi ETH to: $DEPLOYER_ADDRESS"
fi
echo ""

echo "Building gen_glyph_gkr_proof..."
cd "$PROJECT_ROOT"
cargo build --release --bin gen_glyph_gkr_proof >/dev/null
echo ""

RAW_TX_BIN="$PROJECT_ROOT/target/release/glyph_raw_tx"
GAS_PRICE=""
NEXT_NONCE=""
if [ "$SEND_TX" = "1" ]; then
    echo "Building glyph_raw_tx..."
    cargo build --release --bin glyph_raw_tx >/dev/null
fi

CONTRACT_ADDR=""
if [ -f "$DEPLOY_FILE" ]; then
    if command -v jq >/dev/null 2>&1; then
        CONTRACT_ADDR="$(jq -r '.contract // empty' "$DEPLOY_FILE" 2>/dev/null || true)"
    else
        CONTRACT_ADDR="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("contract",""))' < "$DEPLOY_FILE" 2>/dev/null || true)"
    fi
    if [ -n "$CONTRACT_ADDR" ]; then
        CODE="$("$CAST_BIN" code "$CONTRACT_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0x")"
        if [ "$CODE" = "0x" ]; then
            echo "WARN: deployment file present but no code at $CONTRACT_ADDR"
            CONTRACT_ADDR=""
        else
            echo "Using existing deployment: $CONTRACT_ADDR"
            echo ""
        fi
    fi
fi

if [ -z "$CONTRACT_ADDR" ]; then
    die_input "truncated verifier not deployed; set DEPLOY_FILE or deploy first"
fi

if [ "$SEND_TX" = "1" ]; then
    GAS_PRICE="$("$CAST_BIN" gas-price --rpc-url "$RPC_URL" | tr -d '\r\n')"
    NEXT_NONCE="$("$CAST_BIN" nonce "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" | tr -d '\r\n')"
    echo "raw_tx_gas_price=${GAS_PRICE}"
    echo "raw_tx_nonce_base=${NEXT_NONCE}"
    echo ""
fi


bench_case() {
    local name="$1"
    shift

    local out
    out="$(target/release/gen_glyph_gkr_proof --artifact-poly --commitment "$COMMITMENT" --point "$POINT" --claim "$CLAIM" --rounds "$ROUNDS" --chainid "$HOODI_CHAIN_ID" --verifier "$CONTRACT_ADDR" "$@" --json)"
    local calldata
    calldata="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata"])')"
    local calldata_len
    calldata_len="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["calldata_len"])')"

    if ! "$CAST_BIN" call "$CONTRACT_ADDR" --data "$calldata" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
        echo "ERROR: eth_call failed for case=${name}"
        return 1
    fi

    local gas_hex
    local params
    params="[{\"from\":\"$DEPLOYER_ADDRESS\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"$calldata\"}]"
    gas_hex="$("$CAST_BIN" rpc --rpc-url "$RPC_URL" eth_estimateGas --raw "$params" | tr -d '\" \\n\\r')"

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

    local tx_hash=""
    local tx_gas=""
    if [ "$SEND_TX" = "1" ]; then
        local gas_limit
        gas_limit="$(python3 - <<'PY' "$gas_hex"
import sys
gas_used = int(sys.argv[1], 0) if sys.argv[1].startswith("0x") else int(sys.argv[1])
print(int(gas_used * 12 / 10) + 5000)
PY
)"
        local raw_json
        raw_json="$("$RAW_TX_BIN" --to "$CONTRACT_ADDR" --data "$calldata" --chain-id "$CHAIN_ID" --nonce "$NEXT_NONCE" --gas-price "$GAS_PRICE" --gas-limit "$gas_limit" --value 0 --private-key "$DEPLOYER_PRIVATE_KEY" --json)"
        local raw_tx
        raw_tx="$(printf '%s' "$raw_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["raw_tx"])')"
        local local_hash
        local_hash="$(printf '%s' "$raw_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tx_hash"])')"
        local publish_out
        publish_out="$("$CAST_BIN" publish --rpc-url "$RPC_URL" "$raw_tx" | tr -d '\r\n')"
        tx_hash="$(python3 - <<'PY' "$publish_out" "$local_hash"
import json
import sys

raw = sys.argv[1].strip()
fallback = sys.argv[2].strip()
if raw.startswith("{") and raw.endswith("}"):
    try:
        obj = json.loads(raw)
        val = obj.get("transactionHash") or obj.get("txHash") or obj.get("hash") or ""
        if val:
            print(val)
            raise SystemExit(0)
    except Exception:
        pass
if raw.startswith("0x") and len(raw) >= 66:
    print(raw)
elif fallback:
    print(fallback)
PY
)"
        if [ -n "$tx_hash" ]; then
            tx_gas="$("$CAST_BIN" receipt "$tx_hash" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || echo "")"
        fi
        NEXT_NONCE=$((NEXT_NONCE + 1))
    fi

    printf "%-26s %8s %12s\\n" "$name" "$calldata_len" "$gas_hex"
    python3 - "$RESULTS_TMP" "$name" "$calldata_len" "$gas_hex" "$calldata_gas" "$base_tx_gas" "$execution_gas" "$tx_hash" "$tx_gas" <<'PY'
import json
import sys

out, name, calldata_len, gas_hex, calldata_gas, base_tx_gas, execution_gas, tx_hash, tx_gas = sys.argv[1:]
doc = {
    "case": name,
    "calldata_bytes": int(calldata_len),
    "estimate_gas": gas_hex,
    "calldata_gas": int(calldata_gas),
    "base_tx_gas": int(base_tx_gas),
    "execution_gas": int(execution_gas),
}
if tx_hash:
    doc["tx_hash"] = tx_hash
if tx_gas:
    try:
        doc["tx_gas"] = int(tx_gas)
    except ValueError:
        doc["tx_gas"] = tx_gas
with open(out, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(doc) + "\n")
PY
}

printf "%-26s %8s %12s\\n" "case" "bytes" "estimate_gas"
printf "%-26s %8s %12s\\n" "--------------------------" "--------" "------------"

bench_case "artifact_truncated_only"

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
    "bench": "bench_glyph_hoodi_artifact_truncated",
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
