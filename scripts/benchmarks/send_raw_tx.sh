#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  RPC_URL=... PRIVATE_KEY=... TO=... DATA=... scripts/benchmarks/send_raw_tx.sh

Optional env:
  CHAIN_ID
  TIMEOUT (default: 120)
  POLL (default: 1.5)

Outputs:
  JSON line with from, to, tx_hash, gas_used, gas_limit, gas_price, nonce.

Exit codes:
  2 on missing env or missing tools.
  1 on runtime failure.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

require_cmd cast

RPC_URL="${RPC_URL:-}"
PRIVATE_KEY="${PRIVATE_KEY:-}"
TO_ADDR="${TO:-}"
DATA_HEX="${DATA:-}"
CHAIN_ID="${CHAIN_ID:-}"
TIMEOUT="${TIMEOUT:-0}"
POLL="${POLL:-1.5}"

if [ -z "$RPC_URL" ] || [ -z "$PRIVATE_KEY" ] || [ -z "$TO_ADDR" ] || [ -z "$DATA_HEX" ]; then
  echo "ERROR: Missing RPC_URL, PRIVATE_KEY, TO, or DATA env." >&2
  exit 2
fi

FROM_ADDR="$(cast wallet address --private-key "$PRIVATE_KEY" | tr -d '\r\n')"

gas_price_hex="$(cast rpc --rpc-url "$RPC_URL" eth_gasPrice | tr -d '\" \n\r')"
params="[{\"from\":\"$FROM_ADDR\",\"to\":\"$TO_ADDR\",\"data\":\"$DATA_HEX\"}]"
gas_limit_hex="$(cast rpc --rpc-url "$RPC_URL" eth_estimateGas --raw "$params" | tr -d '\" \n\r')"
nonce_hex="$(cast rpc --rpc-url "$RPC_URL" eth_getTransactionCount "$FROM_ADDR" latest | tr -d '\" \n\r')"
if [ -z "$CHAIN_ID" ]; then
  CHAIN_ID="$(cast rpc --rpc-url "$RPC_URL" eth_chainId | tr -d '\" \n\r')"
fi

hex_to_dec() {
  local hex="$1"
  if [[ "$hex" == 0x* ]]; then
    printf '%d' "$((16#${hex#0x}))"
  else
    printf '%d' "$hex"
  fi
}

gas_price_dec="$(hex_to_dec "$gas_price_hex")"
gas_limit_dec="$(hex_to_dec "$gas_limit_hex")"
nonce_dec="$(hex_to_dec "$nonce_hex")"
chain_id_dec="$(hex_to_dec "$CHAIN_ID")"

send_help="$(cast send --help 2>/dev/null || true)"
supports_flag() {
  local flag="$1"
  [[ "$send_help" == *"$flag"* ]]
}

send_args=(cast send --json --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" --data "$DATA_HEX" "$TO_ADDR")
if supports_flag "--nonce"; then
  send_args+=(--nonce "$nonce_dec")
fi
if supports_flag "--gas-limit"; then
  send_args+=(--gas-limit "$gas_limit_dec")
elif supports_flag "--gas"; then
  send_args+=(--gas "$gas_limit_dec")
fi
if supports_flag "--gas-price"; then
  send_args+=(--gas-price "$gas_price_dec")
fi
if supports_flag "--chain-id"; then
  send_args+=(--chain-id "$chain_id_dec")
elif supports_flag "--chain"; then
  send_args+=(--chain "$chain_id_dec")
fi
if supports_flag "--legacy"; then
  send_args+=(--legacy)
fi

tx_json="$("${send_args[@]}")"
tx_hash="$(printf '%s' "$tx_json" | tr -d '\r\n' | sed -n 's/.*"transactionHash"[[:space:]]*:[[:space:]]*"\(0x[0-9a-fA-F]\+\)".*/\1/p')"
if [ -z "$tx_hash" ]; then
  tx_hash="$(printf '%s' "$tx_json" | tr -d '\r\n' | sed -n 's/.*"hash"[[:space:]]*:[[:space:]]*"\(0x[0-9a-fA-F]\+\)".*/\1/p')"
fi
if [ -z "$tx_hash" ]; then
  echo "ERROR: Failed to parse tx hash from cast output." >&2
  exit 1
fi

started="$(date +%s)"
gas_used=""
while true; do
  if [ "$(( $(date +%s) - started ))" -ge "$TIMEOUT" ]; then
    echo "ERROR: Timed out waiting for receipt." >&2
    exit 1
  fi
  gas_used="$(cast receipt "$tx_hash" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || true)"
  if [ -n "$gas_used" ]; then
    break
  fi
  sleep "$POLL"
done

gas_used_dec="$(hex_to_dec "$gas_used")"

printf '{"from":"%s","to":"%s","tx_hash":"%s","gas_used":%s,"gas_limit":%s,"gas_price":%s,"nonce":%s}\n' \
  "$FROM_ADDR" "$TO_ADDR" "$tx_hash" "$gas_used_dec" "$gas_limit_dec" "$gas_price_dec" "$nonce_dec"
