#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_PAYLOAD_PATH=... BLOB_RPC_URL=... BLOB_PRIVATE_KEY=... scripts/da/submit_blob.sh

Required env:
  DA_PAYLOAD_PATH
  BLOB_RPC_URL or RPC_URL
  BLOB_PRIVATE_KEY or PRIVATE_KEY

Optional env:
  BLOB_TO (default: 0x00..00)
  BLOB_TX_TIMEOUT_SECS (default: 180)
  BLOB_TX_POLL_SECS (default: 2)
  BLOB_TX_NONCE
  BLOB_TX_BUMP_FACTOR (default: 1.2)
  BLOB_TX_PRIORITY_GAS_PRICE
  BLOB_TX_GAS_PRICE
  BLOB_TX_BLOB_GAS_PRICE

Outputs:
  JSON with provider, tx_hash, versioned_hashes, chain_id.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

PROJECT_ROOT="${DA_PROJECT_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
PAYLOAD_PATH="${DA_PAYLOAD_PATH:-}"
RPC_URL="${BLOB_RPC_URL:-${RPC_URL:-}}"
PRIVATE_KEY="${BLOB_PRIVATE_KEY:-${PRIVATE_KEY:-}}"
BLOB_TO="${BLOB_TO:-0x0000000000000000000000000000000000000000}"
BLOB_TX_TIMEOUT_SECS="${BLOB_TX_TIMEOUT_SECS:-180}"
BLOB_TX_POLL_SECS="${BLOB_TX_POLL_SECS:-2}"
BLOB_TX_NONCE="${BLOB_TX_NONCE:-}"
BLOB_TX_BUMP_FACTOR="${BLOB_TX_BUMP_FACTOR:-1.2}"
BLOB_TX_PRIORITY_GAS_PRICE="${BLOB_TX_PRIORITY_GAS_PRICE:-2000000000}"
BLOB_TX_GAS_PRICE="${BLOB_TX_GAS_PRICE:-}"
BLOB_TX_BLOB_GAS_PRICE="${BLOB_TX_BLOB_GAS_PRICE:-}"

if [ -z "$PAYLOAD_PATH" ]; then
    echo "ERROR: DA_PAYLOAD_PATH not set" >&2
    exit 2
fi
if [ ! -f "$PAYLOAD_PATH" ]; then
    echo "ERROR: DA_PAYLOAD_PATH not found: $PAYLOAD_PATH" >&2
    exit 2
fi
if [ -z "$RPC_URL" ]; then
    echo "ERROR: BLOB_RPC_URL or RPC_URL not set" >&2
    exit 2
fi
if [ -z "$PRIVATE_KEY" ]; then
    echo "ERROR: BLOB_PRIVATE_KEY or PRIVATE_KEY not set" >&2
    exit 2
fi

require_cmd cast
require_cmd python3

FROM_ADDR="$(cast wallet address --private-key "$PRIVATE_KEY" | tr -d '\r\n')"
if [ -z "$FROM_ADDR" ]; then
    echo "ERROR: failed to derive sender address" >&2
    exit 2
fi

if [ -z "$BLOB_TX_NONCE" ]; then
    NONCE_RAW="$(cast rpc --rpc-url "$RPC_URL" eth_getTransactionCount "$FROM_ADDR" pending 2>/dev/null || true)"
    BLOB_TX_NONCE="$(printf '%s' "$NONCE_RAW" | python3 - <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if raw.startswith("{"):
    data = json.loads(raw)
    raw = data.get("result", "")
raw = raw.strip().strip('"')

try:
    if raw.startswith("0x"):
        print(int(raw, 16))
    else:
        print(int(raw))
except Exception:
    print("")
PY
)"
fi

if [ -z "$BLOB_TX_NONCE" ]; then
    BLOB_TX_NONCE="$(cast nonce --rpc-url "$RPC_URL" "$FROM_ADDR" 2>/dev/null | tr -d '\r\n' || true)"
fi

SEND_ARGS=(cast send --async --blob --path "$PAYLOAD_PATH" --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY")
if [ -n "$BLOB_TX_NONCE" ]; then
    SEND_ARGS+=(--nonce "$BLOB_TX_NONCE")
fi
BASE_ARGS=("${SEND_ARGS[@]}")

if [ -z "$BLOB_TX_GAS_PRICE" ]; then
    GAS_PRICE_RAW="$(cast rpc --rpc-url "$RPC_URL" eth_gasPrice 2>/dev/null || echo "")"
    BLOB_TX_GAS_PRICE="$(python3 - "$GAS_PRICE_RAW" "$BLOB_TX_BUMP_FACTOR" <<'PY'
import sys
raw = sys.argv[1].strip().strip('"')
factor = float(sys.argv[2])
if raw.startswith("0x"):
    val = int(raw, 16)
else:
    val = int(raw or "0")
if val <= 0:
    val = 1
print(int(val * factor))
PY
)"
fi
if [ -z "$BLOB_TX_BLOB_GAS_PRICE" ]; then
    BLOB_BASE_RAW="$(cast rpc --rpc-url "$RPC_URL" eth_blobBaseFee 2>/dev/null || echo "")"
    BLOB_TX_BLOB_GAS_PRICE="$(python3 - "$BLOB_BASE_RAW" "$BLOB_TX_BUMP_FACTOR" <<'PY'
import sys
raw = sys.argv[1].strip().strip('"')
factor = float(sys.argv[2])
if raw.startswith("0x"):
    val = int(raw, 16)
else:
    val = int(raw or "0")
if val <= 0:
    val = 1
print(int(val * factor))
PY
)"
fi

if [ -n "$BLOB_TX_GAS_PRICE" ]; then
    SAFE_PRIORITY_GAS_PRICE="$(python3 - "$BLOB_TX_GAS_PRICE" "$BLOB_TX_PRIORITY_GAS_PRICE" <<'PY'
import sys
max_fee = int(sys.argv[1])
prio = int(sys.argv[2])
if max_fee <= 1:
    print(1)
else:
    print(min(prio, max_fee - 1))
PY
)"
    SEND_ARGS+=(--gas-price "$BLOB_TX_GAS_PRICE" --priority-gas-price "$SAFE_PRIORITY_GAS_PRICE")
fi
if [ -n "$BLOB_TX_BLOB_GAS_PRICE" ]; then
    SEND_ARGS+=(--blob-gas-price "$BLOB_TX_BLOB_GAS_PRICE")
fi

SEND_ARGS+=("$BLOB_TO" --json)

if ! TX_JSON="$("${SEND_ARGS[@]}" 2>&1)"; then
    if printf '%s' "$TX_JSON" | grep -Eqi "replacement transaction underpriced|max fee per gas less than block base fee|fee cap too low"; then
        GAS_PRICE_RAW="$(cast rpc --rpc-url "$RPC_URL" eth_gasPrice 2>/dev/null || echo "")"
        BLOB_BASE_RAW="$(cast rpc --rpc-url "$RPC_URL" eth_blobBaseFee 2>/dev/null || echo "")"
        BUMPED_GAS_PRICE="$(python3 - "$GAS_PRICE_RAW" "$BLOB_TX_BUMP_FACTOR" <<'PY'
import sys
raw = sys.argv[1].strip().strip('"')
factor = float(sys.argv[2])
if raw.startswith("0x"):
    val = int(raw, 16)
else:
    val = int(raw or "0")
if val <= 0:
    val = 1
print(int(val * factor))
PY
)"
        SAFE_PRIORITY_GAS_PRICE="$(python3 - "$BUMPED_GAS_PRICE" "$BLOB_TX_PRIORITY_GAS_PRICE" <<'PY'
import sys
max_fee = int(sys.argv[1])
prio = int(sys.argv[2])
if max_fee <= 1:
    print(1)
else:
    print(min(prio, max_fee - 1))
PY
)"
        BUMPED_BLOB_GAS_PRICE="$(python3 - "$BLOB_BASE_RAW" "$BLOB_TX_BUMP_FACTOR" <<'PY'
import sys
raw = sys.argv[1].strip().strip('"')
factor = float(sys.argv[2])
if raw.startswith("0x"):
    val = int(raw, 16)
else:
    val = int(raw or "0")
if val <= 0:
    val = 1
print(int(val * factor))
PY
)"
        RETRY_ARGS=("${BASE_ARGS[@]}")
        RETRY_ARGS+=(--gas-price "$BUMPED_GAS_PRICE" --priority-gas-price "$SAFE_PRIORITY_GAS_PRICE" --blob-gas-price "$BUMPED_BLOB_GAS_PRICE")
        RETRY_ARGS+=("$BLOB_TO" --json)
        if ! TX_JSON="$("${RETRY_ARGS[@]}" 2>&1)"; then
            echo "ERROR: cast send failed after fee bump: $TX_JSON" >&2
            exit 1
        fi
    else
        echo "ERROR: cast send failed: $TX_JSON" >&2
        exit 1
    fi
fi
TX_HASH="$(printf '%s' "$TX_JSON" | python3 - <<'PY'
import json
import sys

raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start != -1 and end != -1 and end > start:
    data = json.loads(raw[start:end + 1])
    print(data.get("transactionHash", ""))
PY
)"
if [ -z "$TX_HASH" ]; then
    TX_HASH="$(printf '%s' "$TX_JSON" | grep -Eo '0x[0-9a-fA-F]{64}' | head -n 1 || true)"
fi
if [ -z "$TX_HASH" ]; then
    echo "ERROR: failed to parse transaction hash" >&2
    exit 1
fi

echo "blob_tx_hash=$TX_HASH" >&2

python3 - "$TX_HASH" "$RPC_URL" "$BLOB_TX_TIMEOUT_SECS" "$BLOB_TX_POLL_SECS" <<'PY'
import json
import subprocess
import sys
import time

tx_hash = sys.argv[1]
rpc_url = sys.argv[2]
timeout = int(sys.argv[3])
poll = float(sys.argv[4])

start = time.time()
while True:
    out = subprocess.check_output(
        ["cast", "rpc", "--rpc-url", rpc_url, "eth_getTransactionReceipt", tx_hash],
        stderr=subprocess.DEVNULL,
    )
    data = json.loads(out)
    if isinstance(data, dict):
        result = data.get("result", data)
        if isinstance(result, dict) and result.get("transactionHash"):
            sys.exit(0)
    if data is None:
        pass
    if time.time() - start > timeout:
        raise SystemExit("timeout waiting for receipt")
    time.sleep(poll)
PY

VERSIONED_HASHES="$(python3 - "$TX_HASH" "$RPC_URL" "$BLOB_TX_TIMEOUT_SECS" "$BLOB_TX_POLL_SECS" <<'PY'
import json
import sys
import time
import urllib.request
import urllib.error

tx_hash = sys.argv[1]
rpc_url = sys.argv[2]
timeout = int(sys.argv[3])
poll = float(sys.argv[4])

def rpc_call(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit(f"rpc http error: {e.code} {e.reason}: {body}")
    except urllib.error.URLError as e:
        raise SystemExit(f"rpc url error: {e.reason}")
    if "error" in data and data["error"]:
        raise SystemExit(f"rpc error: {data['error']}")
    return data.get("result")

start = time.time()
while True:
    result = rpc_call("eth_getTransactionByHash", [tx_hash])
    if isinstance(result, dict):
        hashes = result.get("blobVersionedHashes") or []
        if hashes:
            print(json.dumps(hashes))
            sys.exit(0)
    if time.time() - start > timeout:
        print("[]")
        sys.exit(0)
    time.sleep(poll)
PY
)"
CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" | tr -d '\r\n')"

python3 - "$TX_HASH" "$VERSIONED_HASHES" "$CHAIN_ID" <<'PY'
import json
import sys

tx_hash = sys.argv[1]
versioned = json.loads(sys.argv[2])
chain_id = int(sys.argv[3]) if sys.argv[3].isdigit() else None

if not tx_hash or not versioned:
    raise SystemExit("blob receipt missing versioned hashes")

out = {
    "provider": "blob",
    "tx_hash": tx_hash,
    "versioned_hashes": versioned,
    "chain_id": chain_id,
}
print(json.dumps(out))
PY
