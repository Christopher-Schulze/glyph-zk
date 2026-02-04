#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_ENVELOPE_PATH=... DA_OUTPUT_PATH=... scripts/da/fetch_blob.sh

Required env:
  DA_ENVELOPE_PATH
  DA_OUTPUT_PATH
  BLOB_RETRIEVER_URL_TEMPLATE or BLOB_BEACON_API_URL

Optional env:
  BLOB_RPC_URL or RPC_URL

Outputs:
  Writes payload to DA_OUTPUT_PATH and prints JSON with provider and payload_path.

Exit codes:
  2 on invalid input or missing tools.
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

ENVELOPE_PATH="${DA_ENVELOPE_PATH:-}"
OUTPUT_PATH="${DA_OUTPUT_PATH:-}"
TEMPLATE="${BLOB_RETRIEVER_URL_TEMPLATE:-}"
BEACON_URL="${BLOB_BEACON_API_URL:-}"
RPC_URL="${BLOB_RPC_URL:-${RPC_URL:-}}"

if [ -z "$ENVELOPE_PATH" ]; then
    echo "ERROR: DA_ENVELOPE_PATH not set" >&2
    exit 2
fi
if [ ! -f "$ENVELOPE_PATH" ]; then
    echo "ERROR: DA_ENVELOPE_PATH not found: $ENVELOPE_PATH" >&2
    exit 2
fi
if [ -z "$OUTPUT_PATH" ]; then
    echo "ERROR: DA_OUTPUT_PATH not set" >&2
    exit 2
fi
if [ -z "$TEMPLATE" ] && [ -z "$BEACON_URL" ]; then
    echo "ERROR: set BLOB_RETRIEVER_URL_TEMPLATE or BLOB_BEACON_API_URL" >&2
    exit 2
fi

require_cmd python3
mkdir -p "$(dirname "$OUTPUT_PATH")"

VERSIONED_HASH="$(python3 - "$ENVELOPE_PATH" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") == "blob":
        hashes = item.get("versioned_hashes") or []
        if hashes:
            print(hashes[0])
            raise SystemExit(0)
print("")
PY
)"

if [ -z "$VERSIONED_HASH" ]; then
    echo "ERROR: blob commitment not found in envelope" >&2
    exit 2
fi

if [ -n "$TEMPLATE" ]; then
    require_cmd curl
    URL="${TEMPLATE//%s/$VERSIONED_HASH}"
    TMP_PATH="${OUTPUT_PATH}.tmp"
    curl -sSL "$URL" -o "$TMP_PATH"

    python3 - "$TMP_PATH" "$OUTPUT_PATH" <<'PY'
import json
import os
import sys

src = sys.argv[1]
dst = sys.argv[2]

with open(src, "rb") as f:
    raw = f.read()

def write_raw(data: bytes) -> None:
    with open(dst, "wb") as out:
        out.write(data)

try:
    text = raw.decode("utf-8")
    data = json.loads(text)
except Exception:
    write_raw(raw)
    sys.exit(0)

blob = data.get("blob") if isinstance(data, dict) else None
hex_data = None
if isinstance(blob, dict):
    hex_data = blob.get("data") or blob.get("blob") or blob.get("payload")
if hex_data is None and isinstance(data, dict):
    hex_data = data.get("data") or data.get("blob_data") or data.get("payload")

if not isinstance(hex_data, str):
    raise SystemExit("blob fetch response missing data field")

hex_data = hex_data.strip()
if hex_data.startswith("0x"):
    hex_data = hex_data[2:]

try:
    decoded = bytes.fromhex(hex_data)
except ValueError as err:
    raise SystemExit(f"invalid hex blob data: {err}")

write_raw(decoded)
PY

    rm -f "$TMP_PATH"
else
    if [ -z "$RPC_URL" ]; then
        echo "ERROR: BLOB_RPC_URL or RPC_URL not set for beacon fetch" >&2
        exit 2
    fi
    python3 - "$ENVELOPE_PATH" "$OUTPUT_PATH" "$BEACON_URL" "$RPC_URL" "$VERSIONED_HASH" <<'PY'
import hashlib
import json
import sys
import urllib.error
import urllib.request

envelope_path = sys.argv[1]
output_path = sys.argv[2]
beacon_url = sys.argv[3].rstrip("/")
rpc_url = sys.argv[4]
target_hash = sys.argv[5].lower()

env = json.load(open(envelope_path, "r", encoding="utf-8"))
tx_hash = None
for item in env.get("commitments", []):
    if item.get("provider") == "blob":
        tx_hash = item.get("tx_hash")
        break
if not tx_hash:
    raise SystemExit("blob commitment missing tx_hash in envelope")

def rpc_call(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(rpc_url, data=payload, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.load(resp)
    if "error" in data and data["error"]:
        raise SystemExit(f"rpc error: {data['error']}")
    return data.get("result")

receipt = rpc_call("eth_getTransactionReceipt", [tx_hash])
if not receipt or not receipt.get("blockHash"):
    raise SystemExit("receipt missing blockHash")

block = rpc_call("eth_getBlockByHash", [receipt["blockHash"], False])
if not block or not block.get("timestamp"):
    raise SystemExit("block missing timestamp")

block_ts = int(block["timestamp"], 16)

def beacon_get(path):
    url = f"{beacon_url}{path}"
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None
        raise

genesis = beacon_get("/eth/v1/beacon/genesis")
if not genesis or "data" not in genesis or "genesis_time" not in genesis["data"]:
    raise SystemExit("beacon genesis_time missing")
genesis_time = int(genesis["data"]["genesis_time"])

spec = beacon_get("/eth/v1/config/spec")
seconds_per_slot = 12
if spec and "data" in spec and "SECONDS_PER_SLOT" in spec["data"]:
    try:
        seconds_per_slot = int(spec["data"]["SECONDS_PER_SLOT"])
    except Exception:
        seconds_per_slot = 12

if block_ts < genesis_time:
    raise SystemExit("block timestamp before genesis_time")

slot = (block_ts - genesis_time) // seconds_per_slot

sidecars = beacon_get(f"/eth/v1/beacon/blob_sidecars/{slot}")
if sidecars is None:
    sidecars = beacon_get(f"/eth/v1/beacon/blobs/{slot}")
if not sidecars or "data" not in sidecars:
    raise SystemExit("beacon blob sidecars missing")

data = sidecars.get("data")
if isinstance(data, list) and data and isinstance(data[0], str):
    raise SystemExit("beacon blobs endpoint lacks commitments; use blob_sidecars or retriever")

matched_blob = None
for sc in data:
    kzg = sc.get("kzg_commitment")
    blob_hex = sc.get("blob")
    if not kzg or not blob_hex:
        continue
    kzg_bytes = bytes.fromhex(kzg[2:])
    h = hashlib.sha256(kzg_bytes).digest()
    versioned = bytes([1]) + h[1:]
    versioned_hex = "0x" + versioned.hex()
    if versioned_hex.lower() == target_hash:
        if blob_hex.startswith("0x"):
            blob_hex = blob_hex[2:]
        matched_blob = bytes.fromhex(blob_hex)
        break

if matched_blob is None:
    raise SystemExit("blob not found in sidecars")

if len(matched_blob) != 131072:
    raise SystemExit(f"unexpected blob size {len(matched_blob)}")

payload_space = b"".join(matched_blob[i + 1:i + 32] for i in range(0, len(matched_blob), 32))
if len(payload_space) < 31:
    raise SystemExit("decoded payload space too small")

length = int.from_bytes(payload_space[0:8], "big")
if length < 0 or 31 + length > len(payload_space):
    raise SystemExit("invalid payload length")

payload = payload_space[31:31 + length]

with open(output_path, "wb") as f:
    f.write(payload)
PY
fi

if [ ! -s "$OUTPUT_PATH" ]; then
    echo "ERROR: payload missing or empty: $OUTPUT_PATH" >&2
    exit 1
fi

python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

out = {"provider": "blob", "payload_path": sys.argv[1]}
print(json.dumps(out))
PY
