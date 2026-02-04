#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_PAYLOAD_PATH=... EIGENDA_MODE=v1 scripts/da/submit_eigenda.sh

Modes:
  EIGENDA_MODE=v1 or v2 (direct mode)
  EIGENDA_PROXY_URL set (proxy mode)
  EIGENDA_CMD set (custom command mode)

Required env:
  DA_PAYLOAD_PATH

Required env for v1 direct:
  EIGENDA_V1_DISPERSER_ADDR
  EIGENDA_V1_ETH_RPC_URL
  EIGENDA_V1_SVC_MANAGER_ADDR

Required env for v2 direct:
  EIGENDA_V2_DISPERSER_ADDR
  EIGENDA_V2_ETH_RPC_URL
  EIGENDA_V2_CERT_VERIFIER_ADDR
  EIGENDA_V2_RELAY_REGISTRY_ADDR
  EIGENDA_V2_AUTH_PRIVATE_KEY_HEX
  EIGENDA_V2_SRS_DIR

Outputs:
  JSON with provider=eigenda and commitment fields.

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

# Required envs for v1 direct mode:
# - EIGENDA_V1_DISPERSER_ADDR=disperser-host:port
# - EIGENDA_V1_ETH_RPC_URL=https://your-rpc
# - EIGENDA_V1_SVC_MANAGER_ADDR=0x...
# - EIGENDA_V1_SIGNER_PRIVATE_KEY_HEX=0x... (optional for unauth)
#
# Required envs for v2 direct mode:
# - EIGENDA_V2_DISPERSER_ADDR=disperser-host:port
# - EIGENDA_V2_ETH_RPC_URL=https://your-rpc
# - EIGENDA_V2_CERT_VERIFIER_ADDR=0x...
# - EIGENDA_V2_RELAY_REGISTRY_ADDR=0x...
# - EIGENDA_V2_AUTH_PRIVATE_KEY_HEX=0x...
# - EIGENDA_V2_SRS_DIR=/path/to/srs

PAYLOAD_PATH="${DA_PAYLOAD_PATH:-}"
EIGENDA_CMD="${EIGENDA_CMD:-}"
EIGENDA_PROXY_URL="${EIGENDA_PROXY_URL:-}"
EIGENDA_COMMITMENT_MODE="${EIGENDA_COMMITMENT_MODE:-standard}"
EIGENDA_MODE="${EIGENDA_MODE:-}"
EIGENDA_V1_DISPERSER_ADDR="${EIGENDA_V1_DISPERSER_ADDR:-}"
EIGENDA_V1_ETH_RPC_URL="${EIGENDA_V1_ETH_RPC_URL:-}"
EIGENDA_V1_SVC_MANAGER_ADDR="${EIGENDA_V1_SVC_MANAGER_ADDR:-}"
EIGENDA_V1_DIRECTORY_ADDR="${EIGENDA_V1_DIRECTORY_ADDR:-0x9620dC4B3564198554e4D2b06dEFB7A369D90257}"
EIGENDA_V1_GO_BIN="${EIGENDA_V1_GO_BIN:-go}"
EIGENDA_V1_NO_WAIT="${EIGENDA_V1_NO_WAIT:-0}"
EIGENDA_V1_RETRIES="${EIGENDA_V1_RETRIES:-2}"
EIGENDA_V1_RETRY_SLEEP_SECS="${EIGENDA_V1_RETRY_SLEEP_SECS:-5}"
EIGENDA_V2_GO_BIN="${EIGENDA_V2_GO_BIN:-go}"
EIGENDA_V2_NO_WAIT="${EIGENDA_V2_NO_WAIT:-0}"
EIGENDA_V2_RETRIES="${EIGENDA_V2_RETRIES:-2}"
EIGENDA_V2_RETRY_SLEEP_SECS="${EIGENDA_V2_RETRY_SLEEP_SECS:-5}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ -z "$PAYLOAD_PATH" ]; then
    echo "ERROR: DA_PAYLOAD_PATH not set" >&2
    exit 2
fi
if [ ! -f "$PAYLOAD_PATH" ]; then
    echo "ERROR: DA_PAYLOAD_PATH not found: $PAYLOAD_PATH" >&2
    exit 2
fi

require_cmd python3

OUTPUT=""
if [ -n "$EIGENDA_CMD" ]; then
    OUTPUT="$(EIGENDA_DATA_PATH="$PAYLOAD_PATH" bash -lc "$EIGENDA_CMD")"
elif [ -n "$EIGENDA_PROXY_URL" ]; then
    require_cmd curl
    TMP_COMMIT="$(mktemp)"
    curl -sSL -X POST --data-binary @"$PAYLOAD_PATH" "${EIGENDA_PROXY_URL%/}/put?commitment_mode=${EIGENDA_COMMITMENT_MODE}" -o "$TMP_COMMIT"
    COMMIT_HEX="$(python3 - "$TMP_COMMIT" <<'PY'
import sys

path = sys.argv[1]
raw = open(path, "rb").read()
if not raw:
    raise SystemExit("eigenda proxy returned empty commitment")
print(raw.hex())
PY
)"
    rm -f "$TMP_COMMIT"
    if [ -z "$COMMIT_HEX" ]; then
        echo "ERROR: eigenda proxy returned empty commitment" >&2
        exit 1
    fi
    if command -v cast >/dev/null 2>&1; then
        CERT_HASH="$(cast keccak 0x$COMMIT_HEX)"
    else
        CERT_HASH="$(python3 - "$COMMIT_HEX" <<'PY'
import hashlib
import sys
raw = bytes.fromhex(sys.argv[1])
print("0x" + hashlib.sha256(raw).hexdigest())
PY
)"
    fi
    OUTPUT="$(python3 - "$COMMIT_HEX" "$CERT_HASH" "$EIGENDA_PROXY_URL" <<'PY'
import json
import sys

commit_hex = sys.argv[1]
cert_hash = sys.argv[2]
proxy_url = sys.argv[3]

out = {
    "blob_key": commit_hex,
    "certificate_hash": cert_hash,
    "disperser_url": proxy_url,
}
print(json.dumps(out))
PY
)"
elif [ "$EIGENDA_MODE" = "v1" ]; then
    if [ -z "$EIGENDA_V1_DISPERSER_ADDR" ]; then
        echo "ERROR: EIGENDA_V1_DISPERSER_ADDR not set" >&2
        exit 2
    fi
    if [ -z "$EIGENDA_V1_ETH_RPC_URL" ]; then
        echo "ERROR: EIGENDA_V1_ETH_RPC_URL not set" >&2
        exit 2
    fi
    if [ -z "$EIGENDA_V1_SVC_MANAGER_ADDR" ]; then
        echo "ERROR: EIGENDA_V1_SVC_MANAGER_ADDR not set and not resolved via directory" >&2
        exit 2
    fi
    if ! command -v "$EIGENDA_V1_GO_BIN" >/dev/null 2>&1; then
        echo "ERROR: go not found in PATH (required for EigenDA v1 direct mode)" >&2
        exit 2
    fi
    NO_WAIT_FLAG=""
    if [ "$EIGENDA_V1_NO_WAIT" = "1" ]; then
        NO_WAIT_FLAG="--no-wait"
    fi
    attempt=0
    while true; do
        set +e
        OUTPUT="$(
            EIGENDA_V1_DISPERSER_ADDR="$EIGENDA_V1_DISPERSER_ADDR" \
            EIGENDA_V1_ETH_RPC_URL="$EIGENDA_V1_ETH_RPC_URL" \
            EIGENDA_V1_SVC_MANAGER_ADDR="$EIGENDA_V1_SVC_MANAGER_ADDR" \
            EIGENDA_V1_SIGNER_PRIVATE_KEY_HEX="${EIGENDA_V1_SIGNER_PRIVATE_KEY_HEX:-}" \
            bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v1\" && \"$EIGENDA_V1_GO_BIN\" run . --mode submit $NO_WAIT_FLAG --payload \"$PAYLOAD_PATH\"" 2>&1
        )"
        status=$?
        set -e
        if [ $status -eq 0 ]; then
            break
        fi
        attempt=$((attempt + 1))
        if [ $attempt -gt "$EIGENDA_V1_RETRIES" ]; then
            echo "ERROR: eigenda v1 submit failed after retries: $OUTPUT" >&2
            exit $status
        fi
        echo "WARN: eigenda v1 submit failed (attempt $attempt/$EIGENDA_V1_RETRIES), retrying..." >&2
        sleep "$((EIGENDA_V1_RETRY_SLEEP_SECS * attempt))"
    done
elif [ "$EIGENDA_MODE" = "v2" ]; then
    if ! command -v "$EIGENDA_V2_GO_BIN" >/dev/null 2>&1; then
        echo "ERROR: go not found in PATH (required for EigenDA v2 direct mode)" >&2
        exit 2
    fi
    NO_WAIT_FLAG=""
    if [ "$EIGENDA_V2_NO_WAIT" = "1" ]; then
        NO_WAIT_FLAG="--no-wait"
    fi
    attempt=0
    while true; do
        set +e
        OUTPUT="$(
            bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v2\" && \"$EIGENDA_V2_GO_BIN\" run . --mode submit $NO_WAIT_FLAG --payload \"$PAYLOAD_PATH\"" 2>&1
        )"
        status=$?
        set -e
        if [ $status -eq 0 ]; then
            break
        fi
        attempt=$((attempt + 1))
        if [ $attempt -gt "$EIGENDA_V2_RETRIES" ]; then
            echo "ERROR: eigenda v2 submit failed after retries: $OUTPUT" >&2
            exit $status
        fi
        echo "WARN: eigenda v2 submit failed (attempt $attempt/$EIGENDA_V2_RETRIES), retrying..." >&2
        sleep "$((EIGENDA_V2_RETRY_SLEEP_SECS * attempt))"
    done
else
    echo "ERROR: EIGENDA_CMD not set, EIGENDA_PROXY_URL not set, and EIGENDA_MODE not set to v1 or v2" >&2
    exit 2
fi

OUTPUT="$(python3 - "$OUTPUT" <<'PY'
import sys

raw = sys.argv[1]
lines = [l.strip() for l in raw.splitlines() if l.strip().startswith("{") and l.strip().endswith("}")]
if lines:
    print(lines[-1])
    sys.exit(0)
start = raw.rfind("{")
end = raw.rfind("}")
if start != -1 and end != -1 and end > start:
    print(raw[start:end + 1])
else:
    print(raw)
PY
)"

python3 - "$OUTPUT" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
data = json.loads(raw)
blob_key = data.get("blob_key") or data.get("blobKey") or ""
cert = data.get("certificate_hash") or data.get("certificateHash") or ""
request_id = data.get("request_id") or data.get("requestId") or ""
status = data.get("status") or ""
disperser = data.get("disperser_url") or data.get("disperserUrl") or ""

if not (blob_key and cert) and not request_id:
    raise SystemExit("eigenda cmd output missing blob_key/certificate_hash or request_id")

out = {"provider": "eigenda"}
if blob_key:
    out["blob_key"] = blob_key
if cert:
    out["certificate_hash"] = cert
if request_id:
    out["request_id"] = request_id
if status:
    out["status"] = status
if disperser:
    out["disperser_url"] = disperser
print(json.dumps(out))
PY
