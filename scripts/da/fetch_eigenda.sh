#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_ENVELOPE_PATH=... DA_OUTPUT_PATH=... scripts/da/fetch_eigenda.sh

Required env:
  DA_ENVELOPE_PATH
  DA_OUTPUT_PATH

Optional env:
  EIGENDA_MODE (v1 or v2)
  EIGENDA_PROXY_URL
  EIGENDA_RETRIEVER_URL_TEMPLATE
  EIGENDA_COMMITMENT_MODE
  EIGENDA_V1_* or EIGENDA_V2_* for direct mode

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
RETRIEVER_TEMPLATE="${EIGENDA_RETRIEVER_URL_TEMPLATE:-}"
EIGENDA_PROXY_URL="${EIGENDA_PROXY_URL:-}"
EIGENDA_COMMITMENT_MODE="${EIGENDA_COMMITMENT_MODE:-standard}"
EIGENDA_MODE="${EIGENDA_MODE:-}"
EIGENDA_V1_DISPERSER_ADDR="${EIGENDA_V1_DISPERSER_ADDR:-}"
EIGENDA_V1_ETH_RPC_URL="${EIGENDA_V1_ETH_RPC_URL:-}"
EIGENDA_V1_SVC_MANAGER_ADDR="${EIGENDA_V1_SVC_MANAGER_ADDR:-}"
EIGENDA_V1_DIRECTORY_ADDR="${EIGENDA_V1_DIRECTORY_ADDR:-0x9620dC4B3564198554e4D2b06dEFB7A369D90257}"
EIGENDA_V1_GO_BIN="${EIGENDA_V1_GO_BIN:-go}"
EIGENDA_V2_GO_BIN="${EIGENDA_V2_GO_BIN:-go}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

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

require_cmd python3
mkdir -p "$(dirname "$OUTPUT_PATH")"

read -r BLOB_KEY DISPERSER_URL <<EOF
$(python3 - "$ENVELOPE_PATH" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") in ("eigenda", "eigen_da", "eigenDA"):
        print(item.get("blob_key", ""))
        print(item.get("disperser_url", ""))
        raise SystemExit(0)
print("")
print("")
PY
)
EOF

if [ -z "$BLOB_KEY" ]; then
    echo "ERROR: eigenda commitment not found or still pending (run scripts/da/poll_eigenda.sh)" >&2
    exit 2
fi

URL=""
if [ "$EIGENDA_MODE" = "v2" ]; then
    if ! command -v "$EIGENDA_V2_GO_BIN" >/dev/null 2>&1; then
        echo "ERROR: go not found in PATH (required for EigenDA v2 mode)" >&2
        exit 2
    fi
    bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v2\" && \"$EIGENDA_V2_GO_BIN\" run . --mode fetch --blob-key \"$BLOB_KEY\" --out \"$OUTPUT_PATH\"" >/dev/null
elif [ "$EIGENDA_MODE" = "v1" ] || [[ "$BLOB_KEY" == *:* ]]; then
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
    EIGENDA_V1_DISPERSER_ADDR="$EIGENDA_V1_DISPERSER_ADDR" \
    EIGENDA_V1_ETH_RPC_URL="$EIGENDA_V1_ETH_RPC_URL" \
    EIGENDA_V1_SVC_MANAGER_ADDR="$EIGENDA_V1_SVC_MANAGER_ADDR" \
    bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v1\" && \"$EIGENDA_V1_GO_BIN\" run . --mode fetch --blob-key \"$BLOB_KEY\" --out \"$OUTPUT_PATH\"" >/dev/null
elif [ -n "$EIGENDA_PROXY_URL" ]; then
    URL="${EIGENDA_PROXY_URL%/}/get/${BLOB_KEY}?commitment_mode=${EIGENDA_COMMITMENT_MODE}"
elif [ -n "$RETRIEVER_TEMPLATE" ]; then
    URL="${RETRIEVER_TEMPLATE//%s/$BLOB_KEY}"
elif [ -n "$DISPERSER_URL" ]; then
    URL="${DISPERSER_URL%/}/retrieve?blob_key=${BLOB_KEY}"
else
    echo "ERROR: EIGENDA_RETRIEVER_URL_TEMPLATE not set and no disperser_url in envelope" >&2
    exit 2
fi

if [ -n "$URL" ]; then
    require_cmd curl
    curl -sSL "$URL" -o "$OUTPUT_PATH"
fi
if [ ! -s "$OUTPUT_PATH" ]; then
    echo "ERROR: payload missing or empty: $OUTPUT_PATH" >&2
    exit 1
fi

python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

out = {"provider": "eigenda", "payload_path": sys.argv[1]}
print(json.dumps(out))
PY
