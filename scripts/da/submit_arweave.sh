#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_PAYLOAD_PATH=... ARWEAVE_JWK_PATH=... scripts/da/submit_arweave.sh

Required env:
  DA_PAYLOAD_PATH
  ARWEAVE_JWK_PATH or ARWEAVE_CMD

Optional env:
  ARWEAVE_GATEWAY_URL (default: https://arweave.net)
  ARWEAVE_TURBO_SCRIPT (default: scripts/da/providers/arweave_turbo_upload.mjs)
  JS runtime: prefers bun, falls back to node

Outputs:
  JSON with provider=arweave, tx_id, and optional gateway_url.

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

PAYLOAD_PATH="${DA_PAYLOAD_PATH:-}"
ARWEAVE_CMD="${ARWEAVE_CMD:-}"
ARWEAVE_JWK_PATH="${ARWEAVE_JWK_PATH:-}"
ARWEAVE_GATEWAY_URL="${ARWEAVE_GATEWAY_URL:-https://arweave.net}"
ARWEAVE_TURBO_SCRIPT="${ARWEAVE_TURBO_SCRIPT:-$(cd "$(dirname "$0")/providers" && pwd)/arweave_turbo_upload.mjs}"

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
if [ -n "$ARWEAVE_CMD" ]; then
    OUTPUT="$(ARWEAVE_DATA_PATH="$PAYLOAD_PATH" bash -lc "$ARWEAVE_CMD")"
else
    if [ -z "$ARWEAVE_JWK_PATH" ]; then
        echo "ERROR: ARWEAVE_CMD not set and ARWEAVE_JWK_PATH not set" >&2
        exit 2
    fi
    if [ ! -f "$ARWEAVE_JWK_PATH" ]; then
        echo "ERROR: ARWEAVE_JWK_PATH not found: $ARWEAVE_JWK_PATH" >&2
        exit 2
    fi
    JS_RUNTIME="node"
    if command -v bun >/dev/null 2>&1; then
        JS_RUNTIME="bun"
    else
        require_cmd node
    fi
    if [ ! -f "$ARWEAVE_TURBO_SCRIPT" ]; then
        echo "ERROR: Turbo upload script not found at $ARWEAVE_TURBO_SCRIPT" >&2
        exit 2
    fi
    OUTPUT="$(ARWEAVE_DATA_PATH="$PAYLOAD_PATH" ARWEAVE_JWK_PATH="$ARWEAVE_JWK_PATH" ARWEAVE_GATEWAY_URL="$ARWEAVE_GATEWAY_URL" "$JS_RUNTIME" "$ARWEAVE_TURBO_SCRIPT")"
fi

python3 - "$OUTPUT" <<'PY'
import json
import sys

raw = sys.argv[1].strip()
data = json.loads(raw)
tx_id = data.get("tx_id") or data.get("id") or ""
gateway = data.get("gateway_url") or data.get("gateway") or ""

if not tx_id:
    raise SystemExit("arweave cmd output missing tx_id")

out = {"provider": "arweave", "tx_id": tx_id}
if gateway:
    out["gateway_url"] = gateway
print(json.dumps(out))
PY
