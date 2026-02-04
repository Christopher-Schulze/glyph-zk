#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_ENVELOPE_PATH=... DA_OUTPUT_PATH=... scripts/da/fetch_arweave.sh

Required env:
  DA_ENVELOPE_PATH
  DA_OUTPUT_PATH

Optional env:
  ARWEAVE_GATEWAY_URL (default: https://arweave.net)

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
GATEWAY_URL="${ARWEAVE_GATEWAY_URL:-https://arweave.net}"

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
require_cmd curl
mkdir -p "$(dirname "$OUTPUT_PATH")"

TX_ID="$(python3 - "$ENVELOPE_PATH" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") == "arweave":
        print(item.get("tx_id", ""))
        raise SystemExit(0)
print("")
PY
)"

if [ -z "$TX_ID" ]; then
    echo "ERROR: arweave commitment not found in envelope" >&2
    exit 2
fi

curl -sSL "${GATEWAY_URL}/${TX_ID}" -o "$OUTPUT_PATH"
if [ ! -s "$OUTPUT_PATH" ]; then
    echo "ERROR: payload missing or empty: $OUTPUT_PATH" >&2
    exit 1
fi

python3 - "$OUTPUT_PATH" <<'PY'
import json
import sys

out = {"provider": "arweave", "payload_path": sys.argv[1]}
print(json.dumps(out))
PY
