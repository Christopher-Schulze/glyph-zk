#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/arweave_local_smoke.sh

Optional env:
  ARTIFACT_PATH
  ARWEAVE_JWK_PATH
  ARWEAVE_GATEWAY_URL (default: http://127.0.0.1:1984)
  OUT_DIR
  JS runtime: prefers bunx, falls back to npx

Outputs:
  Writes submit.json, envelope.json, payload.bin, and arlocal.log under OUT_DIR.

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

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$ROOT_DIR/scripts/out}"
ARTIFACT_PATH="${ARTIFACT_PATH:-$ROOT_DIR/docs/wallet/Arweave/hi.png}"
ARWEAVE_JWK_PATH="${ARWEAVE_JWK_PATH:-$ROOT_DIR/docs/wallet/Arweave/PgRNsN_PYpKkDxUTdReRhNumbitVJJbUqFQrD7k11LA.json}"
ARWEAVE_GATEWAY_URL="${ARWEAVE_GATEWAY_URL:-http://127.0.0.1:1984}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/arweave-local}"

require_cmd curl
require_cmd python3

ARLOCAL_CMD=()
if command -v bunx >/dev/null 2>&1; then
    ARLOCAL_CMD=(bunx --yes arlocal)
elif command -v npx >/dev/null 2>&1; then
    ARLOCAL_CMD=(npx --yes arlocal)
else
    echo "ERROR: required command not found: bunx or npx" >&2
    exit 2
fi

if [ ! -f "$ARTIFACT_PATH" ]; then
    echo "ERROR: ARTIFACT_PATH not found: $ARTIFACT_PATH" >&2
    exit 2
fi

if [ ! -f "$ARWEAVE_JWK_PATH" ]; then
    echo "ERROR: ARWEAVE_JWK_PATH not found: $ARWEAVE_JWK_PATH" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"

cleanup() {
    if [ -n "${ARLOCAL_PID:-}" ]; then
        kill "$ARLOCAL_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "Starting arlocal on $ARWEAVE_GATEWAY_URL"
"${ARLOCAL_CMD[@]}" >"$OUT_DIR/arlocal.log" 2>&1 &
ARLOCAL_PID=$!

for _ in $(seq 1 30); do
    if curl -sSL "$ARWEAVE_GATEWAY_URL" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "Submitting payload"
DA_PAYLOAD_PATH="$ARTIFACT_PATH" \
ARWEAVE_JWK_PATH="$ARWEAVE_JWK_PATH" \
ARWEAVE_GATEWAY_URL="$ARWEAVE_GATEWAY_URL" \
"$ROOT_DIR/scripts/da/submit_arweave.sh" >"$OUT_DIR/submit.json"

echo "Fetching payload"
DA_ENVELOPE_PATH="$OUT_DIR/envelope.json"
python3 - "$OUT_DIR/submit.json" "$DA_ENVELOPE_PATH" <<'PY'
import json
import sys

submit = json.load(open(sys.argv[1], "r", encoding="utf-8"))
env = {"commitments": [submit]}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(env, f)
PY

DA_ENVELOPE_PATH="$DA_ENVELOPE_PATH" \
DA_OUTPUT_PATH="$OUT_DIR/payload.bin" \
ARWEAVE_GATEWAY_URL="$ARWEAVE_GATEWAY_URL" \
"$ROOT_DIR/scripts/da/fetch_arweave.sh" >/dev/null

echo "Arweave local smoke ok: $OUT_DIR/payload.bin"
