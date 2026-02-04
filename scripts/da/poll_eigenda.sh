#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  DA_ENVELOPE_PATH=... scripts/da/poll_eigenda.sh

Required env:
  DA_ENVELOPE_PATH

Optional env:
  DA_OUT_PATH (default: overwrite envelope)
  EIGENDA_MODE (v1 or v2)
  EIGENDA_V1_* or EIGENDA_V2_* for direct mode

Outputs:
  Writes updated envelope JSON to DA_OUT_PATH and prints JSON with provider and envelope_path.

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
OUT_PATH="${DA_OUT_PATH:-}"
EIGENDA_V1_DISPERSER_ADDR="${EIGENDA_V1_DISPERSER_ADDR:-}"
EIGENDA_V1_ETH_RPC_URL="${EIGENDA_V1_ETH_RPC_URL:-}"
EIGENDA_V1_SVC_MANAGER_ADDR="${EIGENDA_V1_SVC_MANAGER_ADDR:-}"
EIGENDA_V1_DIRECTORY_ADDR="${EIGENDA_V1_DIRECTORY_ADDR:-0x9620dC4B3564198554e4D2b06dEFB7A369D90257}"
EIGENDA_V1_GO_BIN="${EIGENDA_V1_GO_BIN:-go}"
EIGENDA_V2_GO_BIN="${EIGENDA_V2_GO_BIN:-go}"
EIGENDA_MODE="${EIGENDA_MODE:-v1}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ -z "$ENVELOPE_PATH" ]; then
    echo "ERROR: DA_ENVELOPE_PATH not set" >&2
    exit 2
fi
if [ ! -f "$ENVELOPE_PATH" ]; then
    echo "ERROR: DA_ENVELOPE_PATH not found: $ENVELOPE_PATH" >&2
    exit 2
fi

case "$EIGENDA_MODE" in
    v1|v2)
        ;;
    *)
        echo "ERROR: unsupported EIGENDA_MODE: $EIGENDA_MODE (use v1 or v2)" >&2
        exit 2
        ;;
esac

if [ -z "$OUT_PATH" ]; then
    OUT_PATH="$ENVELOPE_PATH"
fi

require_cmd python3
mkdir -p "$(dirname "$OUT_PATH")"

read -r REQUEST_ID DISPERSER_URL BLOB_KEY <<EOF
$(python3 - "$ENVELOPE_PATH" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") in ("eigenda", "eigen_da", "eigenDA"):
        request_id = item.get("request_id", "")
        disperser = item.get("disperser_url", "")
        blob_key = item.get("blob_key", "")
        print(f"{request_id}\t{disperser}\t{blob_key}")
        raise SystemExit(0)
print("\t\t")
PY
)
EOF

if [ "$EIGENDA_MODE" = "v2" ]; then
    if [ -z "$BLOB_KEY" ]; then
        BLOB_KEY="$(python3 - "$ENVELOPE_PATH" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") in ("eigenda", "eigen_da", "eigenDA"):
        print(item.get("blob_key", ""))
        raise SystemExit(0)
print("")
PY
)"
    fi
    if [ -z "$BLOB_KEY" ]; then
        echo "ERROR: eigenda blob_key not found in envelope for v2" >&2
        exit 2
    fi
    if ! command -v "$EIGENDA_V2_GO_BIN" >/dev/null 2>&1; then
        echo "ERROR: go not found in PATH (required for EigenDA v2 poll)" >&2
        exit 2
    fi
    POLL_JSON="$(
        bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v2\" && \"$EIGENDA_V2_GO_BIN\" run . --mode poll --blob-key \"$BLOB_KEY\""
    )"
else
    if [ -z "$REQUEST_ID" ]; then
        echo "ERROR: eigenda request_id not found in envelope" >&2
        exit 2
    fi
    if [ -z "$EIGENDA_V1_DISPERSER_ADDR" ]; then
        if [ -n "$DISPERSER_URL" ]; then
            EIGENDA_V1_DISPERSER_ADDR="$DISPERSER_URL"
        else
            echo "ERROR: EIGENDA_V1_DISPERSER_ADDR not set" >&2
            exit 2
        fi
    fi
    if [ -z "$EIGENDA_V1_ETH_RPC_URL" ]; then
        echo "ERROR: EIGENDA_V1_ETH_RPC_URL not set" >&2
        exit 2
    fi
    if [ -z "$EIGENDA_V1_SVC_MANAGER_ADDR" ]; then
        echo "ERROR: EIGENDA_V1_SVC_MANAGER_ADDR not set" >&2
        exit 2
    fi
    if ! command -v "$EIGENDA_V1_GO_BIN" >/dev/null 2>&1; then
        echo "ERROR: go not found in PATH (required for EigenDA v1 poll)" >&2
        exit 2
    fi

    POLL_JSON="$(
        EIGENDA_V1_DISPERSER_ADDR="$EIGENDA_V1_DISPERSER_ADDR" \
        EIGENDA_V1_ETH_RPC_URL="$EIGENDA_V1_ETH_RPC_URL" \
        EIGENDA_V1_SVC_MANAGER_ADDR="$EIGENDA_V1_SVC_MANAGER_ADDR" \
        bash -lc "cd \"$ROOT_DIR/scripts/da/providers/eigenda_v1\" && \"$EIGENDA_V1_GO_BIN\" run . --mode poll --request-id \"$REQUEST_ID\""
    )"
fi

POLL_JSON="$(python3 - "$POLL_JSON" <<'PY'
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

python3 - "$ENVELOPE_PATH" "$OUT_PATH" "$POLL_JSON" <<'PY'
import json
import sys

env_path = sys.argv[1]
out_path = sys.argv[2]
poll = json.loads(sys.argv[3])

env = json.load(open(env_path, "r", encoding="utf-8"))
updated = False
for item in env.get("commitments", []):
    if item.get("provider") in ("eigenda", "eigen_da", "eigenDA"):
        item["status"] = poll.get("status", item.get("status"))
        if poll.get("request_id"):
            item["request_id"] = poll.get("request_id")
        if poll.get("blob_key"):
            item["blob_key"] = poll.get("blob_key")
        if poll.get("certificate_hash"):
            item["certificate_hash"] = poll.get("certificate_hash")
        if poll.get("disperser_url"):
            item["disperser_url"] = poll.get("disperser_url")
        updated = True
        break

if not updated:
    raise SystemExit("eigenda commitment not found in envelope")

env["envelope_hash"] = None

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(env, f, indent=2)
print(json.dumps({"provider": "eigenda", "envelope_path": out_path}))
PY
