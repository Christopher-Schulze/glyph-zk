#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
GLYPH_DA_BIN="${GLYPH_DA_BIN:-$PROJECT_ROOT/target/release/glyph_da}"

PROFILE=""
NETWORK=""
ENV_FILE=""
ARTIFACT_PATH=""
MODE="minimal"
OUT_DIR=""
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
WITH_V2="0"
V2_PAYLOAD_PATH=""
V2_SMALL_PAYLOAD="${V2_SMALL_PAYLOAD:-1}"

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/run_profile.sh --profile <name> --artifact <path> [options]

Profiles:
  verifier-only
  blob-only
  blob-arweave
  blob-eigenda-arweave
  full                 (alias for blob-eigenda-arweave)
  eigenda-v2            (Sepolia only)

Options:
  --network <sepolia|hoodi>      Load scripts/deploy/.env.<network>
  --env-file <path>             Load a specific env file
  --mode <minimal|full>          Payload mode (default: minimal)
  --out-dir <path>              Output directory
  --with-v2                     Also run eigenda-v2 after full package
  --v2-payload <path>           Payload for eigenda-v2 (default: artifact or small payload)

Env requirements per provider:
  Blob:
    BLOB_RPC_URL, BLOB_PRIVATE_KEY, and one of BLOB_RETRIEVER_URL_TEMPLATE or BLOB_BEACON_API_URL
  Arweave:
    ARWEAVE_JWK_PATH or ARWEAVE_CMD, and ARWEAVE_GATEWAY_URL (default: https://arweave.net)
  EigenDA v1:
    EIGENDA_V1_DISPERSER_ADDR, EIGENDA_V1_ETH_RPC_URL, EIGENDA_V1_SVC_MANAGER_ADDR
  EigenDA v2 (Sepolia only):
    EIGENDA_V2_DISPERSER_ADDR, EIGENDA_V2_ETH_RPC_URL, EIGENDA_V2_CERT_VERIFIER_ADDR,
    EIGENDA_V2_RELAY_REGISTRY_ADDR, EIGENDA_V2_AUTH_PRIVATE_KEY_HEX, EIGENDA_V2_SRS_DIR

Outputs:
  Writes envelope and payloads under --out-dir or scripts/out/da/<profile>/<run_id>.
  Emits status lines and hash checks to stdout.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

die() {
    echo "ERROR: $1" >&2
    exit 1
}

die_input() {
    echo "ERROR: $1" >&2
    exit 2
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die_input "required command not found: $cmd"
    fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

case "$MODE" in
    minimal|full)
        ;;
    *)
        die_input "unsupported --mode: $MODE (use minimal or full)"
        ;;
esac

require_env() {
    local var="$1"
    if [ -z "${!var:-}" ]; then
        die_input "$var not set"
    fi
}

load_env() {
    if [ -n "$ENV_FILE" ]; then
        # shellcheck disable=SC1090
        set -a && . "$ENV_FILE" && set +a
    elif [ -n "$NETWORK" ]; then
        local path="$PROJECT_ROOT/scripts/deploy/.env.$NETWORK"
        if [ ! -f "$path" ]; then
            die_input "env file not found: $path"
        fi
        # shellcheck disable=SC1090
        set -a && . "$path" && set +a
    fi
}

ensure_glyph_da() {
    if [ ! -x "$GLYPH_DA_BIN" ]; then
        require_cmd cargo
        echo "Building glyph_da..."
        cargo build --release --bin glyph_da
    fi
}

log_context() {
    local out_dir="$1"
    echo "=== da_context ==="
    echo "profile=$PROFILE"
    echo "network=$NETWORK"
    echo "env_file=${ENV_FILE:-}"
    echo "mode=$MODE"
    echo "run_id=$RUN_ID"
    echo "with_v2=$WITH_V2"
    echo "out_dir=$out_dir"
    echo "artifact_path=$ARTIFACT_PATH"
    echo "v2_payload=${V2_PAYLOAD_PATH:-}"
    echo ""
}

hash_pair() {
    local a="$1"
    local b="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$a" "$b"
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$a" "$b"
        return
    fi
    die_input "sha256sum or shasum required"
}

check_blob_env() {
    require_env BLOB_RPC_URL
    require_env BLOB_PRIVATE_KEY
    if [ -z "${BLOB_RETRIEVER_URL_TEMPLATE:-}" ] && [ -z "${BLOB_BEACON_API_URL:-}" ]; then
        die_input "BLOB_RETRIEVER_URL_TEMPLATE or BLOB_BEACON_API_URL required"
    fi
    require_cmd cast
}

check_arweave_env() {
    if [ -z "${ARWEAVE_CMD:-}" ] && [ -z "${ARWEAVE_JWK_PATH:-}" ]; then
        die_input "ARWEAVE_CMD or ARWEAVE_JWK_PATH required"
    fi
    if [ -z "${ARWEAVE_CMD:-}" ] && [ -n "${ARWEAVE_JWK_PATH:-}" ] && [ ! -f "$ARWEAVE_JWK_PATH" ]; then
        die_input "ARWEAVE_JWK_PATH not found: $ARWEAVE_JWK_PATH"
    fi
}

check_eigenda_v1_env() {
    require_env EIGENDA_V1_DISPERSER_ADDR
    require_env EIGENDA_V1_ETH_RPC_URL
    require_env EIGENDA_V1_SVC_MANAGER_ADDR
    require_cmd go
}

check_eigenda_v2_env() {
    if [ -z "${EIGENDA_V2_SRS_DIR:-}" ] && [ -d "$PROJECT_ROOT/scripts/da/srs/eigenda_v2" ]; then
        export EIGENDA_V2_SRS_DIR="$PROJECT_ROOT/scripts/da/srs/eigenda_v2"
    fi
    require_env EIGENDA_V2_DISPERSER_ADDR
    require_env EIGENDA_V2_ETH_RPC_URL
    require_env EIGENDA_V2_CERT_VERIFIER_ADDR
    require_env EIGENDA_V2_RELAY_REGISTRY_ADDR
    require_env EIGENDA_V2_AUTH_PRIVATE_KEY_HEX
    require_env EIGENDA_V2_SRS_DIR
    if [ ! -d "$EIGENDA_V2_SRS_DIR" ]; then
        die_input "EIGENDA_V2_SRS_DIR not found"
    fi
    require_cmd go
}

submit_fetch_verify() {
    local profile="$1"
    local out_dir="$2"

    mkdir -p "$out_dir"

    "$GLYPH_DA_BIN" submit --profile "$profile" --mode "$MODE" --artifact "$ARTIFACT_PATH" --out-dir "$out_dir"

    local envelope="$out_dir/envelope.json"
    if [ "$profile" = "blob-eigenda-arweave" ]; then
        if python3 - "$envelope" <<'PY'
import json
import sys

env = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for item in env.get("commitments", []):
    if item.get("provider") in ("eigenda", "eigen_da", "eigenDA"):
        req = item.get("request_id")
        if isinstance(req, str) and req.strip():
            sys.exit(0)
sys.exit(1)
PY
        then
            EIGENDA_MODE=v1 EIGENDA_V1_NO_WAIT=1 DA_ENVELOPE_PATH="$envelope" "$PROJECT_ROOT/scripts/da/poll_eigenda.sh" >/dev/null
        fi
    fi

    case "$profile" in
        blob-only)
            "$GLYPH_DA_BIN" fetch --provider blob --envelope "$envelope" --out "$out_dir/payload.blob.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.blob.bin"
            ;;
        blob-arweave)
            "$GLYPH_DA_BIN" fetch --provider blob --envelope "$envelope" --out "$out_dir/payload.blob.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.blob.bin"
            "$GLYPH_DA_BIN" fetch --provider arweave --envelope "$envelope" --out "$out_dir/payload.arweave.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.arweave.bin"
            ;;
        blob-eigenda-arweave)
            "$GLYPH_DA_BIN" fetch --provider blob --envelope "$envelope" --out "$out_dir/payload.blob.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.blob.bin"
            "$GLYPH_DA_BIN" fetch --provider eigenda --envelope "$envelope" --out "$out_dir/payload.eigenda.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.eigenda.bin"
            "$GLYPH_DA_BIN" fetch --provider arweave --envelope "$envelope" --out "$out_dir/payload.arweave.bin"
            "$GLYPH_DA_BIN" verify --envelope "$envelope" --payload "$out_dir/payload.arweave.bin"
            ;;
        verifier-only)
            echo "Verifier-only profile has no fetch step."
            ;;
        *)
            die_input "unsupported profile: $profile"
            ;;
    esac
}

run_eigenda_v2() {
    check_eigenda_v2_env
    if [ -n "$NETWORK" ] && [ "$NETWORK" != "sepolia" ]; then
        die_input "eigenda-v2 is Sepolia only"
    fi

    local payload="$V2_PAYLOAD_PATH"
    if [ -z "$payload" ]; then
        payload="$ARTIFACT_PATH"
    fi
    if [ ! -f "$payload" ]; then
        die_input "v2 payload not found: $payload"
    fi
    if [ "$V2_SMALL_PAYLOAD" = "1" ]; then
        local small="$PROJECT_OUT/da/eigenda-v2/payload.small.bin"
        mkdir -p "$(dirname "$small")"
        head -c 1024 "$payload" > "$small"
        payload="$small"
    fi

    local out_dir="$OUT_DIR"
    if [ -z "$out_dir" ]; then
        out_dir="$PROJECT_OUT/da/eigenda-v2/sepolia-$RUN_ID"
    fi
    mkdir -p "$out_dir"
    log_context "$out_dir"

    EIGENDA_MODE=v2 DA_PAYLOAD_PATH="$payload" "$PROJECT_ROOT/scripts/da/submit_eigenda.sh" > "$out_dir/commitment.json"
    python3 -c "import json; commit=json.load(open('$out_dir/commitment.json','r')); json.dump({'commitments':[commit]}, open('$out_dir/envelope.json','w'), indent=2)"

    EIGENDA_MODE=v2 DA_ENVELOPE_PATH="$out_dir/envelope.json" "$PROJECT_ROOT/scripts/da/poll_eigenda.sh" >/dev/null
    EIGENDA_MODE=v2 DA_ENVELOPE_PATH="$out_dir/envelope.json" DA_OUTPUT_PATH="$out_dir/payload.bin" "$PROJECT_ROOT/scripts/da/fetch_eigenda.sh" >/dev/null

    echo "eigenda-v2 ok: $out_dir"
    hash_pair "$payload" "$out_dir/payload.bin"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --network) NETWORK="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        --artifact) ARTIFACT_PATH="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --with-v2) WITH_V2="1"; shift 1 ;;
        --v2-payload) V2_PAYLOAD_PATH="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die_input "unknown arg: $1" ;;
    esac
done

if [ -z "$PROFILE" ]; then
    die_input "--profile required"
fi
if [ -z "$ARTIFACT_PATH" ]; then
    die_input "--artifact required"
fi
if [ ! -f "$ARTIFACT_PATH" ]; then
    die_input "artifact not found: $ARTIFACT_PATH"
fi

if [ "$PROFILE" = "full" ]; then
    PROFILE="blob-eigenda-arweave"
fi

require_cmd python3

load_env
ensure_glyph_da

case "$PROFILE" in
    verifier-only)
        OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/verifier-only/$RUN_ID}"
        log_context "$OUT_DIR"
        submit_fetch_verify "$PROFILE" "$OUT_DIR"
        ;;
    blob-only)
        check_blob_env
        OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/blob-only/$RUN_ID}"
        log_context "$OUT_DIR"
        submit_fetch_verify "$PROFILE" "$OUT_DIR"
        ;;
    blob-arweave)
        check_blob_env
        check_arweave_env
        OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/blob-arweave/$RUN_ID}"
        log_context "$OUT_DIR"
        submit_fetch_verify "$PROFILE" "$OUT_DIR"
        ;;
    blob-eigenda-arweave)
        check_blob_env
        check_arweave_env
        check_eigenda_v1_env
        export EIGENDA_MODE="${EIGENDA_MODE:-v1}"
        export EIGENDA_V1_RESPONSE_TIMEOUT_SEC="${EIGENDA_V1_RESPONSE_TIMEOUT_SEC:-120}"
        export EIGENDA_V1_STATUS_TIMEOUT_SEC="${EIGENDA_V1_STATUS_TIMEOUT_SEC:-1500}"
        OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/blob-eigenda-arweave/$RUN_ID}"
        log_context "$OUT_DIR"
        submit_fetch_verify "$PROFILE" "$OUT_DIR"
        if [ "$WITH_V2" = "1" ]; then
            run_eigenda_v2
        fi
        ;;
    eigenda-v2)
        run_eigenda_v2
        ;;
    *)
        die_input "unsupported profile: $PROFILE"
        ;;
esac
