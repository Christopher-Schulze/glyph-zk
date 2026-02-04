#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  PROFILE=... ARTIFACT_PATH=... scripts/da/smoke_test.sh

Required env:
  PROFILE
  ARTIFACT_PATH

Optional env:
  PROOF_PATH
  VK_PATH
  MODE (default: minimal)
  RUN_ID (default: UTC timestamp)
  OUT_DIR (default: scripts/out/da/smoke/<profile>/<run_id>)
  GLYPH_DA_BIN (default: target/release/glyph_da)

Outputs:
  Runs submit, fetch, and verify for the selected profile.

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

log_context() {
  echo "=== da_context ==="
  echo "mode=smoke_test"
  echo "profile=$PROFILE"
  echo "run_id=$RUN_ID"
  echo "out_dir=$OUT_DIR"
  echo "artifact_path=$ARTIFACT_PATH"
  echo "proof_path=$PROOF_PATH"
  echo "vk_path=$VK_PATH"
  echo "profile_mode=$MODE"
  echo "glyph_da_bin=$GLYPH_DA_BIN"
  echo ""
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
GLYPH_DA_BIN="${GLYPH_DA_BIN:-$PROJECT_ROOT/target/release/glyph_da}"
PROFILE="${PROFILE:-}"
ARTIFACT_PATH="${ARTIFACT_PATH:-}"
PROOF_PATH="${PROOF_PATH:-}"
VK_PATH="${VK_PATH:-}"
MODE="${MODE:-minimal}"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"

if [ -z "$PROFILE" ]; then
    echo "ERROR: PROFILE not set" >&2
    exit 2
fi
if [ -z "$ARTIFACT_PATH" ]; then
    echo "ERROR: ARTIFACT_PATH not set" >&2
    exit 2
fi

if [ ! -x "$GLYPH_DA_BIN" ]; then
    require_cmd cargo
    echo "Building glyph_da..."
    cargo build --release --bin glyph_da
fi

if [[ "$PROFILE" == blob-* ]]; then
    require_cmd cast
fi

OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/smoke/$PROFILE/$RUN_ID}"
mkdir -p "$OUT_DIR"
log_context

submit_args=(submit --profile "$PROFILE" --mode "$MODE" --artifact "$ARTIFACT_PATH" --out-dir "$OUT_DIR")
if [ -n "$PROOF_PATH" ]; then
    submit_args+=(--proof "$PROOF_PATH")
fi
if [ -n "$VK_PATH" ]; then
    submit_args+=(--vk "$VK_PATH")
fi

echo "=== DA smoke submit: $PROFILE ==="
"$GLYPH_DA_BIN" "${submit_args[@]}"

ENVELOPE_PATH="$OUT_DIR/envelope.json"

fetch_and_verify() {
    local provider="$1"
    local out_path="$2"
    echo "=== DA fetch: $provider ==="
    "$GLYPH_DA_BIN" fetch --provider "$provider" --envelope "$ENVELOPE_PATH" --out "$out_path"
    echo "=== DA verify: $provider ==="
    "$GLYPH_DA_BIN" verify --envelope "$ENVELOPE_PATH" --payload "$out_path"
}

case "$PROFILE" in
    verifier-only)
        echo "Verifier-only profile does not require fetch."
        ;;
    blob-only)
        fetch_and_verify blob "$OUT_DIR/payload.blob.bin"
        ;;
    blob-arweave)
        fetch_and_verify blob "$OUT_DIR/payload.blob.bin"
        fetch_and_verify arweave "$OUT_DIR/payload.arweave.bin"
        ;;
    blob-eigenda-arweave)
        fetch_and_verify blob "$OUT_DIR/payload.blob.bin"
        fetch_and_verify eigenda "$OUT_DIR/payload.eigenda.bin"
        fetch_and_verify arweave "$OUT_DIR/payload.arweave.bin"
        ;;
    *)
        echo "ERROR: unsupported PROFILE '$PROFILE'" >&2
        exit 2
        ;;
esac
