#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  ARTIFACT_PATH=... scripts/da/run_all_profiles.sh

Required env:
  ARTIFACT_PATH

Optional env:
  PROOF_PATH
  VK_PATH
  MODE (default: minimal)
  RUN_SMOKE (default: 0)
  GLYPH_DA_BIN (default: target/release/glyph_da)
  RUN_ID (default: UTC timestamp)
  OUT_DIR_BASE (default: scripts/out/da/run-all)

Outputs:
  Submits or runs smoke tests for all DA profiles.

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
  local profile="$1"
  local out_dir="$2"
  echo "=== da_context ==="
  echo "mode=run_all"
  echo "profile=$profile"
  echo "run_id=$RUN_ID"
  echo "out_dir_base=$OUT_DIR_BASE"
  echo "out_dir=$out_dir"
  echo "artifact_path=$ARTIFACT_PATH"
  echo "proof_path=$PROOF_PATH"
  echo "vk_path=$VK_PATH"
  echo "profile_mode=$MODE"
  echo "run_smoke=$RUN_SMOKE"
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
ARTIFACT_PATH="${ARTIFACT_PATH:-}"
PROOF_PATH="${PROOF_PATH:-}"
VK_PATH="${VK_PATH:-}"
MODE="${MODE:-minimal}"
RUN_SMOKE="${RUN_SMOKE:-0}"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
OUT_DIR_BASE="${OUT_DIR_BASE:-$PROJECT_OUT/da/run-all}"

case "$MODE" in
    minimal|full)
        ;;
    *)
        echo "ERROR: unsupported MODE: $MODE (use minimal or full)" >&2
        exit 2
        ;;
esac

if [ -z "$ARTIFACT_PATH" ]; then
    echo "ERROR: ARTIFACT_PATH not set" >&2
    exit 2
fi
if [ ! -f "$ARTIFACT_PATH" ]; then
    echo "ERROR: ARTIFACT_PATH not found: $ARTIFACT_PATH" >&2
    exit 2
fi
if [ -n "$PROOF_PATH" ] && [ ! -f "$PROOF_PATH" ]; then
    echo "ERROR: PROOF_PATH not found: $PROOF_PATH" >&2
    exit 2
fi
if [ -n "$VK_PATH" ] && [ ! -f "$VK_PATH" ]; then
    echo "ERROR: VK_PATH not found: $VK_PATH" >&2
    exit 2
fi

if [ ! -x "$GLYPH_DA_BIN" ]; then
    require_cmd cargo
    echo "Building glyph_da..."
    cargo build --release --bin glyph_da
fi

PROFILES=(
    "verifier-only"
    "blob-only"
    "blob-arweave"
    "blob-eigenda-arweave"
)

for profile in "${PROFILES[@]}"; do
    echo "=== DA profile: ${profile} ==="
    if [ "$RUN_SMOKE" = "1" ]; then
        log_context "$profile" ""
        PROFILE="$profile" \
            ARTIFACT_PATH="$ARTIFACT_PATH" \
            PROOF_PATH="$PROOF_PATH" \
            VK_PATH="$VK_PATH" \
            MODE="$MODE" \
            GLYPH_DA_BIN="$GLYPH_DA_BIN" \
            "$PROJECT_ROOT/scripts/da/smoke_test.sh"
        continue
    fi

    out_dir="$OUT_DIR_BASE/$profile/$RUN_ID"
    mkdir -p "$out_dir"
    log_context "$profile" "$out_dir"
    args=(submit --profile "$profile" --mode "$MODE" --artifact "$ARTIFACT_PATH" --out-dir "$out_dir")
    if [ -n "$PROOF_PATH" ]; then
        args+=(--proof "$PROOF_PATH")
    fi
    if [ -n "$VK_PATH" ]; then
        args+=(--vk "$VK_PATH")
    fi
    "$GLYPH_DA_BIN" "${args[@]}"
done
