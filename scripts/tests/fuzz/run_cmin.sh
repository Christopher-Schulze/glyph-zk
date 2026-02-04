#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/tests/fuzz/run_cmin.sh <target> <corpus_dir> <out_dir>

Optional env:
  RUSTUP_TOOLCHAIN (default: nightly-2025-09-15)

Outputs:
  Writes minimized corpus to out_dir.

Exit codes:
  2 on missing args or missing tools.
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

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz/workspace"
TARGET="${1:-}"
CORPUS_DIR="${2:-}"
OUT_DIR="${3:-}"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2025-09-15}"

if [ -z "$TARGET" ] || [ -z "$CORPUS_DIR" ] || [ -z "$OUT_DIR" ]; then
  usage >&2
  exit 2
fi
if [ ! -d "$CORPUS_DIR" ]; then
  echo "ERROR: corpus_dir not found: $CORPUS_DIR" >&2
  exit 2
fi

require_cmd cargo
require_cmd cargo-fuzz

mkdir -p "$OUT_DIR"

echo "=== fuzz_context ==="
echo "mode=cmin"
echo "target=$TARGET"
echo "corpus_dir=$CORPUS_DIR"
echo "out_dir=$OUT_DIR"
echo "toolchain=$RUSTUP_TOOLCHAIN"
echo ""

(cd "$FUZZ_DIR" && cargo +"$RUSTUP_TOOLCHAIN" fuzz cmin --fuzz-dir "$FUZZ_DIR" "$TARGET" "$CORPUS_DIR" "$OUT_DIR")
