#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/tests/fuzz/run_tmin.sh <target> <input_file> <out_file>

Optional env:
  RUSTUP_TOOLCHAIN (default: nightly-2025-09-15)

Outputs:
  Writes minimized input to out_file.

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
INPUT_FILE="${2:-}"
OUT_FILE="${3:-}"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2025-09-15}"

if [ -z "$TARGET" ] || [ -z "$INPUT_FILE" ] || [ -z "$OUT_FILE" ]; then
  usage >&2
  exit 2
fi
if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: input_file not found: $INPUT_FILE" >&2
  exit 2
fi

require_cmd cargo
require_cmd cargo-fuzz

mkdir -p "$(dirname "$OUT_FILE")"

echo "=== fuzz_context ==="
echo "mode=tmin"
echo "target=$TARGET"
echo "input_file=$INPUT_FILE"
echo "out_file=$OUT_FILE"
echo "toolchain=$RUSTUP_TOOLCHAIN"
echo ""

(cd "$FUZZ_DIR" && cargo +"$RUSTUP_TOOLCHAIN" fuzz tmin --fuzz-dir "$FUZZ_DIR" "$TARGET" "$INPUT_FILE" "$OUT_FILE")
