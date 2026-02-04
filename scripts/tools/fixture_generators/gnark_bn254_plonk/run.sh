#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/tools/fixture_generators/gnark_bn254_plonk/run.sh

Outputs:
  scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt

Exit codes:
  2 on missing tools.
  1 on runtime failure.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_PATH="$ROOT_DIR/scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_cmd go
mkdir -p "$(dirname "$OUT_PATH")"

(
    cd "$SCRIPT_DIR"
    go run . -out "$OUT_PATH"
)
