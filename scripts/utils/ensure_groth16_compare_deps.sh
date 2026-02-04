#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/utils/ensure_groth16_compare_deps.sh

Ensures local Node dependencies for the Groth16 compare bench are installed.

Behavior:
  - Prefers bun if available.
  - Falls back to npm if bun is missing.
  - Installs in scripts/benchmarks/groth16_compare/.

Exit codes:
  2 on missing tools or missing package.json.
  1 on install failure.
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$ROOT_DIR/scripts/benchmarks/groth16_compare"

if [ ! -f "$TARGET_DIR/package.json" ]; then
  echo "ERROR: missing package.json at $TARGET_DIR" >&2
  exit 2
fi

if [ -d "$TARGET_DIR/node_modules" ]; then
  exit 0
fi

if require_cmd bun; then
  if [ -f "$TARGET_DIR/bun.lock" ]; then
    (cd "$TARGET_DIR" && bun install --frozen-lockfile)
    exit 0
  fi
  (cd "$TARGET_DIR" && bun install)
  exit 0
fi

if require_cmd npm; then
  if [ -f "$TARGET_DIR/package-lock.json" ]; then
    (cd "$TARGET_DIR" && npm ci)
    exit 0
  fi
  (cd "$TARGET_DIR" && npm install)
  exit 0
fi

echo "ERROR: bun or npm required to install groth16_compare dependencies" >&2
exit 2
