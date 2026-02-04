#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/formal/sumcheck_invariants.sh

Purpose:
  Run the sumcheck interpolation invariants in a dedicated Rust crate.

Outputs:
  Prints "sumcheck invariants ok" on success.

Exit codes:
  1 if cargo is missing or the check fails.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
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

require_cmd cargo

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo run --quiet --manifest-path "$ROOT_DIR/scripts/formal/sumcheck_invariants/Cargo.toml"
