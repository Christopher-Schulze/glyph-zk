#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/tests/verifier_symbolic.sh

Optional env:
  FOUNDRY_FUZZ_RUNS (default: 1024)
  FOUNDRY_INVARIANT_RUNS (default: 256)
  OUT_DIR (default: scripts/out/formal)

Outputs:
  Writes glyph_verifier_fuzz.log under OUT_DIR.

Exit codes:
  2 on missing tools.
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
  echo "=== test_context ==="
  echo "mode=verifier_symbolic"
  echo "out_dir=$OUT_DIR"
  echo "foundry_fuzz_runs=$FOUNDRY_FUZZ_RUNS"
  echo "foundry_invariant_runs=$FOUNDRY_INVARIANT_RUNS"
  echo ""
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/formal}"
mkdir -p "$OUT_DIR"

require_cmd forge

export FOUNDRY_FUZZ_RUNS="${FOUNDRY_FUZZ_RUNS:-1024}"
export FOUNDRY_INVARIANT_RUNS="${FOUNDRY_INVARIANT_RUNS:-256}"
log_context

cd "$PROJECT_ROOT/scripts/tests/foundry"

echo "== GLYPHVerifier symbolic fuzz run =="
forge test --match-contract GLYPHVerifierTest -vv | tee "$OUT_DIR/glyph_verifier_fuzz.log"
