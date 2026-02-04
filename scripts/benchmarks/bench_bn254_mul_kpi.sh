#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_bn254_mul_kpi.sh

Optional env:
  TIMEOUT
  ADD_N
  SUB_N
  MUL_N
  SEED
  GLYPH_BN254_SIMD
  GLYPH_BN254_MUL_MONT
  OUT_DIR
  OUT_FILE

Outputs:
  Writes bench_v1 JSON to OUT_FILE.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

# Stabilize terminal size in non-interactive shells to avoid "bogus screen size" warnings.
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if [ -t 1 ]; then
  stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

TIMEOUT="${TIMEOUT:-0}"

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
cd "$PROJECT_ROOT"

TIMEOUT_PID=""
if [ "${TIMEOUT}" -gt 0 ]; then
    (sleep "$TIMEOUT" && echo "FATAL: Timeout ($TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
    TIMEOUT_PID=$!
    trap "if [ -n "${TIMEOUT_PID:-}" ]; then kill $TIMEOUT_PID 2>/dev/null; fi" EXIT
fi

ADD_N="${ADD_N:-100000}"
SUB_N="${SUB_N:-100000}"
MUL_N="${MUL_N:-50000}"
SEED="${SEED:-0x5a173d2f9a4ce1b3}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/bn254_mul_kpi.json}"
mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "bn254_mul_kpi"
require_cmd cargo

export GLYPH_BN254_MUL_KPI_ADD="$ADD_N"
export GLYPH_BN254_MUL_KPI_SUB="$SUB_N"
export GLYPH_BN254_MUL_KPI_MUL="$MUL_N"
export GLYPH_BN254_MUL_KPI_SEED="$SEED"

bench_log_basic
bench_log_kv "add_n" "$ADD_N"
bench_log_kv "sub_n" "$SUB_N"
bench_log_kv "mul_n" "$MUL_N"
bench_log_kv "seed" "$SEED"
bench_log_kv "simd" "${GLYPH_BN254_SIMD:-auto}"
bench_log_kv "mul_mont" "${GLYPH_BN254_MUL_MONT:-auto}"

cargo run --release --bin bench_bn254_mul_kpi | tee "$OUT_FILE"
bench_finalize
