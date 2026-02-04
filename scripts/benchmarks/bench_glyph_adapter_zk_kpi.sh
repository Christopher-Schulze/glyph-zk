#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_adapter_zk_kpi.sh

Optional env:
  TIMEOUT
  GLYPH_ADAPTER_ZK_KPI
  GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_IC_WINDOW
  GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_PRECOMP
  GLYPH_ADAPTER_ZK_KPI_KZG_BN254_PRECOMP
  GLYPH_ADAPTER_ZK_KPI_STARK_F64
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

ADAPTERS="${GLYPH_ADAPTER_ZK_KPI:-all}"
GROTH16_WINDOW="${GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_IC_WINDOW:-4}"
GROTH16_PRECOMP="${GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_PRECOMP:-1}"
KZG_PRECOMP="${GLYPH_ADAPTER_ZK_KPI_KZG_BN254_PRECOMP:-1}"
STARK_F64="${GLYPH_ADAPTER_ZK_KPI_STARK_F64:-0}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/glyph_adapter_zk_kpi.json}"

mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_adapter_zk_kpi"
require_cmd cargo

bench_log_basic
bench_log_kv "adapters" "$ADAPTERS"
bench_log_kv "groth16_window" "$GROTH16_WINDOW"
bench_log_kv "groth16_precomp" "$GROTH16_PRECOMP"
bench_log_kv "kzg_precomp" "$KZG_PRECOMP"
bench_log_kv "stark_f64" "$STARK_F64"

run_cmd=(
  cargo run --release --bin bench_glyph_adapter_zk_kpi --
)

GLYPH_ADAPTER_ZK_KPI="$ADAPTERS" \
GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_IC_WINDOW="$GROTH16_WINDOW" \
GLYPH_ADAPTER_ZK_KPI_GROTH16_BN254_PRECOMP="$GROTH16_PRECOMP" \
GLYPH_ADAPTER_ZK_KPI_KZG_BN254_PRECOMP="$KZG_PRECOMP" \
GLYPH_ADAPTER_ZK_KPI_STARK_F64="$STARK_F64" \
  "${run_cmd[@]}" | tee "$OUT_FILE"
bench_finalize
