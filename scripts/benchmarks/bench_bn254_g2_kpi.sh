#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_bn254_g2_kpi.sh

Optional env:
  BN254_G2_KPI_ITERS
  BN254_G2_KPI_SEED
  BN254_G2_KPI_WINDOW_MIN
  BN254_G2_KPI_WINDOW_MAX
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
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
cd "$PROJECT_ROOT"

BN254_G2_KPI_ITERS=${BN254_G2_KPI_ITERS:-64}
BN254_G2_KPI_SEED=${BN254_G2_KPI_SEED:-0x4d782e55b8a40c21}
BN254_G2_KPI_WINDOW_MIN=${BN254_G2_KPI_WINDOW_MIN:-2}
BN254_G2_KPI_WINDOW_MAX=${BN254_G2_KPI_WINDOW_MAX:-6}
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/bn254_g2_kpi.json}"
mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "bn254_g2_kpi"
require_cmd cargo

bench_log_basic
bench_log_kv "iters" "$BN254_G2_KPI_ITERS"
bench_log_kv "seed" "$BN254_G2_KPI_SEED"
bench_log_kv "window_min" "$BN254_G2_KPI_WINDOW_MIN"
bench_log_kv "window_max" "$BN254_G2_KPI_WINDOW_MAX"

BN254_G2_KPI_ITERS="$BN254_G2_KPI_ITERS" \
BN254_G2_KPI_SEED="$BN254_G2_KPI_SEED" \
BN254_G2_KPI_WINDOW_MIN="$BN254_G2_KPI_WINDOW_MIN" \
BN254_G2_KPI_WINDOW_MAX="$BN254_G2_KPI_WINDOW_MAX" \
cargo run --release --bin bench_bn254_g2_kpi -- | tee "$OUT_FILE"
bench_finalize
