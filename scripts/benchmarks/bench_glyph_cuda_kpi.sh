#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_cuda_kpi.sh

Optional env:
  TIMEOUT
  GLYPH_ENABLE_CUDA_BENCH
  GLYPH_CUDA_KPI_ALLOW_NO_NVCC
  GLYPH_CUDA_KPI_N
  GLYPH_CUDA_KPI_ROWS
  GLYPH_CUDA_KPI_COLS
  GLYPH_CUDA_KPI_HASHES
  GLYPH_CUDA_KPI_SEED
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

N="${GLYPH_CUDA_KPI_N:-1048576}"
ROWS="${GLYPH_CUDA_KPI_ROWS:-1024}"
COLS="${GLYPH_CUDA_KPI_COLS:-1024}"
HASHES="${GLYPH_CUDA_KPI_HASHES:-16384}"
SEED="${GLYPH_CUDA_KPI_SEED:-3235825150}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/glyph_cuda_kpi.json}"

mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_cuda_kpi"
require_cmd cargo

if [ "${GLYPH_ENABLE_CUDA_BENCH:-0}" != "1" ]; then
  die_input "CUDA benchmark disabled by default. Set GLYPH_ENABLE_CUDA_BENCH=1 to run."
fi

if ! command -v nvcc >/dev/null 2>&1; then
  if [ "${GLYPH_CUDA_KPI_ALLOW_NO_NVCC:-0}" != "1" ]; then
    die_input "nvcc not found. Set GLYPH_CUDA_KPI_ALLOW_NO_NVCC=1 to bypass."
  fi
  echo "WARN: nvcc not found, continuing because GLYPH_CUDA_KPI_ALLOW_NO_NVCC=1"
fi

bench_log_section "bench_context"
bench_log_kv "bench_name" "$BENCH_NAME"
bench_log_kv "n" "$N"
bench_log_kv "rows" "$ROWS"
bench_log_kv "cols" "$COLS"
bench_log_kv "hashes" "$HASHES"
bench_log_kv "seed" "$SEED"
bench_log_kv "out_file" "$OUT_FILE"
echo ""

run_cmd=(
  cargo run --release --features cuda --bin bench_glyph_cuda_kpi --
)

time_cmd="time"
time_args=()
if [ -x /usr/bin/time ]; then
  if /usr/bin/time -l true >/dev/null 2>&1; then
    time_cmd="/usr/bin/time"
    time_args=(-l)
  elif /usr/bin/time -v true >/dev/null 2>&1; then
    time_cmd="/usr/bin/time"
    time_args=(-v)
  fi
fi

if [ "$time_cmd" = "time" ]; then
  GLYPH_CUDA_KPI_N="$N" \
  GLYPH_CUDA_KPI_ROWS="$ROWS" \
  GLYPH_CUDA_KPI_COLS="$COLS" \
  GLYPH_CUDA_KPI_HASHES="$HASHES" \
  GLYPH_CUDA_KPI_SEED="$SEED" \
  time "${run_cmd[@]}" >"$OUT_FILE"
else
  GLYPH_CUDA_KPI_N="$N" \
  GLYPH_CUDA_KPI_ROWS="$ROWS" \
  GLYPH_CUDA_KPI_COLS="$COLS" \
  GLYPH_CUDA_KPI_HASHES="$HASHES" \
  GLYPH_CUDA_KPI_SEED="$SEED" \
  "$time_cmd" "${time_args[@]}" "${run_cmd[@]}" >"$OUT_FILE"
fi

cat "$OUT_FILE"
bench_finalize
