#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_ivc_fold_kpi.sh

Optional env:
  TIMEOUT
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

export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if command -v stty >/dev/null 2>&1; then
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

OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/ivc_fold_kpi.json}"

mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "ivc_fold_kpi"
require_cmd cargo

bench_log_basic
bench_log_kv "timeout" "$TIMEOUT"

run_cmd=(
  cargo run --release --bin bench_ivc_fold_kpi
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
  time "${run_cmd[@]}" >"$OUT_FILE"
else
  "$time_cmd" "${time_args[@]}" "${run_cmd[@]}" >"$OUT_FILE"
fi

cat "$OUT_FILE"
bench_finalize
