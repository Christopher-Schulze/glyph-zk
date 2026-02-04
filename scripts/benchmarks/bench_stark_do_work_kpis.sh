#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_stark_do_work_kpis.sh

Optional env:
  TIMEOUT
  START
  TRACE_LENGTH
  SHA3
  F64
  SEED
  RECEIPTS
  GLYPH_ARTIFACT
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

START="${START:-3}"
TRACE_LENGTH="${TRACE_LENGTH:-1024}"
SHA3="${SHA3:-0}"
F64="${F64:-0}"
SEED="${SEED:-}"
RECEIPTS="${RECEIPTS:-1}"
GLYPH_ARTIFACT="${GLYPH_ARTIFACT:-0}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/stark_do_work_kpis.json}"

mkdir -p "$(dirname "$OUT_FILE")"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "stark_do_work_kpis"
require_cmd cargo

bench_log_basic
bench_log_kv "start" "$START"
bench_log_kv "trace_length" "$TRACE_LENGTH"
bench_log_kv "sha3" "$SHA3"
bench_log_kv "f64" "$F64"
bench_log_kv "receipts" "$RECEIPTS"
bench_log_kv "glyph_artifact" "$GLYPH_ARTIFACT"
bench_log_kv "seed" "${SEED:-}"

run_cmd=(
  cargo run --release --bin stark_do_work_kpis --
    --start "$START"
    --trace-length "$TRACE_LENGTH"
    --json
)
if [ "$SHA3" = "1" ]; then
  run_cmd+=(--sha3)
  if [ -n "$SEED" ]; then
    run_cmd+=(--seed "$SEED")
  fi
  run_cmd+=(--receipts "$RECEIPTS")
  if [ "$GLYPH_ARTIFACT" = "1" ]; then
    run_cmd+=(--glyph-artifact)
  fi
fi
if [ "$F64" = "1" ]; then
  run_cmd+=(--f64)
fi

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
