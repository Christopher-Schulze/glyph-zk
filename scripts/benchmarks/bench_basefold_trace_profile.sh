#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_basefold_trace_profile.sh

Optional env:
  TIMEOUT
  SECURITY_BITS
  LOG_INV_RATE
  FOLD_ARITY
  SMALL_N_VARS
  LARGE_N_VARS
  SEED
  OUT_DIR

Outputs:
  Writes small.json, large.json, logs, and bench_v1 index under OUT_DIR.

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

SECURITY_BITS="${SECURITY_BITS:-128}"
LOG_INV_RATE="${LOG_INV_RATE:-2}"
FOLD_ARITY="${FOLD_ARITY:-}"
SMALL_N_VARS="${SMALL_N_VARS:-13}"
LARGE_N_VARS="${LARGE_N_VARS:-16}"
SEED="${GLYPH_BASEFOLD_BENCH_SEED:-2779096485}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks/basefold_trace_profile}"
OUT_INDEX="${OUT_INDEX:-$OUT_DIR/index.json}"

mkdir -p "$OUT_DIR"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "basefold_trace_profile"
OUT_FILE="$OUT_INDEX"
OUT_META="${OUT_INDEX}.meta.json"
require_cmd cargo
bench_log_basic
bench_log_kv "security_bits" "$SECURITY_BITS"
bench_log_kv "log_inv_rate" "$LOG_INV_RATE"
bench_log_kv "fold_arity" "${FOLD_ARITY:-default}"
bench_log_kv "small_n_vars" "$SMALL_N_VARS"
bench_log_kv "large_n_vars" "$LARGE_N_VARS"
bench_log_kv "seed" "$SEED"
bench_log_kv "out_dir" "$OUT_DIR"
bench_log_kv "out_index" "$OUT_INDEX"

run_cmd=(cargo run --release --bin bench_basefold_pcs --)
FOLD_ARITY_ENV=()
if [ -n "$FOLD_ARITY" ]; then
  FOLD_ARITY_ENV=(GLYPH_PCS_BASEFOLD_FOLD_ARITY="$FOLD_ARITY")
fi

echo "== small =="
env \
  GLYPH_PCS_BASEFOLD_TRACE=1 \
  GLYPH_PCS_BASEFOLD_SECURITY_BITS="$SECURITY_BITS" \
  GLYPH_PCS_BASEFOLD_LOG_INV_RATE="$LOG_INV_RATE" \
  "${FOLD_ARITY_ENV[@]}" \
  GLYPH_BASEFOLD_BENCH_N_VARS="$SMALL_N_VARS" \
  GLYPH_BASEFOLD_BENCH_SEED="$SEED" \
  GLYPH_BASEFOLD_BENCH_LABEL="small" \
  "${run_cmd[@]}" >"$OUT_DIR/small.json" 2>"$OUT_DIR/small.log"

echo "== large =="
env \
  GLYPH_PCS_BASEFOLD_TRACE=1 \
  GLYPH_PCS_BASEFOLD_SECURITY_BITS="$SECURITY_BITS" \
  GLYPH_PCS_BASEFOLD_LOG_INV_RATE="$LOG_INV_RATE" \
  "${FOLD_ARITY_ENV[@]}" \
  GLYPH_BASEFOLD_BENCH_N_VARS="$LARGE_N_VARS" \
  GLYPH_BASEFOLD_BENCH_SEED="$SEED" \
  GLYPH_BASEFOLD_BENCH_LABEL="large" \
  "${run_cmd[@]}" >"$OUT_DIR/large.json" 2>"$OUT_DIR/large.log"

cat >"$OUT_INDEX" <<EOF
{
  "cases": [
    {"label": "small", "file": "small.json", "log": "small.log"},
    {"label": "large", "file": "large.json", "log": "large.log"}
  ],
  "out_dir": "$OUT_DIR"
}
EOF
bench_finalize
