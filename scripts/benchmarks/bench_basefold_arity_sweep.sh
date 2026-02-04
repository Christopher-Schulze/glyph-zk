#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_basefold_arity_sweep.sh

Optional env:
  TIMEOUT
  ARITIES
  SECURITY_BITS
  LOG_INV_RATE
  LOG_INV_RATES
  N_VARS
  SEED
  REPEAT
  CHAINID
  CONTRACT
  OUT_DIR
  OUT_BASE
  OUT_INDEX

Outputs:
  Writes per-arity JSON under OUT_BASE and a bench_v1 index at OUT_INDEX.

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

ARITIES="${ARITIES:-2 4 8}"
SECURITY_BITS="${SECURITY_BITS:-${GLYPH_PCS_BASEFOLD_SECURITY_BITS:-96}}"
LOG_INV_RATE="${LOG_INV_RATE:-${GLYPH_PCS_BASEFOLD_LOG_INV_RATE:-2}}"
LOG_INV_RATES="${LOG_INV_RATES:-}"
N_VARS="${N_VARS:-${GLYPH_BASEFOLD_BENCH_N_VARS:-16}}"
SEED="${GLYPH_ZK_KPI_SEED:-2779096485}"
REPEAT="${GLYPH_ZK_KPI_REPEAT:-1}"
CHAINID="${GLYPH_ZK_KPI_CHAINID:-31337}"
CONTRACT="${GLYPH_ZK_KPI_CONTRACT:-0x1111111111111111111111111111111111111111}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_BASE="${OUT_BASE:-$OUT_DIR/basefold_arity_sweep}"
OUT_INDEX="${OUT_INDEX:-$OUT_BASE/index.json}"

mkdir -p "$OUT_BASE"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "basefold_arity_sweep"
OUT_FILE="$OUT_INDEX"
OUT_META="${OUT_INDEX}.meta.json"
require_cmd cargo
require_cmd python3
bench_log_basic
bench_log_kv "arities" "$ARITIES"
bench_log_kv "security_bits" "$SECURITY_BITS"
if [ -n "$LOG_INV_RATES" ]; then
  bench_log_kv "log_inv_rates" "$LOG_INV_RATES"
else
  bench_log_kv "log_inv_rate" "$LOG_INV_RATE"
fi
bench_log_kv "n_vars" "$N_VARS"
bench_log_kv "seed" "$SEED"
bench_log_kv "repeat" "$REPEAT"
bench_log_kv "chainid" "$CHAINID"
bench_log_kv "contract" "$CONTRACT"
bench_log_kv "out_base" "$OUT_BASE"
bench_log_kv "out_index" "$OUT_INDEX"

run_cmd=(cargo run --release --bin bench_basefold_pcs --)

index_tmp="$OUT_INDEX.tmp"
echo "[" >"$index_tmp"
first=1
had_fail=0
if [ -n "$LOG_INV_RATES" ]; then
  for log_rate in $LOG_INV_RATES; do
    for arity in $ARITIES; do
      echo "== arity=$arity log_inv_rate=$log_rate =="
      out_file="$OUT_BASE/arity_${arity}_log_${log_rate}.json"
      status=0
      env_cmd=(
        "GLYPH_PCS_BASEFOLD_FOLD_ARITY=$arity"
        "GLYPH_PCS_BASEFOLD_SECURITY_BITS=$SECURITY_BITS"
        "GLYPH_PCS_BASEFOLD_LOG_INV_RATE=$log_rate"
        "GLYPH_BASEFOLD_BENCH_N_VARS=$N_VARS"
        "GLYPH_ZK_KPI_SEED=$SEED"
        "GLYPH_ZK_KPI_REPEAT=$REPEAT"
        "GLYPH_ZK_KPI_CHAINID=$CHAINID"
        "GLYPH_ZK_KPI_CONTRACT=$CONTRACT"
      )
      if ! env "${env_cmd[@]}" "${run_cmd[@]}" >"$out_file"; then
        status=$?
      fi
      if [ "$status" -ne 0 ]; then
        had_fail=1
      fi
      if [ $first -eq 0 ]; then
        echo "," >>"$index_tmp"
      fi
      first=0
      cat <<EOF >>"$index_tmp"
  {
    "fold_arity": $arity,
    "security_bits": $SECURITY_BITS,
    "log_inv_rate": $log_rate,
    "file": "$(basename "$out_file")",
    "status": $status
  }
EOF
    done
  done
else
  for arity in $ARITIES; do
    echo "== arity=$arity =="
    out_file="$OUT_BASE/arity_${arity}.json"
    status=0
    env_cmd=(
      "GLYPH_PCS_BASEFOLD_FOLD_ARITY=$arity"
      "GLYPH_PCS_BASEFOLD_SECURITY_BITS=$SECURITY_BITS"
      "GLYPH_PCS_BASEFOLD_LOG_INV_RATE=$LOG_INV_RATE"
      "GLYPH_BASEFOLD_BENCH_N_VARS=$N_VARS"
      "GLYPH_ZK_KPI_SEED=$SEED"
      "GLYPH_ZK_KPI_REPEAT=$REPEAT"
      "GLYPH_ZK_KPI_CHAINID=$CHAINID"
      "GLYPH_ZK_KPI_CONTRACT=$CONTRACT"
    )
    if ! env "${env_cmd[@]}" "${run_cmd[@]}" >"$out_file"; then
      status=$?
    fi
    if [ "$status" -ne 0 ]; then
      had_fail=1
    fi
    if [ $first -eq 0 ]; then
      echo "," >>"$index_tmp"
    fi
    first=0
    cat <<EOF >>"$index_tmp"
  {
    "fold_arity": $arity,
    "security_bits": $SECURITY_BITS,
    "log_inv_rate": $LOG_INV_RATE,
    "file": "$(basename "$out_file")",
    "status": $status
  }
EOF
  done
fi
echo "]" >>"$index_tmp"
python3 - "$index_tmp" "$OUT_INDEX" "$OUT_BASE" <<'PY'
import json, sys

tmp_path, out_path, out_dir = sys.argv[1:]
cases = json.load(open(tmp_path, "r", encoding="utf-8"))
doc = {"cases": cases, "out_dir": out_dir}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2, sort_keys=True)
PY
rm -f "$index_tmp"
bench_finalize
if [ "$had_fail" -ne 0 ]; then
  exit 1
fi
