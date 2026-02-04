#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_basefold_mem_sweetspot.sh

Optional env:
  TIMEOUT
  MEM_LIST
  SECURITY_BITS
  LOG_INV_RATE
  FOLD_ARITY
  N_VARS
  SEED
  OUT_DIR
  OUT_INDEX

Outputs:
  Writes per-mem JSON under OUT_DIR and a bench_v1 index at OUT_INDEX.

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

MEM_LIST="${MEM_LIST:-64 128 256 512 1024}"
SECURITY_BITS="${SECURITY_BITS:-128}"
LOG_INV_RATE="${LOG_INV_RATE:-2}"
FOLD_ARITY="${FOLD_ARITY:-}"
N_VARS="${N_VARS:-16}"
SEED="${GLYPH_BASEFOLD_BENCH_SEED:-2779096485}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks/basefold_mem_sweetspot}"
OUT_INDEX="${OUT_INDEX:-$OUT_DIR/index.json}"

mkdir -p "$OUT_DIR"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "basefold_mem_sweetspot"
OUT_FILE="$OUT_INDEX"
OUT_META="${OUT_INDEX}.meta.json"
require_cmd cargo
require_cmd python3
bench_log_basic
bench_log_kv "mem_list" "$MEM_LIST"
bench_log_kv "security_bits" "$SECURITY_BITS"
bench_log_kv "log_inv_rate" "$LOG_INV_RATE"
bench_log_kv "fold_arity" "${FOLD_ARITY:-default}"
bench_log_kv "n_vars" "$N_VARS"
bench_log_kv "seed" "$SEED"
bench_log_kv "out_dir" "$OUT_DIR"
bench_log_kv "out_index" "$OUT_INDEX"

run_cmd=(cargo run --release --bin bench_basefold_pcs --)

index_tmp="$OUT_INDEX.tmp"
echo "[" >"$index_tmp"
first=1
had_fail=0
for mem in $MEM_LIST; do
  mem_bytes=$((mem * 1024 * 1024))
  out_file="$OUT_DIR/mem_${mem}MiB.json"
  echo "== mem=${mem}MiB =="
  status=0
  env_cmd=(
    "GLYPH_PCS_BASEFOLD_SECURITY_BITS=$SECURITY_BITS"
    "GLYPH_PCS_BASEFOLD_LOG_INV_RATE=$LOG_INV_RATE"
    "GLYPH_PCS_BASEFOLD_HOST_MEM=$mem_bytes"
    "GLYPH_PCS_BASEFOLD_DEV_MEM=$mem_bytes"
    "GLYPH_BASEFOLD_BENCH_N_VARS=$N_VARS"
    "GLYPH_BASEFOLD_BENCH_SEED=$SEED"
  )
  if [ -n "$FOLD_ARITY" ]; then
    env_cmd+=("GLYPH_PCS_BASEFOLD_FOLD_ARITY=$FOLD_ARITY")
  fi
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
    "mem_mib": $mem,
    "security_bits": $SECURITY_BITS,
    "log_inv_rate": $LOG_INV_RATE,
    "fold_arity": "${FOLD_ARITY:-default}",
    "file": "$(basename "$out_file")",
    "status": $status
  }
EOF
done
echo "]" >>"$index_tmp"
python3 - "$index_tmp" "$OUT_INDEX" "$OUT_DIR" <<'PY'
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
