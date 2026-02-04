#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_ivc_parallel_profile.sh

Optional env:
  TIMEOUT
  THREADS_LIST
  GLYPH_IVC_KPI_NVARS
  GLYPH_IVC_KPI_REPEAT
  GLYPH_IVC_KPI_FOLD_REPEAT
  GLYPH_IVC_KPI_RECEIPTS
  GLYPH_IVC_KPI_SEED
  OUT_DIR
  OUT_JSONL
  OUT_FILE

Outputs:
  Writes JSONL to OUT_JSONL and bench_v1 JSON to OUT_FILE.

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
OUT_JSONL="${OUT_JSONL:-$OUT_DIR/ivc_parallel_profile.jsonl}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/ivc_parallel_profile.json}"
THREADS_LIST="${THREADS_LIST:-1 2 4 8 12 16}"

NVARS="${GLYPH_IVC_KPI_NVARS:-16}"
REPEAT="${GLYPH_IVC_KPI_REPEAT:-5}"
FOLD_REPEAT="${GLYPH_IVC_KPI_FOLD_REPEAT:-5}"
RECEIPTS="${GLYPH_IVC_KPI_RECEIPTS:-16}"
SEED="${GLYPH_IVC_KPI_SEED:-glyph-ivc-kpi}"

mkdir -p "$(dirname "$OUT_FILE")"
: > "$OUT_JSONL"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "ivc_parallel_profile"
require_cmd cargo
require_cmd python3

bench_log_basic
bench_log_kv "out_jsonl" "$OUT_JSONL"
bench_log_kv "threads" "$THREADS_LIST"
bench_log_kv "n_vars" "$NVARS"
bench_log_kv "repeat" "$REPEAT"
bench_log_kv "fold_repeat" "$FOLD_REPEAT"
bench_log_kv "receipts" "$RECEIPTS"
bench_log_kv "seed" "$SEED"

cargo build --release --bin bench_ivc_fold_kpi

for threads in $THREADS_LIST; do
  echo "threads=$threads"
  result=$(
    RAYON_NUM_THREADS="$threads" \
    GLYPH_IVC_KPI_NVARS="$NVARS" \
    GLYPH_IVC_KPI_REPEAT="$REPEAT" \
    GLYPH_IVC_KPI_FOLD_REPEAT="$FOLD_REPEAT" \
    GLYPH_IVC_KPI_RECEIPTS="$RECEIPTS" \
    GLYPH_IVC_KPI_SEED="$SEED" \
    target/release/bench_ivc_fold_kpi
  )
  line="$(python3 - <<'PY' "$result" "$threads"
import json
import re
import sys

raw = sys.argv[1]
threads = int(sys.argv[2])
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    match = re.search(r"(\\{.*\\})", raw, re.DOTALL)
    if not match:
        raise SystemExit("bench_ivc_fold_kpi did not emit JSON")
    data = json.loads(match.group(1))
data["threads"] = threads
print(json.dumps(data, sort_keys=True))
PY
)"
  printf '%s\n' "$line" >> "$OUT_JSONL"
done

python3 - <<'PY' "$OUT_JSONL" "$OUT_FILE" "$THREADS_LIST" "$NVARS" "$REPEAT" "$FOLD_REPEAT" "$RECEIPTS"
import json, sys
data = []
for line in open(sys.argv[1], "r", encoding="utf-8"):
  line = line.strip()
  if not line:
    continue
  data.append(json.loads(line))
doc = {
  "cases": data,
  "threads": sys.argv[3],
  "n_vars": int(sys.argv[4]),
  "repeat": int(sys.argv[5]),
  "fold_repeat": int(sys.argv[6]),
  "receipts": int(sys.argv[7]),
}
json.dump(doc, open(sys.argv[2], "w", encoding="utf-8"), indent=2, sort_keys=True)
PY

bench_finalize
