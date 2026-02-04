#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$PROJECT_ROOT/scripts/benchmarks/common.sh"

BENCH_BIN="${BENCH_BIN:-$PROJECT_ROOT/target/release/bench_state_transition_vm}"
OPS="${OPS:-1024}"
DEPTH="${DEPTH:-16}"
ITERS="${ITERS:-5}"
WARMUP="${WARMUP:-1}"
ADD_PERCENT="${ADD_PERCENT:-50}"
SEED="${SEED:-1}"
COMPILE="${COMPILE:-1}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_state_transition_vm.sh [--ops <n>] [--depth <n>] [--iters <n>] [--warmup <n>] [--add-percent <n>] [--seed <n>] [--no-compile]

Outputs:
  Writes bench_v1 JSON to OUT_FILE.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ops) OPS="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    --iters) ITERS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --add-percent) ADD_PERCENT="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --no-compile) COMPILE="0"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown arg: $1" >&2; exit 2 ;;
  esac
done

bench_init "state_transition_vm"
require_cmd cargo
bench_log_basic
bench_log_kv "bench_bin" "$BENCH_BIN"
bench_log_kv "ops" "$OPS"
bench_log_kv "depth" "$DEPTH"
bench_log_kv "iters" "$ITERS"
bench_log_kv "warmup" "$WARMUP"
bench_log_kv "add_percent" "$ADD_PERCENT"
bench_log_kv "seed" "$SEED"
bench_log_kv "compile" "$COMPILE"

if [ ! -x "$BENCH_BIN" ]; then
  echo "Building bench_state_transition_vm..."
  cargo build --release --bin bench_state_transition_vm
fi

ARGS=(--ops "$OPS" --depth "$DEPTH" --iters "$ITERS" --warmup "$WARMUP" --add-percent "$ADD_PERCENT" --seed "$SEED" --json)
if [ "$COMPILE" = "0" ]; then
  ARGS+=(--no-compile)
fi

"$BENCH_BIN" "${ARGS[@]}" > "$OUT_FILE"
bench_finalize
echo "bench_out=$OUT_FILE"
