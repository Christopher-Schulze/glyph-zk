#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$PROJECT_ROOT/scripts/benchmarks/common.sh"

BENCH_BIN="${BENCH_BIN:-$PROJECT_ROOT/target/release/bench_state_diff_compile_prove}"
BYTES_PATH=""
MODE="fast"
WARMUP="1"

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_state_diff_compile_prove.sh --bytes <file> [--mode fast|zk] [--warmup <n>]

Outputs:
  Writes bench_v1 JSON to OUT_FILE.

Exit codes:
  2 on invalid input.
  1 on runtime failure.
USAGE
}

die() {
  echo "ERROR: $1" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bytes) BYTES_PATH="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

if [ -z "$BYTES_PATH" ]; then
  usage
  exit 2
fi
if [ ! -f "$BYTES_PATH" ]; then
  die "bytes not found: $BYTES_PATH"
fi
if [ "$MODE" != "fast" ] && [ "$MODE" != "zk" ]; then
  die "mode must be fast or zk"
fi

bench_init "state_diff_compile_prove"
require_cmd cargo
bench_log_basic
bench_log_kv "bench_bin" "$BENCH_BIN"
bench_log_kv "bytes_path" "$BYTES_PATH"
bench_log_kv "mode" "$MODE"
bench_log_kv "warmup" "$WARMUP"

if [ ! -x "$BENCH_BIN" ]; then
  echo "Building bench_state_diff_compile_prove..."
  cargo build --release --bin bench_state_diff_compile_prove
fi

"$BENCH_BIN" --bytes "$BYTES_PATH" --mode "$MODE" --warmup "$WARMUP" --json > "$OUT_FILE"
bench_finalize
echo "bench_out=$OUT_FILE"
