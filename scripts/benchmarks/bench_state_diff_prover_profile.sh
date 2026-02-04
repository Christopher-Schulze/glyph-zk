#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$PROJECT_ROOT/scripts/benchmarks/common.sh"

PROVER_BIN="${PROVER_BIN:-$PROJECT_ROOT/target/release/glyph_state_diff_prove}"
MERKLE_BENCH_BIN="${MERKLE_BENCH_BIN:-$PROJECT_ROOT/target/release/bench_state_diff_merkle}"

BYTES_PATH=""
MODE="fast"
RUNS="1"
MERKLE_ITERS="10"
MERKLE_WARMUP="2"
PROVER_WARMUP="1"

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_state_diff_prover_profile.sh --bytes <file> [--mode fast|zk] [--runs <n>] [--merkle-iters <n>] [--merkle-warmup <n>] [--prover-warmup <n>]

Outputs:
  Writes bench_v1 JSON to OUT_FILE plus intermediate JSON files in OUT_DIR.

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
    --runs) RUNS="$2"; shift 2 ;;
    --merkle-iters) MERKLE_ITERS="$2"; shift 2 ;;
    --merkle-warmup) MERKLE_WARMUP="$2"; shift 2 ;;
    --prover-warmup) PROVER_WARMUP="$2"; shift 2 ;;
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

bench_init "state_diff_prover_profile"
require_cmd cargo
require_cmd python3
bench_log_basic
bench_log_kv "prover_bin" "$PROVER_BIN"
bench_log_kv "merkle_bench_bin" "$MERKLE_BENCH_BIN"
bench_log_kv "bytes_path" "$BYTES_PATH"
bench_log_kv "mode" "$MODE"
bench_log_kv "runs" "$RUNS"
bench_log_kv "merkle_iters" "$MERKLE_ITERS"
bench_log_kv "merkle_warmup" "$MERKLE_WARMUP"
bench_log_kv "prover_warmup" "$PROVER_WARMUP"

if [ ! -x "$PROVER_BIN" ]; then
  echo "Building glyph_state_diff_prove..."
  cargo build --release --bin glyph_state_diff_prove
fi
if [ ! -x "$MERKLE_BENCH_BIN" ]; then
  echo "Building bench_state_diff_merkle..."
  cargo build --release --bin bench_state_diff_merkle
fi

MERKLE_JSON="$OUT_DIR/state_diff_merkle_profile.json"
PROVER_JSON="$OUT_DIR/state_diff_prove_profile.json"

"$MERKLE_BENCH_BIN" --bytes "$BYTES_PATH" --iters "$MERKLE_ITERS" --warmup "$MERKLE_WARMUP" --json > "$MERKLE_JSON"

python3 - <<PY
import json, time, subprocess, sys

bytes_path = "$BYTES_PATH"
mode = "$MODE"
runs = int("$RUNS")
warmup = int("$PROVER_WARMUP")
prover_bin = "$PROVER_BIN"
out_path = "$PROVER_JSON"

times = []
for _ in range(warmup):
    subprocess.run([prover_bin, "--bytes", bytes_path, "--mode", mode, "--json"], check=True, stdout=subprocess.DEVNULL)
for _ in range(runs):
    start = time.perf_counter()
    subprocess.run([prover_bin, "--bytes", bytes_path, "--mode", mode, "--json"], check=True, stdout=subprocess.DEVNULL)
    end = time.perf_counter()
    times.append((end - start) * 1000.0)

data = {
    "bytes": len(open(bytes_path, "rb").read()),
    "mode": mode,
    "runs": runs,
    "warmup": warmup,
    "total_ms": sum(times),
    "avg_ms": sum(times) / runs if runs else 0.0,
    "min_ms": min(times) if times else 0.0,
    "max_ms": max(times) if times else 0.0,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PY

python3 - <<PY
import json

with open("$MERKLE_JSON", "r", encoding="utf-8") as f:
    merkle = json.load(f)
with open("$PROVER_JSON", "r", encoding="utf-8") as f:
    prover = json.load(f)

merkle_ms = float(merkle.get("per_iter_ms", 0.0))
prover_ms = float(prover.get("avg_ms", 0.0))
ratio = (merkle_ms / prover_ms) if prover_ms else 0.0

out = {
    "bytes": merkle.get("bytes"),
    "mode": prover.get("mode"),
    "runs": prover.get("runs"),
    "merkle_per_iter_ms": merkle_ms,
    "prover_avg_ms": prover_ms,
    "merkle_share": ratio,
    "merkle_profile": merkle,
    "prover_profile": prover
}
with open("$OUT_FILE", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
PY

bench_finalize
echo "bench_out=$OUT_FILE"
