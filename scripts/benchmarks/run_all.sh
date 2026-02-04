#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  BENCH_PRESET=local scripts/benchmarks/run_all.sh
  scripts/benchmarks/run_all.sh <preset>

Optional env:
  OUT_DIR (default: scripts/out/benchmarks)
  FAIL_FAST (default: 0)
  RPC_URL (required for presets with requires_rpc=1)
  GLYPH_ENABLE_CUDA_BENCH=1 (opt-in to CUDA benches; legacy RUN_CUDA_BENCH)

Outputs:
  Per-benchmark JSON under OUT_DIR.

Exit codes:
  2 on invalid input or missing registry.
  1 on runtime failure when FAIL_FAST=1.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
REGISTRY="$PROJECT_ROOT/scripts/benchmarks/registry.json"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"

PRESET="${1:-${BENCH_PRESET:-local}}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
FAIL_FAST="${FAIL_FAST:-0}"
GLYPH_ENABLE_CUDA_BENCH="${GLYPH_ENABLE_CUDA_BENCH:-${RUN_CUDA_BENCH:-0}}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"

if [ ! -f "$REGISTRY" ]; then
  die_input "registry not found: $REGISTRY"
fi

require_cmd python3

mkdir -p "$OUT_DIR"
bench_log_section "bench_context"
bench_log_kv "preset" "$PRESET"
bench_log_kv "out_dir" "$OUT_DIR"
bench_log_kv "run_id" "$RUN_ID"
bench_log_kv "fail_fast" "$FAIL_FAST"
bench_log_kv "enable_cuda" "$GLYPH_ENABLE_CUDA_BENCH"

readarray -t entries < <(python3 - <<'PY' "$REGISTRY" "$PRESET"
import json, sys
path = sys.argv[1]
preset = sys.argv[2]
data = json.load(open(path, "r", encoding="utf-8"))
for item in data.get("benchmarks", []):
  if item.get("preset") == preset:
    print("{}|{}|{}".format(item["name"], item["script"], int(item.get("requires_rpc", False))))
PY
)

if [ "${#entries[@]}" -eq 0 ]; then
  die_input "no benchmarks found for preset: $PRESET"
fi

printf "%-40s %-8s %-12s\n" "bench" "status" "out"
printf "%-40s %-8s %-12s\n" "-----" "------" "------"

validate_bench_output() {
  local out_path="$1"
  python3 - <<'PY' "$out_path"
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
if data.get("schema_version") != "bench_v1":
    sys.exit(2)
sys.exit(0)
PY
}

for entry in "${entries[@]}"; do
  IFS="|" read -r name script requires_rpc <<< "$entry"
  if [ "$GLYPH_ENABLE_CUDA_BENCH" != "1" ]; then
    if [[ "$name" == *"cuda"* || "$script" == *"cuda"* ]]; then
      printf "%-40s %-8s %-12s\n" "$name" "skipped" "cuda_disabled"
      continue
    fi
  fi
  if [ "$requires_rpc" = "1" ] && [ -z "${RPC_URL:-}" ]; then
    printf "%-40s %-8s %-12s\n" "$name" "skipped" "no_rpc"
    continue
  fi

  out_file="$OUT_DIR/${name}.json"
  status="ok"
  if [ ! -f "$PROJECT_ROOT/scripts/benchmarks/$script" ]; then
    status="missing"
    if [ "$FAIL_FAST" = "1" ]; then
      printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
      exit 1
    fi
    printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
    continue
  fi
  if ! OUT_DIR="$OUT_DIR" OUT_FILE="$out_file" RUN_ID="$RUN_ID" "$PROJECT_ROOT/scripts/benchmarks/$script"; then
    status="fail"
    if [ "$FAIL_FAST" = "1" ]; then
      printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
      exit 1
    fi
  fi
  if [ ! -f "$out_file" ]; then
    status="missing_output"
    if [ "$FAIL_FAST" = "1" ]; then
      printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
      exit 1
    fi
  elif [ ! -s "$out_file" ]; then
    status="empty"
    rm -f "$out_file" "${out_file}.meta.json"
    if [ "$FAIL_FAST" = "1" ]; then
      printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
      exit 1
    fi
  else
    if ! validate_bench_output "$out_file"; then
      status="invalid_output"
      if [ "$FAIL_FAST" = "1" ]; then
        printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
        exit 1
      fi
    fi
  fi
  printf "%-40s %-8s %-12s\n" "$name" "$status" "$(basename "$out_file")"
done
