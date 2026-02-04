#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/profile_perf_config.sh

Optional env:
  PROJECT_OUT
  OUT_DIR
  PROFILE_OUT

Outputs:
  Writes perf_profile.json and perf_config_snapshot.json under OUT_DIR.

Exit codes:
  2 on missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
PROFILE_OUT="${PROFILE_OUT:-$OUT_DIR/perf_profile.json}"

mkdir -p "$OUT_DIR"
source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "profile_perf_config"
bench_log_basic
bench_log_kv "profile_out" "$PROFILE_OUT"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

require_cmd python3

echo "== Perf profile: state transition VM =="
"$PROJECT_ROOT/scripts/benchmarks/bench_state_transition_vm.sh" \
  --ops 1024 \
  --depth 16 \
  --iters 3 \
  --warmup 1 \
  --add-percent 50 \
  --seed 1

echo "== Perf profile: state diff merkle =="
bash "$PROJECT_ROOT/scripts/utils/ensure_state_diff_fixture.sh" "$PROJECT_ROOT/scripts/out/repro/inputs/state_diff_1m.bytes"
"$PROJECT_ROOT/scripts/benchmarks/bench_state_diff_merkle.sh" \
  --bytes "$PROJECT_ROOT/scripts/out/repro/inputs/state_diff_1m.bytes" \
  --iters 3 \
  --warmup 1

echo "== Perf profile: config snapshot =="
"$PROJECT_ROOT/scripts/utils/dump_perf_config.sh" "$OUT_DIR/perf_config_snapshot.json"

python3 - <<'PY' "$PROFILE_OUT" "$OUT_DIR"
import json
import os
import sys

profile_out = sys.argv[1]
out_dir = sys.argv[2]

def read_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

doc = {
    "perf_config": read_json(os.path.join(out_dir, "perf_config_snapshot.json")),
    "bench_state_transition_vm": read_json(os.path.join(out_dir, "state_transition_vm.json")),
    "bench_state_diff_merkle": read_json(os.path.join(out_dir, "state_diff_merkle.json")),
    "recommended_config": read_json(os.path.join(out_dir, "perf_config_snapshot.json")),
    "notes": [
        "recommended_config is derived from the measured run environment",
        "re-run with different env vars to generate alternative recommendations",
    ],
}

with open(profile_out, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2, sort_keys=True)
print(f"profile={profile_out}")
PY
