#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/repro/repro_pack.sh

Env:
  PROJECT_OUT   Base output directory (default: ./scripts/out)
  OUT_DIR       Output directory (default: $PROJECT_OUT/repro)
  INPUT_DIR     Input directory (default: $OUT_DIR/inputs)
  MANIFEST      Manifest output path (default: $OUT_DIR/manifest.json)

Outputs:
  Manifest JSON at $MANIFEST plus benchmark outputs under scripts/out/benchmarks.

Exit codes:
  2 on missing tools.
  1 on runtime failure.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

require_cmd python3

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/repro}"
INPUT_DIR="${INPUT_DIR:-$OUT_DIR/inputs}"
MANIFEST="${MANIFEST:-$OUT_DIR/manifest.json}"

mkdir -p "$OUT_DIR" "$INPUT_DIR"

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_commit="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
rustc_ver="$(rustc -V 2>/dev/null || echo "rustc-unavailable")"
cargo_ver="$(cargo -V 2>/dev/null || echo "cargo-unavailable")"
platform="$(uname -a 2>/dev/null || echo "unknown")"

STATE_DIFF_BYTES="$INPUT_DIR/state_diff_1m.bytes"
if [ ! -f "$STATE_DIFF_BYTES" ]; then
  python3 - <<'PY' "$STATE_DIFF_BYTES"
import os
import sys

path = sys.argv[1]
seed = 1
size = 1024 * 1024
data = bytearray(size)
val = seed & 0xff
for i in range(size):
    data[i] = val
    val = (val * 1103515245 + 12345) & 0xff
with open(path, "wb") as handle:
    handle.write(data)
PY
fi

BENCH_LIST="$(mktemp)"
SKIP_LIST="$(mktemp)"
trap 'rm -f "$BENCH_LIST" "$SKIP_LIST"' EXIT

echo "== Repro Pack: state transition VM =="
"$PROJECT_ROOT/scripts/benchmarks/bench_state_transition_vm.sh" \
  --ops 1024 \
  --depth 16 \
  --iters 5 \
  --warmup 1 \
  --add-percent 50 \
  --seed 1
echo "$PROJECT_ROOT/scripts/out/benchmarks/state_transition_vm.json" >> "$BENCH_LIST"

echo "== Repro Pack: state diff merkle =="
"$PROJECT_ROOT/scripts/benchmarks/bench_state_diff_merkle.sh" \
  --bytes "$STATE_DIFF_BYTES" \
  --iters 5 \
  --warmup 1
echo "$PROJECT_ROOT/scripts/out/benchmarks/state_diff_merkle.json" >> "$BENCH_LIST"

echo "== Repro Pack: perf config snapshot =="
bash "$PROJECT_ROOT/scripts/utils/dump_perf_config.sh" \
  "$PROJECT_ROOT/scripts/out/benchmarks/perf_config.json"
echo "$PROJECT_ROOT/scripts/out/benchmarks/perf_config.json" >> "$BENCH_LIST"

if command -v forge >/dev/null 2>&1 && command -v anvil >/dev/null 2>&1 && command -v cast >/dev/null 2>&1; then
  echo "== Repro Pack: GLYPHVerifier gas (local Anvil) =="
  set +e
  bash "$PROJECT_ROOT/scripts/benchmarks/bench_glyph_evm_local.sh"
  bench_status=$?
  set -e
  if [ -f "$PROJECT_ROOT/scripts/out/benchmarks/bench_glyph_evm_local.json" ]; then
    echo "$PROJECT_ROOT/scripts/out/benchmarks/bench_glyph_evm_local.json" >> "$BENCH_LIST"
    bench_status=0
  fi
  if [ "$bench_status" -ne 0 ]; then
    echo "bench_glyph_evm_local (run failed, status=$bench_status)" >> "$SKIP_LIST"
  fi
else
  echo "bench_glyph_evm_local (missing foundry binaries: forge/anvil/cast)" >> "$SKIP_LIST"
fi

python3 - <<'PY' "$MANIFEST" "$timestamp" "$git_commit" "$rustc_ver" "$cargo_ver" "$platform" "$STATE_DIFF_BYTES" "$BENCH_LIST" "$SKIP_LIST"
import hashlib
import json
import os
import sys

manifest = sys.argv[1]
timestamp = sys.argv[2]
git_commit = sys.argv[3]
rustc_ver = sys.argv[4]
cargo_ver = sys.argv[5]
platform = sys.argv[6]
state_diff_path = sys.argv[7]
bench_list = sys.argv[8]
skip_list = sys.argv[9]

bench_outs = []
if os.path.exists(bench_list):
    with open(bench_list, "r", encoding="utf-8") as handle:
        bench_outs = [line.strip() for line in handle if line.strip()]

skipped = []
if os.path.exists(skip_list):
    with open(skip_list, "r", encoding="utf-8") as handle:
        skipped = [line.strip() for line in handle if line.strip()]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

inputs = []
if os.path.exists(state_diff_path):
    inputs.append({
        "path": os.path.abspath(state_diff_path),
        "sha256": sha256_file(state_diff_path),
        "size": os.path.getsize(state_diff_path),
    })

outputs = []
for path in bench_outs:
    if not path:
        continue
    if not os.path.exists(path):
        continue
    outputs.append({
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "size": os.path.getsize(path),
    })

doc = {
    "timestamp": timestamp,
    "git_commit": git_commit,
    "rustc": rustc_ver,
    "cargo": cargo_ver,
    "platform": platform,
    "inputs": inputs,
    "outputs": outputs,
    "skipped": skipped,
}

with open(manifest, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2, sort_keys=True)
print(f"manifest={manifest}")
PY
