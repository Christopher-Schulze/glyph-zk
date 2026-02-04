#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/utils/dump_perf_config.sh [output-path]

Env:
  PROJECT_OUT   Base output directory (default: ./scripts/out)

Outputs:
  Writes perf_config.json to the output path.

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
OUT_PATH="${1:-$PROJECT_OUT/perf/perf_config.json}"

mkdir -p "$(dirname "$OUT_PATH")"

python3 - <<'PY' "$OUT_PATH"
import json
import os
import sys

out_path = sys.argv[1]
keys = [
    "GLYPH_PCS_MASK_ROWS",
    "GLYPH_SUMCHECK_PAGED",
    "GLYPH_PCS_RING_SWITCH_PAR_MIN",
    "GLYPH_PCS_BASEFOLD_SECURITY_BITS",
    "GLYPH_PCS_BASEFOLD_LOG_INV_RATE",
    "GLYPH_PCS_BASEFOLD_HOST_MEM",
    "GLYPH_PCS_BASEFOLD_DEV_MEM",
    "GLYPH_PCS_BASEFOLD_FOLD_ARITY",
    "GLYPH_PCS_BASEFOLD_TRACE",
    "GLYPH_PCS_BASEFOLD_CPU_ONLY",
    "GLYPH_PCS_BASEFOLD_PAR_MIN",
    "GLYPH_CUDA",
    "GLYPH_CUDA_DEBUG",
    "GLYPH_CUDA_PTX",
    "GLYPH_CUDA_MIN_ELEMS",
    "GLYPH_CUDA_BN254_MIN_ELEMS",
    "GLYPH_CUDA_PINNED_HOST",
    "GLYPH_STARK_MIN_SECURITY",
    "GLYPH_CIRCLE_STARK_PAR_MIN",
    "GLYPH_STANDARD_STARK_PAR_MIN",
    "GLYPH_STWO_PAR_MIN",
    "GLYPH_BN254_SIMD",
    "GLYPH_BN254_MUL_MONT",
    "GLYPH_BN254_PAR_MIN",
    "GLYPH_BN254_WITNESS_BATCH",
    "GLYPH_BN254_WITNESS_BATCH_MIN",
    "GLYPH_WITNESS_WATCHERS_MAX_EDGES",
    "GLYPH_WITNESS_WATCHER_FANOUT",
    "GLYPH_KECCAK_X4",
    "GLYPH_KZG_BN254_TRACE_G2S_PRECOMP",
    "GLYPH_KZG_BN254_TRACE_STATS",
    "GLYPH_GROTH16_BN254_TRACE_STATS",
    "GLYPH_GROTH16_BN254_TRACE_IC_PRECOMP",
    "GLYPH_BN254_FIXED_BASE_PRECOMP",
    "GLYPH_BN254_KZG_JOINT_MSM",
    "GLYPH_BN254_IC_PRECOMP_AUTO",
    "GLYPH_BN254_G2_PRECOMP_AUTO",
    "GLYPH_BN254_TRACE_VALIDATE_BATCH",
    "GLYPH_BN254_SCALAR_WINDOW",
    "GLYPH_BN254_SCALAR_MUL",
    "GLYPH_BN254_WNAF_SLOW",
    "GLYPH_BN254_MSM_GLV",
    "GLYPH_BN254_MSM_WINDOW",
    "GLYPH_BN254_MSM_SMALL_THRESHOLD",
    "GLYPH_BN254_MSM_PRECOMP_THRESHOLD",
    "GLYPH_BN254_MSM_SHAMIR",
    "GLYPH_PROFILE_VERSION",
    "GLYPH_ACCEL_PROFILE",
    "GLYPH_BN254_PROVER_CORE",
    "GLYPH_GROTH16_BN254_PROFILE",
    "GLYPH_KZG_BN254_PROFILE",
    "GLYPH_IVC_PROFILE",
    "GLYPH_STARK_PROFILE",
    "GLYPH_HASH_PROFILE",
    "GLYPH_SP1_PROFILE",
    "GLYPH_PLONK_PROFILE",
]

payload = {key: os.environ.get(key) for key in keys}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)

print(f"perf_config={out_path}")
PY
