#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/tests/fuzz/run_all.sh [short|deep]

Optional env:
  GLYPH_FUZZ_PRESET (default: short)
  GLYPH_FUZZ_STARK (default: 0)
  GLYPH_FUZZ_SEED (optional, deterministic seed for libFuzzer)
  FUZZ_TIME_SHORT, FUZZ_TIME_STARK, FUZZ_TIME_DEEP
  FUZZ_OUT_DIR (default: scripts/out/tests/fuzz)
  GLYPH_FUZZ_DARWIN_FORCE (default: 0)

Outputs:
  Writes artifacts under scripts/out/tests/fuzz.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz/workspace"
OUT_DIR="${FUZZ_OUT_DIR:-$PROJECT_OUT/tests/fuzz}"
DICT_DIR="$PROJECT_ROOT/scripts/tests/fuzz/dicts"
PRESET="${1:-${GLYPH_FUZZ_PRESET:-short}}"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2025-09-15}"

CORE_TARGETS=(
  decode_adapter_bytes
  decode_adapter_ir_deep
  diff_adapter_ir_roundtrip
  verify_adapter_proof
  verify_packed_calldata
  decode_plonky2_receipt
  decode_ipa_receipt
  bn254_op_traces
  decode_r1cs_receipt
  decode_supernova_external_proof
  decode_stwo_profile
  decode_stwo_program
  synthesize_stwo_proof
)

STARK_TARGETS=(
  decode_stark_receipt
  decode_stark_vk
  decode_stark_ir
  decode_winterfell_program
  decode_circle_stark_program
  decode_circle_stark_proof
  decode_standard_stark_program
  decode_standard_stark_proof
)

TIME_SHORT="${FUZZ_TIME_SHORT:-60}"
TIME_STARK="${FUZZ_TIME_STARK:-60}"
TIME_DEEP="${FUZZ_TIME_DEEP:-240}"

require_cmd cargo
require_cmd cargo-fuzz

if [ "$(uname -s)" = "Darwin" ] && [ "${GLYPH_FUZZ_DARWIN_FORCE:-0}" != "1" ]; then
  echo "ERROR: macOS ASAN fuzz builds are currently unstable (binius_core linker failure)." >&2
  echo "Run on Linux, or set GLYPH_FUZZ_DARWIN_FORCE=1 to attempt anyway." >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

echo "=== fuzz_context ==="
echo "mode=run_all"
echo "preset=$PRESET"
echo "out_dir=$OUT_DIR"
echo "fuzz_dir=$FUZZ_DIR"
echo "dict_dir=$DICT_DIR"
echo "toolchain=$RUSTUP_TOOLCHAIN"
echo "seed=${GLYPH_FUZZ_SEED:-}"
echo "time_short=$TIME_SHORT"
echo "time_stark=$TIME_STARK"
echo "time_deep=$TIME_DEEP"
echo "fuzz_stark=$GLYPH_FUZZ_STARK"
echo ""

run_target() {
  local target="$1"
  local time_budget="$2"
  local dict_path="$3"
  local corpus_dir="$FUZZ_DIR/corpus/$target"
  local artifact_prefix="$OUT_DIR/${target}_"
  local features
  local feature_args=()

  features="$(features_for_target "$target")"
  if [ -n "$features" ]; then
    feature_args=(--features "$features")
  fi

  echo "== fuzz: $target (time=${time_budget}s) =="
  if [ ! -d "$corpus_dir" ]; then
    echo "ERROR: corpus not found: $corpus_dir" >&2
    exit 2
  fi
  if [ -n "$dict_path" ] && [ ! -f "$dict_path" ]; then
    echo "ERROR: dict not found: $dict_path" >&2
    exit 2
  fi

  local dict_args=()
  if [ -n "$dict_path" ]; then
    dict_args+=("-dict=$dict_path")
  fi
  local seed_args=()
  if [ -n "${GLYPH_FUZZ_SEED:-}" ]; then
    seed_args+=("-seed=${GLYPH_FUZZ_SEED}")
  fi

  (cd "$FUZZ_DIR" && cargo +"$RUSTUP_TOOLCHAIN" fuzz run --fuzz-dir "$FUZZ_DIR" \
    "${feature_args[@]}" "$target" "$corpus_dir" -- -max_total_time="$time_budget" \
    -artifact_prefix="$artifact_prefix" "${seed_args[@]}" "${dict_args[@]}")
}

features_for_target() {
  case "$1" in
    decode_plonky2_receipt)
      echo "stark-goldilocks"
      ;;
    decode_ipa_receipt)
      echo "snark"
      ;;
    decode_r1cs_receipt)
      echo "ivc"
      ;;
    decode_supernova_external_proof)
      echo "ivc,ivc-supernova"
      ;;
    decode_stwo_profile|decode_stwo_program)
      echo "stark-m31"
      ;;
    synthesize_stwo_proof)
      echo "stwo-prover"
      ;;
    decode_stark_receipt|decode_stark_vk|decode_stark_ir|decode_winterfell_program|decode_circle_stark_program|decode_circle_stark_proof|decode_standard_stark_program|decode_standard_stark_proof)
      echo "stark-goldilocks"
      ;;
    *)
      echo ""
      ;;
  esac
}

dict_for_core_target() {
  case "$1" in
    bn254_op_traces)
      echo ""
      ;;
    *)
      echo "$DICT_DIR/adapter_ir.dict"
      ;;
  esac
}

for target in "${CORE_TARGETS[@]}"; do
  run_target "$target" "$TIME_SHORT" "$(dict_for_core_target "$target")"
done

if [ "$PRESET" = "deep" ]; then
  for target in "${STARK_TARGETS[@]}"; do
    run_target "$target" "$TIME_DEEP" "$DICT_DIR/stark.dict"
  done
else
  if [ "${GLYPH_FUZZ_STARK:-0}" = "1" ]; then
    for target in "${STARK_TARGETS[@]}"; do
      run_target "$target" "$TIME_STARK" "$DICT_DIR/stark.dict"
    done
  else
    echo "Skipping STARK fuzz targets (GLYPH_FUZZ_STARK=0)."
  fi
fi
