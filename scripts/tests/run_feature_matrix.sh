#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/tests/run_feature_matrix.sh [options]

Options:
  --matrix ci|extended|full   Preset matrix to run (default: ci)
  --profile NAME             Cargo profile for builds (default: release-fast)
  --with-tests               Run default test suite after matrix builds
  --dry-run                  Print commands without executing
  -h, --help                 Show this help text

Key env:
  GLYPH_MATRIX_CUDA          Set to 1 to include the cuda preset
  GLYPH_MATRIX_REQUIRE_CUDA  Set to 1 to fail if cuda is requested but unavailable
  GLYPH_MATRIX_REQUIRE_FULL  Set to 1 to fail if full preset is skipped
  GLYPH_MATRIX_FULL_MIN_KB   Minimum free disk KB required for full preset (default: 2000000)
  GLYPH_MATRIX_CLEAN_BEFORE_TESTS  Set to 0 to skip `cargo clean` before --with-tests
  RUN_ID                     Shared run id for metadata output (default: timestamp)

Notes:
  - The matrix uses scripts/build/ci_deterministic_run.sh for reproducible logging.
  - CI builds cover a subset of presets by design. Extended and full presets are opt-in.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

MATRIX="ci"
PROFILE="release-fast"
WITH_TESTS=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --matrix)
            MATRIX="${2:-}"
            shift 2
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --with-tests)
            WITH_TESTS=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
require_cmd bash

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
export RUN_ID

CI_PRESETS=(default snark ivc hash binius stark-babybear stark-goldilocks stark-m31)
EXTENDED_PRESETS=(core full)
CUDA_PRESETS=(cuda)
FULL_MIN_KB="${GLYPH_MATRIX_FULL_MIN_KB:-2000000}"

PRESETS=()
case "$MATRIX" in
    ci)
        PRESETS=("${CI_PRESETS[@]}")
        ;;
    extended)
        PRESETS=("${CI_PRESETS[@]}" "${EXTENDED_PRESETS[@]}")
        ;;
    full)
        PRESETS=("${CI_PRESETS[@]}" "${EXTENDED_PRESETS[@]}" "${CUDA_PRESETS[@]}")
        ;;
    *)
        echo "ERROR: unknown matrix: $MATRIX" >&2
        exit 2
        ;;
esac

can_run_cuda() {
    if [ "${GLYPH_MATRIX_CUDA:-0}" != "1" ]; then
        return 1
    fi
    if [ "${NVCC:-}" = "disabled" ]; then
        return 1
    fi
    if ! command -v nvcc >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

available_kb() {
    df -k "$PROJECT_ROOT" | awk 'NR==2 {print $4}'
}

can_run_full() {
    local avail
    avail="$(available_kb)"
    if [ -z "$avail" ]; then
        return 1
    fi
    if [ "$avail" -ge "$FULL_MIN_KB" ]; then
        return 0
    fi
    return 1
}

run_preset() {
    local preset="$1"
    local cmd="scripts/build/ci_deterministic_run.sh --preset ${preset} --cmd build --profile ${PROFILE}"
    if [ "$DRY_RUN" = "1" ]; then
        echo "DRY RUN: $cmd"
        return 0
    fi
    bash scripts/build/ci_deterministic_run.sh --preset "${preset}" --cmd build --profile "${PROFILE}"
}

echo "Matrix: $MATRIX"
echo "Profile: $PROFILE"
echo "Run ID: $RUN_ID"
echo "With tests: $WITH_TESTS"

for preset in "${PRESETS[@]}"; do
    if [ "$preset" = "cuda" ]; then
        if ! can_run_cuda; then
            if [ "${GLYPH_MATRIX_REQUIRE_CUDA:-0}" = "1" ]; then
                echo "ERROR: cuda preset requested but unavailable (set GLYPH_MATRIX_CUDA=1 and ensure nvcc is present)" >&2
                exit 2
            fi
            echo "Skipping cuda preset. Set GLYPH_MATRIX_CUDA=1 to enable."
            continue
        fi
    fi
    if [ "$preset" = "full" ]; then
        if ! can_run_full; then
            if [ "${GLYPH_MATRIX_REQUIRE_FULL:-0}" = "1" ]; then
                echo "ERROR: full preset skipped due to low disk space (need ${FULL_MIN_KB} KB free)" >&2
                exit 2
            fi
            echo "Skipping full preset due to low disk space. Set GLYPH_MATRIX_REQUIRE_FULL=1 to enforce."
            continue
        fi
    fi
    run_preset "$preset"
done

if [ "$WITH_TESTS" = "1" ]; then
    if [ "${GLYPH_MATRIX_CLEAN_BEFORE_TESTS:-1}" = "1" ]; then
        require_cmd cargo
        cargo clean
    fi
    TEST_CMD="scripts/build/ci_deterministic_run.sh --preset default --cmd test --profile ${PROFILE}"
    if [ "$DRY_RUN" = "1" ]; then
        echo "DRY RUN: $TEST_CMD"
    else
        bash scripts/build/ci_deterministic_run.sh --preset default --cmd test --profile "${PROFILE}"
    fi
fi

echo "Feature matrix complete."
