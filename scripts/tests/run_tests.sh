#!/bin/bash
# GLYPH Test Suite Runner
# Usage: ./scripts/tests/run_tests.sh [options]

set -euo pipefail

EXIT_INVALID_INPUT=2
EXIT_RUNTIME=1

usage() {
    cat <<'USAGE'
Usage:
  scripts/tests/run_tests.sh

Key env:
  STEP_TIMEOUT, TOTAL_TIMEOUT
  GLYPH_DISABLE_TIMEOUTS (default: 1)
  GLYPH_TEST_PROFILE (release|release-fast|debug)
  GLYPH_SKIP_FUZZ (default: 1)
  GLYPH_FULL_TESTS (default: 1)
  GLYPH_TEST_FEATURES
  GLYPH_TEST_NO_DEFAULT (default: 0)
  GLYPH_TEST_SUPERNOVA (default: 1)
  GLYPH_TEST_STWO_PROVER (default: 1)
  GLYPH_FUZZ_STARK
  GLYPH_FUZZ_SEED
  GLYPH_FUZZ_SOFT_FAIL (default: 0)
  GLYPH_E2E_INCLUDE_SP1
  FUZZ_TIME, FUZZ_TARGETS

Outputs:
  Writes logs to scripts/out/tests/run_tests.log and fuzz logs under scripts/out/tests/fuzz.

Exit codes:
  2 on missing tools.
  1 on runtime failure.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit "$EXIT_INVALID_INPUT"
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

# Stabilize terminal size to avoid "bogus screen size" warnings.
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if [ -t 1 ]; then
    stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

# Timeout in seconds (default off)
STEP_TIMEOUT="${STEP_TIMEOUT:-9600}"
TOTAL_TIMEOUT="${TOTAL_TIMEOUT:-28800}"

require_cmd cargo

TIMEOUT_PID=""
if [ "${GLYPH_DISABLE_TIMEOUTS:-1}" = "0" ]; then
    # Kill script after total timeout
    (sleep "$TOTAL_TIMEOUT" && echo "FATAL: Total timeout ($TOTAL_TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
    TIMEOUT_PID=$!
    trap "if [ -n \"${TIMEOUT_PID:-}\" ]; then kill $TIMEOUT_PID 2>/dev/null; fi" EXIT
fi

# Helper: run command with step timeout
run_with_timeout() {
    if [ "${GLYPH_DISABLE_TIMEOUTS:-1}" = "1" ]; then
        "$@"
        return
    fi
    if command -v timeout &>/dev/null; then
        timeout "$STEP_TIMEOUT" "$@"
    elif command -v gtimeout &>/dev/null; then
        gtimeout "$STEP_TIMEOUT" "$@"
    else
        "$@"
    fi
}

# Helper: run cargo with optional vendor-warning suppression
VENDOR_WARN_FILTER="${VENDOR_WARN_FILTER:-/vendor/|binius_core|binius_m3|forge-std}"
run_cargo() {
    if [ "${GLYPH_SUPPRESS_VENDOR_WARNINGS:-0}" = "1" ]; then
        run_with_timeout "$@" 2> >(grep -v -E "$VENDOR_WARN_FILTER" >&2)
    else
        run_with_timeout "$@"
    fi
}

run_cargo_no_timeout() {
    if [ "${GLYPH_SUPPRESS_VENDOR_WARNINGS:-0}" = "1" ]; then
        "$@" 2> >(grep -v -E "$VENDOR_WARN_FILTER" >&2)
    else
        "$@"
    fi
}

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/tests}"
OUT_LOG="${OUT_LOG:-$OUT_DIR/run_tests.log}"
FUZZ_OUT_DIR="${FUZZ_OUT_DIR:-$OUT_DIR/fuzz}"
GLYPH_DISABLE_TIMEOUTS="${GLYPH_DISABLE_TIMEOUTS:-1}"
GLYPH_SKIP_FUZZ="${GLYPH_SKIP_FUZZ:-1}"
GLYPH_FULL_TESTS="${GLYPH_FULL_TESTS:-1}"
GLYPH_FUZZ_STARK="${GLYPH_FUZZ_STARK:-0}"
GLYPH_TEST_FEATURES_DEFAULT="snark,ivc,hash,stark-babybear,stark-goldilocks,stark-m31,binius"
GLYPH_TEST_FEATURES="${GLYPH_TEST_FEATURES:-$GLYPH_TEST_FEATURES_DEFAULT}"
GLYPH_TEST_NO_DEFAULT="${GLYPH_TEST_NO_DEFAULT:-0}"
GLYPH_TEST_SUPERNOVA="${GLYPH_TEST_SUPERNOVA:-1}"
GLYPH_TEST_STWO_PROVER="${GLYPH_TEST_STWO_PROVER:-1}"
GLYPH_FUZZ_SOFT_FAIL="${GLYPH_FUZZ_SOFT_FAIL:-0}"
OS_NAME="$(uname -s)"

if [ -z "${GLYPH_TEST_PROFILE+x}" ]; then
    if [ "$OS_NAME" = "Darwin" ]; then
        GLYPH_TEST_PROFILE="release-fast"
    elif [ "$OS_NAME" = "Linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
        GLYPH_TEST_PROFILE="release-fast"
    else
        GLYPH_TEST_PROFILE="release"
    fi
fi

case "$GLYPH_TEST_PROFILE" in
    release)
        CARGO_PROFILE_FLAG=(--release)
        ;;
    release-fast)
        CARGO_PROFILE_FLAG=(--profile release-fast)
        ;;
    debug)
        CARGO_PROFILE_FLAG=()
        ;;
    *)
        echo "Error: Unsupported GLYPH_TEST_PROFILE=$GLYPH_TEST_PROFILE (use release, release-fast, or debug)"
        exit "$EXIT_INVALID_INPUT"
        ;;
esac

# Default to CPU max performance, keep CUDA optional via env override.
export GLYPH_ACCEL_PROFILE="${GLYPH_ACCEL_PROFILE:-cpu}"
export GLYPH_BN254_SIMD="${GLYPH_BN254_SIMD:-1}"
export GLYPH_BN254_MUL_MONT="${GLYPH_BN254_MUL_MONT:-1}"
export NVCC="${NVCC:-disabled}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2025-09-15}"

mkdir -p "$(dirname "$OUT_LOG")"
exec > >(tee "$OUT_LOG") 2>&1
cd "$PROJECT_ROOT"

echo -e "${YELLOW}=== GLYPH TEST SUITE ===${NC}"
echo "=== test_context ==="
echo "root=$PROJECT_ROOT"
echo "out_log=$OUT_LOG"
echo "fuzz_out_dir=$FUZZ_OUT_DIR"
echo "profile=$GLYPH_TEST_PROFILE"
echo "full_tests=$GLYPH_FULL_TESTS"
echo "skip_fuzz=$GLYPH_SKIP_FUZZ"
echo "fuzz_stark=$GLYPH_FUZZ_STARK"
echo "test_features=$GLYPH_TEST_FEATURES"
echo "test_no_default=$GLYPH_TEST_NO_DEFAULT"
echo "toolchain=$RUSTUP_TOOLCHAIN"
echo ""
echo "Root: $PROJECT_ROOT"
echo "Profile: $GLYPH_TEST_PROFILE"
echo ""

# 1. Rust Unit & Integration Tests
TEST_NO_DEFAULT_FLAG=()
if [ "$GLYPH_TEST_NO_DEFAULT" = "1" ]; then
    TEST_NO_DEFAULT_FLAG+=(--no-default-features)
fi
DEV_FEATURES="dev-tools"
if [ "$GLYPH_TEST_NO_DEFAULT" = "1" ]; then
    DEV_FEATURES="dev-tools,${GLYPH_TEST_FEATURES}"
fi
echo -e "${YELLOW}[1/4] Running Rust Tests (dev-tools enabled)...${NC}"
# We skip doc tests to focus on logic, release mode for performance on heavy crypto
if run_cargo cargo test "${CARGO_PROFILE_FLAG[@]}" "${TEST_NO_DEFAULT_FLAG[@]}" --features "$DEV_FEATURES" --lib --bins --tests; then
    echo -e "${GREEN}✓ Rust tests passed${NC}"
else
    echo -e "${RED}✗ Rust tests failed (or timeout after ${STEP_TIMEOUT}s)${NC}"
    exit 1
fi

echo ""

FULL_FEATURES="dev-tools,${GLYPH_TEST_FEATURES}"
RUN_FULL_TESTS="$GLYPH_FULL_TESTS"
if [ "$GLYPH_TEST_NO_DEFAULT" = "1" ]; then
    RUN_FULL_TESTS=0
fi

# 1b. Rust Unit & Integration Tests with full adapter features
if [ "$RUN_FULL_TESTS" = "1" ]; then
    echo -e "${YELLOW}[1b/4] Running Rust Tests (full adapter features)...${NC}"
    if run_cargo cargo test "${CARGO_PROFILE_FLAG[@]}" "${TEST_NO_DEFAULT_FLAG[@]}" --features "$FULL_FEATURES" --lib --bins --tests; then
        echo -e "${GREEN}OK: Rust tests (full features) passed${NC}"
    else
        echo -e "${RED}FAILED: Rust tests (full features) failed (or timeout after ${STEP_TIMEOUT}s)${NC}"
        exit 1
    fi
    echo ""
else
    echo -e "${YELLOW}Skipping full adapter test pass (GLYPH_FULL_TESTS=0)${NC}"
    echo ""
fi

if [ "$GLYPH_TEST_SUPERNOVA" = "1" ]; then
    echo -e "${YELLOW}[1c/4] Running IVC SuperNova tests...${NC}"
    if run_cargo cargo test "${CARGO_PROFILE_FLAG[@]}" --no-default-features \
        --features "adapter-core,ivc,ivc-supernova,dev-tools" --test ivc_supernova_tests; then
        echo -e "${GREEN}OK: IVC SuperNova tests passed${NC}"
    else
        echo -e "${RED}FAILED: IVC SuperNova tests failed (or timeout after ${STEP_TIMEOUT}s)${NC}"
        exit 1
    fi
    echo ""
else
    echo -e "${YELLOW}Skipping IVC SuperNova tests (GLYPH_TEST_SUPERNOVA=0)${NC}"
    echo ""
fi

if [ "$GLYPH_TEST_STWO_PROVER" = "1" ]; then
    echo -e "${YELLOW}[1d/4] Running Stwo Prover tests...${NC}"
    if run_cargo cargo test "${CARGO_PROFILE_FLAG[@]}" --no-default-features \
        --features "adapter-core,stwo-prover,dev-tools" --test stwo_prover_tests; then
        echo -e "${GREEN}OK: Stwo Prover tests passed${NC}"
    else
        echo -e "${RED}FAILED: Stwo Prover tests failed (or timeout after ${STEP_TIMEOUT}s)${NC}"
        exit 1
    fi
    echo ""
else
    echo -e "${YELLOW}Skipping Stwo Prover tests (GLYPH_TEST_STWO_PROVER=0)${NC}"
    echo ""
fi

# 2. Generate/Update Solidity Test Vectors from Rust
# This ensures Foundry tests run against the latest Rust prover logic
echo -e "${YELLOW}[2/4] Updating Solidity Test Vectors...${NC}"
E2E_FEATURES=(--features snark,ivc,hash,stark-babybear,stark-goldilocks,stark-m31,binius)

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_solidity_tests -- --nocapture; then
     echo -e "${GREEN}✓ Solidity vectors updated (GeneratedRealProofTest.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update solidity vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_stark_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_STARK_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update Stark V4 vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_hash_merge_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_HASH_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update hash vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_ivc_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_IVC_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update IVC vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_snark_groth16_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_SNARK_GROTH16_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update Groth16 vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_snark_kzg_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_SNARK_KZG_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update KZG vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_snark_ipa_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_SNARK_IPA_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update IPA vectors${NC}"
     exit 1
fi

if [ "${GLYPH_E2E_INCLUDE_SP1:-0}" = "1" ]; then
    if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_snark_sp1_vectors -- --nocapture; then
        echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_SNARK_SP1_Test.t.sol)${NC}"
    else
         echo -e "${RED}✗ Failed to update SP1 vectors${NC}"
         exit 1
    fi
else
    echo -e "${YELLOW}Skipping SNARK SP1 vectors (GLYPH_E2E_INCLUDE_SP1=0)${NC}"
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_snark_plonk_vectors -- --nocapture; then
    echo -e "${GREEN}✓ Solidity vectors updated (GLYPH_SNARK_PLONK_Test.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update PLONK vectors${NC}"
     exit 1
fi

if run_cargo_no_timeout cargo test "${CARGO_PROFILE_FLAG[@]}" "${E2E_FEATURES[@]}" --package glyph --lib e2e_proofs::tests::test_export_glyph_verifier_vectors -- --nocapture; then
     echo -e "${GREEN}✓ Solidity vectors updated (GLYPHVerifierTest.t.sol)${NC}"
else
     echo -e "${RED}✗ Failed to update GLYPHVerifier vectors${NC}"
     exit 1
fi
echo ""

# 3. Foundry Tests (Solidity)
echo -e "${YELLOW}[3/4] Running Foundry Tests...${NC}"
FOUNDRY_OUT="${FOUNDRY_OUT:-$PROJECT_ROOT/scripts/out/foundry}"
FOUNDRY_CACHE_PATH="${FOUNDRY_CACHE_PATH:-$PROJECT_ROOT/scripts/out/foundry-cache}"
export FOUNDRY_OUT
export FOUNDRY_CACHE_PATH
mkdir -p "$FOUNDRY_OUT" "$FOUNDRY_CACHE_PATH"
cd "$PROJECT_ROOT/scripts/tests/foundry"

# Check if forge is installed, try a common PATH fixup for Foundry.
if ! command -v forge &> /dev/null; then
    if [ -d "$HOME/.foundry/bin" ]; then
        export PATH="$PATH:$HOME/.foundry/bin"
    fi
fi
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: forge not found. Please install Foundry.${NC}"
    exit 2
fi

# Run tests with gas report for KPIs
# Filter out "test_VerifyBound_EventEmitted" which is known to fail without valid bound-proofs yet (unless we fix it now)
# For now run all to show true status.
if forge test --gas-report; then
    echo -e "${GREEN}✓ Foundry tests passed${NC}"
else
    echo -e "${RED}✗ Foundry tests failed${NC}"
    exit 1
fi

echo ""

# 4. Fuzzing (optional but enabled when cargo-fuzz is available)
echo -e "${YELLOW}[4/4] Running Fuzzing Targets (short)...${NC}"
cd "$PROJECT_ROOT"
if [ "${GLYPH_SKIP_FUZZ}" = "1" ]; then
    echo -e "${YELLOW}Skipping fuzzing (GLYPH_SKIP_FUZZ=1)${NC}"
else
    if command -v cargo-fuzz &>/dev/null; then
        if cargo +"$RUSTUP_TOOLCHAIN" fuzz --version &>/dev/null; then
            FUZZ_CARGO=(cargo +"$RUSTUP_TOOLCHAIN")
        else
            echo -e "${YELLOW}cargo-fuzz requires nightly; skipping fuzzing${NC}"
            FUZZ_CARGO=()
        fi
        if [ "${#FUZZ_CARGO[@]}" -gt 0 ]; then
            mkdir -p "$FUZZ_OUT_DIR"
            FUZZ_TIME="${FUZZ_TIME:-60}"
            FUZZ_SEED="${GLYPH_FUZZ_SEED:-}"
            FUZZ_TARGETS="${FUZZ_TARGETS:-decode_adapter_bytes decode_adapter_ir_deep verify_adapter_proof verify_packed_calldata transcript_challenges validate_state_transition_batch}"
            FUZZ_FEATURES_LIST=()
            if [ "${GLYPH_FUZZ_STARK}" = "1" ]; then
                FUZZ_TARGETS="$FUZZ_TARGETS decode_stark_receipt decode_stark_vk"
                FUZZ_FEATURES_LIST+=("stark-babybear")
            else
                echo -e "${YELLOW}Skipping STARK fuzz targets (GLYPH_FUZZ_STARK=0)${NC}"
            fi
            if [ "${GLYPH_FUZZ_CAIRO:-0}" = "1" ]; then
                OS_NAME="$(uname -s)"
                if [ "$OS_NAME" = "Linux" ]; then
                    FUZZ_FEATURES_LIST+=("stark-m31")
                else
                    echo -e "${YELLOW}GLYPH_FUZZ_CAIRO=1 requires Linux. Skipping stark-m31 feature.${NC}"
                fi
            fi
            FUZZ_FEATURES=()
            if [ "${#FUZZ_FEATURES_LIST[@]}" -gt 0 ]; then
                FUZZ_FEATURES_JOINED="$(IFS=,; echo "${FUZZ_FEATURES_LIST[*]}")"
                FUZZ_FEATURES=(--features "$FUZZ_FEATURES_JOINED")
            fi
            FUZZ_RUSTFLAGS_EXTRA=""
            if [ "$(uname -s)" = "Darwin" ]; then
                FUZZ_RUSTFLAGS_EXTRA="-C link-arg=-Wl,-no_dead_strip_inits_and_terms -C link-arg=-Wl,-no_dead_strip"
            fi
            for target in $FUZZ_TARGETS; do
                echo "Fuzzing target=${target} time=${FUZZ_TIME}s"
                FUZZ_LOG="$FUZZ_OUT_DIR/${target}.log"
                FUZZ_ARGS=(-max_total_time="$FUZZ_TIME")
                if [ -n "$FUZZ_SEED" ]; then
                    FUZZ_ARGS+=(-seed="$FUZZ_SEED")
                fi
                if ! CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=off \
                    CARGO_TARGET_DIR="$PROJECT_ROOT/target" \
                    CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="${CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS:-} ${FUZZ_RUSTFLAGS_EXTRA}" \
                    RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}" \
                    run_with_timeout "${FUZZ_CARGO[@]}" fuzz run --fuzz-dir "$PROJECT_ROOT/scripts/tests/fuzz/workspace" \
                    "$target" "${FUZZ_FEATURES[@]}" -- "${FUZZ_ARGS[@]}" 2>&1 | tee "$FUZZ_LOG"; then
                    if [ "$GLYPH_FUZZ_SOFT_FAIL" = "1" ]; then
                        if grep -E "SIGSEGV|stack overflow|signal: 11" "$FUZZ_LOG" >/dev/null 2>&1; then
                            echo -e "${YELLOW}WARN: Toolchain crash during fuzz target=${target}.${NC}"
                            echo -e "${YELLOW}WARN: Try newer nightly or RUST_MIN_STACK=16777216 (ASAN builds can crash).${NC}"
                            continue
                        fi
                    fi
                    echo -e "${RED}✗ Fuzzing failed for target=${target}${NC}"
                    exit 1
                fi
            done
            echo -e "${GREEN}✓ Fuzzing targets passed${NC}"
        fi
    else
        echo -e "${YELLOW}cargo-fuzz not installed, skipping fuzzing${NC}"
    fi
fi

echo ""
echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
