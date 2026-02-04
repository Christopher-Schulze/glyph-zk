#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/groth16_compare/build_groth16.sh

Optional env:
  ARTIFACT_DIR
  CIRCUIT_PATH
  CIRCUIT_NAME
  INPUT_PATH
  FORCE

Notes:
  Prefers bun if available, otherwise uses npm to install JS tooling.

Outputs:
  Writes Groth16 artifacts under ARTIFACT_DIR.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$ROOT_DIR/../../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
ARTIFACTS="${ARTIFACT_DIR:-$PROJECT_OUT/benchmarks/groth16_compare/artifacts}"
BIN_DIR="$ROOT_DIR/node_modules/.bin"

if [[ ! -d "$ROOT_DIR/node_modules" ]]; then
    if command -v bun >/dev/null 2>&1; then
        (
            cd "$ROOT_DIR"
            bun install
        )
    else
        require_cmd npm
        (
            cd "$ROOT_DIR"
            npm ci
        )
    fi
fi

if [[ -x "$BIN_DIR/circom" ]]; then
    CIRCOM="$BIN_DIR/circom"
elif [[ -x "$BIN_DIR/circom.cmd" ]]; then
    CIRCOM="$BIN_DIR/circom.cmd"
else
    echo "ERROR: circom not found in $BIN_DIR" >&2
    exit 2
fi

if [[ -x "$BIN_DIR/snarkjs" ]]; then
    SNARKJS="$BIN_DIR/snarkjs"
elif [[ -x "$BIN_DIR/snarkjs.cmd" ]]; then
    SNARKJS="$BIN_DIR/snarkjs.cmd"
else
    echo "ERROR: snarkjs not found in $BIN_DIR" >&2
    exit 2
fi

if [[ -n "${CIRCUIT_PATH:-}" ]]; then
    CIRCUIT="$CIRCUIT_PATH"
elif [[ -n "${CIRCUIT_NAME:-}" ]]; then
    CIRCUIT="$ROOT_DIR/${CIRCUIT_NAME}.circom"
else
    CIRCUIT="$ROOT_DIR/circuit.circom"
fi

INPUT_PATH="${INPUT_PATH:-$ARTIFACTS/input.json}"

if [[ ! -f "$CIRCUIT" ]]; then
    echo "ERROR: missing circuit: $CIRCUIT" >&2
    exit 2
fi
if [[ ! -f "$INPUT_PATH" ]]; then
    echo "ERROR: missing input: $INPUT_PATH" >&2
    exit 2
fi

CIRCUIT_BASE="$(basename "$CIRCUIT" .circom)"
R1CS="$ARTIFACTS/${CIRCUIT_BASE}.r1cs"
WASM="$ARTIFACTS/${CIRCUIT_BASE}.wasm"
SYM="$ARTIFACTS/${CIRCUIT_BASE}.sym"
PTAU0="$ARTIFACTS/pot12_0000.ptau"
PTAU1="$ARTIFACTS/pot12_0001.ptau"
PTAU_FINAL="$ARTIFACTS/pot12_final.ptau"
ZKEY0="$ARTIFACTS/circuit_0000.zkey"
ZKEY_FINAL="$ARTIFACTS/circuit_final.zkey"
VK="$ARTIFACTS/verification_key.json"
PROOF="$ARTIFACTS/proof.json"
PUBLIC="$ARTIFACTS/public.json"
VERIFIER_SOL="$ARTIFACTS/verifier.sol"
CALLDATA="$ARTIFACTS/calldata.txt"

mkdir -p "$ARTIFACTS"

if [[ -f "$VERIFIER_SOL" && -z "${FORCE:-}" ]]; then
    echo "ERROR: artifacts already exist. Set FORCE=1 to regenerate." >&2
    exit 2
fi

(
    cd "$ROOT_DIR"
    "$CIRCOM" "$CIRCUIT" --r1cs --wasm --sym
)

cp -f "$ROOT_DIR/${CIRCUIT_BASE}.r1cs" "$R1CS"
cp -f "$ROOT_DIR/${CIRCUIT_BASE}.wasm" "$WASM"
cp -f "$ROOT_DIR/${CIRCUIT_BASE}.sym" "$SYM"
rm -f "$ROOT_DIR/${CIRCUIT_BASE}.r1cs" "$ROOT_DIR/${CIRCUIT_BASE}.wasm" "$ROOT_DIR/${CIRCUIT_BASE}.sym"

"$SNARKJS" powersoftau new bn128 12 "$PTAU0" -v
"$SNARKJS" powersoftau contribute "$PTAU0" "$PTAU1" --name="glyph-groth16" -v -e="glyph-bench"
"$SNARKJS" powersoftau prepare phase2 "$PTAU1" "$PTAU_FINAL" -v
"$SNARKJS" groth16 setup "$R1CS" "$PTAU_FINAL" "$ZKEY0"
"$SNARKJS" zkey contribute "$ZKEY0" "$ZKEY_FINAL" --name="glyph-groth16" -v -e="glyph-bench"
"$SNARKJS" zkey export verificationkey "$ZKEY_FINAL" "$VK"
"$SNARKJS" groth16 fullprove "$INPUT_PATH" "$WASM" "$ZKEY_FINAL" "$PROOF" "$PUBLIC"
"$SNARKJS" zkey export solidityverifier "$ZKEY_FINAL" "$VERIFIER_SOL"
"$SNARKJS" zkey export soliditycalldata "$PUBLIC" "$PROOF" | tr -d '\n' > "$CALLDATA"

echo "Groth16 artifacts generated in $ARTIFACTS"
