#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"
GLYPH_VM_EXEC_BIN="${GLYPH_VM_EXEC_BIN:-$PROJECT_ROOT/target/release/glyph_state_transition_execute}"
GLYPH_VM_PROVE_BIN="${GLYPH_VM_PROVE_BIN:-$PROJECT_ROOT/target/release/glyph_state_transition_prove}"

OPS_JSON=""
OUT_DIR=""
CHAINID=""
VERIFIER=""
MODE="zk"
TRUNCATED="true"

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/state_transition_vm_flow.sh \
    --ops <ops.json> \
    [--chainid <u64> --verifier <0xaddr>] \
    [--out-dir <dir>] [--mode fast|zk] [--full | --truncated]

Notes:
  - This flow builds a VM batch with proofs and then generates a GLYPH proof.
  - The output is a VM proof bundle suitable for direct GLYPHVerifier calls.

Outputs:
  Writes batch.json and proof.json under --out-dir.

Exit codes:
  2 on invalid input.
  1 on build/prove failures.
USAGE
}

die() {
    echo "ERROR: $1" >&2
    exit 1
}

die_input() {
    echo "ERROR: $1" >&2
    exit 2
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die_input "required command not found: $cmd"
    fi
}

ensure_bin() {
    local bin_path="$1"
    local bin_name="$2"
    if [ ! -x "$bin_path" ]; then
        require_cmd cargo
        echo "Building $bin_name..."
        cargo build --release --bin "$bin_name"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ops) OPS_JSON="$2"; shift 2 ;;
        --chainid) CHAINID="$2"; shift 2 ;;
        --verifier) VERIFIER="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --mode) MODE="$2"; shift 2 ;;
        --full) TRUNCATED="false"; shift 1 ;;
        --truncated) TRUNCATED="true"; shift 1 ;;
        -h|--help) usage; exit 0 ;;
        *) die_input "unknown arg: $1" ;;
    esac
done

if [ -z "$OPS_JSON" ]; then
    usage
    exit 2
fi
if [ ! -f "$OPS_JSON" ]; then
    die_input "ops json not found: $OPS_JSON"
fi

case "$MODE" in
    fast|zk)
        ;;
    *)
        die_input "unsupported --mode: $MODE (use fast or zk)"
        ;;
esac

OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/state-transition-vm/$RUN_ID}"
mkdir -p "$OUT_DIR"

BATCH_JSON="$OUT_DIR/batch.json"
PROOF_JSON="$OUT_DIR/proof.json"

ensure_bin "$GLYPH_VM_EXEC_BIN" glyph_state_transition_execute
ensure_bin "$GLYPH_VM_PROVE_BIN" glyph_state_transition_prove

"$GLYPH_VM_EXEC_BIN" --in "$OPS_JSON" --out "$BATCH_JSON"

PROVE_ARGS=(--in "$BATCH_JSON" --mode "$MODE" --json --out "$PROOF_JSON")
if [ -n "$CHAINID" ]; then
    PROVE_ARGS+=(--chainid "$CHAINID")
fi
if [ -n "$VERIFIER" ]; then
    PROVE_ARGS+=(--verifier "$VERIFIER")
fi
if [ "$TRUNCATED" = "true" ]; then
    PROVE_ARGS+=(--truncated)
else
    PROVE_ARGS+=(--full)
fi

"$GLYPH_VM_PROVE_BIN" "${PROVE_ARGS[@]}"

echo "VM batch: $BATCH_JSON"
echo "VM proof: $PROOF_JSON"
