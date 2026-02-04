#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
RUN_ID="${RUN_ID:-$(date -u +"%Y%m%dT%H%M%SZ")}"

GLYPH_STATE_DIFF_BIN="${GLYPH_STATE_DIFF_BIN:-$PROJECT_ROOT/target/release/glyph_state_diff}"
GLYPH_STATE_DIFF_PROVE_BIN="${GLYPH_STATE_DIFF_PROVE_BIN:-$PROJECT_ROOT/target/release/glyph_state_diff_prove}"
GLYPH_L2_STATEMENT_BIN="${GLYPH_L2_STATEMENT_BIN:-$PROJECT_ROOT/target/release/glyph_l2_statement}"
GEN_GKR_PROOF_BIN="${GEN_GKR_PROOF_BIN:-$PROJECT_ROOT/target/release/gen_glyph_gkr_proof}"

PRE=""
POST=""
CHAINID=""
VERIFIER=""
CONTRACT=""
OLD_ROOT=""
NEW_ROOT=""
BATCH_ID=""
DA_COMMITMENT=""
OUT_DIR=""
STATE_DIFF_JSON=""
STATE_DIFF_BYTES=""
PROVER_MODE="fast"
TRUNCATED="true"

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/state_diff_proof_flow.sh \
    --pre <file> --post <file> \
    --chainid <u64> \
    --verifier <0xglyph_verifier_addr> \
    --contract <0xroot_updater_addr> \
    --old-root <0xbytes32> --new-root <0xbytes32> --batch-id <u64> \
    [--out-dir <dir>] \
    [--da-commitment <0xbytes32>] \
    [--state-diff-json <file> --state-diff-bytes <file>] \
    [--mode fast|zk] [--full | --truncated]

Notes:
  - If --state-diff-json/--state-diff-bytes are not provided, the script will
    generate them from --pre/--post using glyph_state_diff.
  - If --da-commitment is omitted, the state diff hash (keccak of canonical bytes)
    is used.
  - The proof is generated in --artifact-poly mode and bound to tags derived from
    the extended statement hash (extra_commitment=state_diff_root).

Outputs:
  Writes state diff artifacts and proof bundle under --out-dir:
  - state_diff.json, state_diff.bytes, state_diff_build.json
  - state_diff_proof.json, statement_tags.json, gkr_proof.json, bundle.json

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
        --pre) PRE="$2"; shift 2 ;;
        --post) POST="$2"; shift 2 ;;
        --chainid) CHAINID="$2"; shift 2 ;;
        --verifier) VERIFIER="$2"; shift 2 ;;
        --contract) CONTRACT="$2"; shift 2 ;;
        --old-root) OLD_ROOT="$2"; shift 2 ;;
        --new-root) NEW_ROOT="$2"; shift 2 ;;
        --batch-id) BATCH_ID="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --da-commitment) DA_COMMITMENT="$2"; shift 2 ;;
        --state-diff-json) STATE_DIFF_JSON="$2"; shift 2 ;;
        --state-diff-bytes) STATE_DIFF_BYTES="$2"; shift 2 ;;
        --mode) PROVER_MODE="$2"; shift 2 ;;
        --full) TRUNCATED="false"; shift 1 ;;
        --truncated) TRUNCATED="true"; shift 1 ;;
        -h|--help) usage; exit 0 ;;
        *) die_input "unknown arg: $1" ;;
    esac
done

if [ -z "$CHAINID" ] || [ -z "$VERIFIER" ] || [ -z "$CONTRACT" ] || [ -z "$OLD_ROOT" ] || [ -z "$NEW_ROOT" ] || [ -z "$BATCH_ID" ]; then
    usage
    exit 2
fi

if [ -z "$STATE_DIFF_JSON" ] || [ -z "$STATE_DIFF_BYTES" ]; then
    if [ -z "$PRE" ] || [ -z "$POST" ]; then
        die_input "missing --pre/--post or --state-diff-json/--state-diff-bytes"
    fi
fi
if [ -n "$PRE" ] && [ ! -f "$PRE" ]; then
    die_input "pre snapshot not found: $PRE"
fi
if [ -n "$POST" ] && [ ! -f "$POST" ]; then
    die_input "post snapshot not found: $POST"
fi
if [ -n "$STATE_DIFF_JSON" ] && [ ! -f "$STATE_DIFF_JSON" ] && { [ -z "$PRE" ] || [ -z "$POST" ]; }; then
    die_input "state diff json not found: $STATE_DIFF_JSON"
fi
if [ -n "$STATE_DIFF_BYTES" ] && [ ! -f "$STATE_DIFF_BYTES" ] && { [ -z "$PRE" ] || [ -z "$POST" ]; }; then
    die_input "state diff bytes not found: $STATE_DIFF_BYTES"
fi

case "$PROVER_MODE" in
    fast|zk)
        ;;
    *)
        die_input "unsupported --mode: $PROVER_MODE (use fast or zk)"
        ;;
esac

require_cmd python3

OUT_DIR="${OUT_DIR:-$PROJECT_OUT/da/state-diff/$RUN_ID}"
mkdir -p "$OUT_DIR"

STATE_DIFF_JSON="${STATE_DIFF_JSON:-$OUT_DIR/state_diff.json}"
STATE_DIFF_BYTES="${STATE_DIFF_BYTES:-$OUT_DIR/state_diff.bytes}"
STATE_DIFF_BUILD_JSON="$OUT_DIR/state_diff_build.json"
STATE_DIFF_PROOF_JSON="$OUT_DIR/state_diff_proof.json"
STATEMENT_JSON="$OUT_DIR/statement_tags.json"
GKR_PROOF_JSON="$OUT_DIR/gkr_proof.json"
BUNDLE_JSON="$OUT_DIR/bundle.json"

ensure_bin "$GLYPH_STATE_DIFF_BIN" glyph_state_diff
ensure_bin "$GLYPH_STATE_DIFF_PROVE_BIN" glyph_state_diff_prove
ensure_bin "$GLYPH_L2_STATEMENT_BIN" glyph_l2_statement
ensure_bin "$GEN_GKR_PROOF_BIN" gen_glyph_gkr_proof

if [ -n "$PRE" ] && [ -n "$POST" ] && { [ ! -f "$STATE_DIFF_JSON" ] || [ ! -f "$STATE_DIFF_BYTES" ]; }; then
    echo "=== Build state diff ==="
    "$GLYPH_STATE_DIFF_BIN" build --pre "$PRE" --post "$POST" --out "$STATE_DIFF_JSON" --emit-bytes "$STATE_DIFF_BYTES" --json > "$STATE_DIFF_BUILD_JSON"
fi

if [ ! -f "$STATE_DIFF_JSON" ]; then
    die "state diff json not found: $STATE_DIFF_JSON"
fi
if [ ! -f "$STATE_DIFF_BYTES" ]; then
    die "state diff bytes not found: $STATE_DIFF_BYTES"
fi

STATE_DIFF_HASH="$(
    "$GLYPH_STATE_DIFF_BIN" hash --in "$STATE_DIFF_JSON" --json | python3 -c "import json,sys; print(json.load(sys.stdin)['hash'])"
)"
if [ -z "$STATE_DIFF_HASH" ]; then
    die "failed to compute state diff hash"
fi

if [ -z "$DA_COMMITMENT" ]; then
    DA_COMMITMENT="$STATE_DIFF_HASH"
fi

echo "=== Compute state diff merkle root ==="
"$GLYPH_STATE_DIFF_PROVE_BIN" --bytes "$STATE_DIFF_BYTES" --mode "$PROVER_MODE" --json --out "$STATE_DIFF_PROOF_JSON"

STATE_DIFF_ROOT="$(
    python3 -c "import json; print(json.load(open('$STATE_DIFF_PROOF_JSON','r'))['state_diff_root'])"
)"
SCHEMA_ID="$(
    python3 -c "import json; print(json.load(open('$STATE_DIFF_PROOF_JSON','r'))['schema_id'])"
)"
if [ -z "$STATE_DIFF_ROOT" ] || [ -z "$SCHEMA_ID" ]; then
    die "missing state diff root or schema id"
fi

echo "=== Derive statement tags ==="
"$GLYPH_L2_STATEMENT_BIN" \
    --chainid "$CHAINID" \
    --contract "$CONTRACT" \
    --old-root "$OLD_ROOT" \
    --new-root "$NEW_ROOT" \
    --da "$DA_COMMITMENT" \
    --batch-id "$BATCH_ID" \
    --extra-commitment "$STATE_DIFF_ROOT" \
    --extra-schema-id "$SCHEMA_ID" \
    --json > "$STATEMENT_JSON"

COMMITMENT_TAG="$(
    python3 -c "import json; print(json.load(open('$STATEMENT_JSON','r'))['commitment_tag'])"
)"
POINT_TAG="$(
    python3 -c "import json; print(json.load(open('$STATEMENT_JSON','r'))['point_tag'])"
)"
CLAIM="$(
    python3 -c "import json; print(json.load(open('$STATEMENT_JSON','r'))['claim'])"
)"
STATEMENT_HASH="$(
    python3 -c "import json; print(json.load(open('$STATEMENT_JSON','r'))['statement_hash'])"
)"

if [ -z "$COMMITMENT_TAG" ] || [ -z "$POINT_TAG" ] || [ -z "$CLAIM" ]; then
    die "missing commitment_tag, point_tag, or claim from statement json"
fi

echo "=== Generate artifact-bound proof ==="
PROOF_ARGS=(
    --artifact-poly
    --commitment "$COMMITMENT_TAG"
    --point "$POINT_TAG"
    --claim "$CLAIM"
    --chainid "$CHAINID"
    --verifier "$VERIFIER"
    --json
)
if [ "$TRUNCATED" = "true" ]; then
    PROOF_ARGS+=(--truncated)
else
    PROOF_ARGS+=(--full)
fi

"$GEN_GKR_PROOF_BIN" "${PROOF_ARGS[@]}" > "$GKR_PROOF_JSON"

CALLDATA="$(
    python3 -c "import json; print(json.load(open('$GKR_PROOF_JSON','r'))['calldata'])"
)"
if [ -z "$CALLDATA" ]; then
    die "missing calldata in proof json"
fi

python3 - <<PY
import json

bundle = {
    "state_diff_hash": "$STATE_DIFF_HASH",
    "state_diff_root": "$STATE_DIFF_ROOT",
    "schema_id": "$SCHEMA_ID",
    "da_commitment": "$DA_COMMITMENT",
    "statement_hash": "$STATEMENT_HASH",
    "commitment_tag": "$COMMITMENT_TAG",
    "point_tag": "$POINT_TAG",
    "claim": "$CLAIM",
    "calldata": "$CALLDATA",
    "paths": {
        "state_diff_json": "$STATE_DIFF_JSON",
        "state_diff_bytes": "$STATE_DIFF_BYTES",
        "state_diff_proof_json": "$STATE_DIFF_PROOF_JSON",
        "statement_json": "$STATEMENT_JSON",
        "gkr_proof_json": "$GKR_PROOF_JSON"
    }
}
with open("$BUNDLE_JSON", "w", encoding="utf-8") as f:
    json.dump(bundle, f, indent=2)
PY

echo "=== Done ==="
echo "bundle_json=$BUNDLE_JSON"
