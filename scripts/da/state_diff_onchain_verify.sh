#!/bin/bash
set -euo pipefail

RPC_URL=""
PRIVATE_KEY=""
ROOT_UPDATER=""
NEW_ROOT=""
DA_COMMITMENT=""
PROOF_JSON=""
MODE="send"
EXTRA_COMMITMENT=""
EXTRA_SCHEMA_ID=""

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/state_diff_onchain_verify.sh \
    --rpc <url> --private-key <hex> \
    --root-updater <0xaddr> \
    --new-root <0xbytes32> \
    --da-commitment <0xbytes32> \
    --proof-json <path> \
    [--extra-commitment <0xbytes32> --extra-schema-id <0xbytes32>] \
    [--call]

Modes:
  default is --send (state update)
  --call performs a static call without state change

Outputs:
  Prints cast call or cast send output to stdout.

Exit codes:
  2 on invalid input or missing proof file.
  1 on runtime failure.
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

while [ $# -gt 0 ]; do
    case "$1" in
        --rpc) RPC_URL="$2"; shift 2 ;;
        --private-key) PRIVATE_KEY="$2"; shift 2 ;;
        --root-updater) ROOT_UPDATER="$2"; shift 2 ;;
        --new-root) NEW_ROOT="$2"; shift 2 ;;
        --da-commitment) DA_COMMITMENT="$2"; shift 2 ;;
        --proof-json) PROOF_JSON="$2"; shift 2 ;;
        --extra-commitment) EXTRA_COMMITMENT="$2"; shift 2 ;;
        --extra-schema-id) EXTRA_SCHEMA_ID="$2"; shift 2 ;;
        --call) MODE="call"; shift 1 ;;
        -h|--help) usage; exit 0 ;;
        *) die_input "unknown arg: $1" ;;
    esac
done

if [ -z "$RPC_URL" ] || [ -z "$ROOT_UPDATER" ] || [ -z "$NEW_ROOT" ] || [ -z "$DA_COMMITMENT" ] || [ -z "$PROOF_JSON" ]; then
    usage
    exit 2
fi
if [ ! -f "$PROOF_JSON" ]; then
    die_input "proof json not found: $PROOF_JSON"
fi

require_cmd cast
require_cmd python3

calldata="$(
    python3 -c "import json; print(json.load(open('$PROOF_JSON','r'))['calldata'])"
)"
if [ -z "$calldata" ]; then
    die_input "calldata missing in proof json"
fi

if [ "$MODE" = "call" ]; then
    if [ -n "$EXTRA_COMMITMENT" ] || [ -n "$EXTRA_SCHEMA_ID" ]; then
        [ -n "$EXTRA_COMMITMENT" ] || die_input "--extra-commitment required with --extra-schema-id"
        [ -n "$EXTRA_SCHEMA_ID" ] || die_input "--extra-schema-id required with --extra-commitment"
        cast call "$ROOT_UPDATER" \
            "verifyRootUpdate(bytes32,bytes32,bytes32,bytes32,bytes)" \
            "$NEW_ROOT" \
            "$DA_COMMITMENT" \
            "$EXTRA_COMMITMENT" \
            "$EXTRA_SCHEMA_ID" \
            "$calldata" \
            --rpc-url "$RPC_URL"
        exit 0
    fi
    cast call "$ROOT_UPDATER" \
        "verifyRootUpdate(bytes32,bytes32,bytes)" \
        "$NEW_ROOT" \
        "$DA_COMMITMENT" \
        "$calldata" \
        --rpc-url "$RPC_URL"
    exit 0
fi

if [ -z "$PRIVATE_KEY" ]; then
    die_input "--private-key required for send"
fi

if [ -n "$EXTRA_COMMITMENT" ] || [ -n "$EXTRA_SCHEMA_ID" ]; then
    [ -n "$EXTRA_COMMITMENT" ] || die_input "--extra-commitment required with --extra-schema-id"
    [ -n "$EXTRA_SCHEMA_ID" ] || die_input "--extra-schema-id required with --extra-commitment"
    cast send "$ROOT_UPDATER" \
        "verifyRootUpdate(bytes32,bytes32,bytes32,bytes32,bytes)" \
        "$NEW_ROOT" \
        "$DA_COMMITMENT" \
        "$EXTRA_COMMITMENT" \
        "$EXTRA_SCHEMA_ID" \
        "$calldata" \
        --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY"
    exit 0
fi

cast send "$ROOT_UPDATER" \
    "verifyRootUpdate(bytes32,bytes32,bytes)" \
    "$NEW_ROOT" \
    "$DA_COMMITMENT" \
    "$calldata" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY"
