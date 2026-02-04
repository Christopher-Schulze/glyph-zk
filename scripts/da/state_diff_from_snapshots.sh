#!/bin/bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GLYPH_STATE_DIFF_BIN="${GLYPH_STATE_DIFF_BIN:-$PROJECT_ROOT/target/release/glyph_state_diff}"

PRE=""
POST=""
OUT=""
EMIT_BYTES=""

usage() {
    cat <<'USAGE'
Usage:
  scripts/da/state_diff_from_snapshots.sh --pre <file> --post <file> --out <file> [--emit-bytes <file>]

Outputs:
  - state diff JSON written to --out
  - optional canonical bytes written to --emit-bytes

Exit codes:
  2 on invalid input or missing input files.
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

ensure_bin() {
    if [ ! -x "$GLYPH_STATE_DIFF_BIN" ]; then
        require_cmd cargo
        echo "Building glyph_state_diff..."
        cargo build --release --bin glyph_state_diff
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pre) PRE="$2"; shift 2 ;;
        --post) POST="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --emit-bytes) EMIT_BYTES="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die_input "unknown arg: $1" ;;
    esac
done

if [ -z "$PRE" ] || [ -z "$POST" ] || [ -z "$OUT" ]; then
    usage
    exit 2
fi

if [ ! -f "$PRE" ]; then
    die_input "pre snapshot not found: $PRE"
fi
if [ ! -f "$POST" ]; then
    die_input "post snapshot not found: $POST"
fi

mkdir -p "$(dirname "$OUT")"
if [ -n "$EMIT_BYTES" ]; then
    mkdir -p "$(dirname "$EMIT_BYTES")"
fi

ensure_bin

if [ -n "$EMIT_BYTES" ]; then
    "$GLYPH_STATE_DIFF_BIN" build --pre "$PRE" --post "$POST" --out "$OUT" --emit-bytes "$EMIT_BYTES" --json
else
    "$GLYPH_STATE_DIFF_BIN" build --pre "$PRE" --post "$POST" --out "$OUT" --json
fi
