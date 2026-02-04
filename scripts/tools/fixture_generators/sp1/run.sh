#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  scripts/tools/fixture_generators/sp1/run.sh [--elf <path>] [--stdin-hex <hex> | --stdin-file <path>]

Outputs:
  scripts/tools/fixtures/sp1_groth16_receipt.txt
  scripts/tools/fixtures/sp1_plonk_receipt.txt

Exit codes:
  2 on invalid args or missing tools.
  1 on runtime failure.
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

ELF=""
STDIN_HEX=""
STDIN_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --elf)
            ELF="${2:-}"
            shift 2
            ;;
        --stdin-hex)
            STDIN_HEX="${2:-}"
            shift 2
            ;;
        --stdin-file)
            STDIN_FILE="${2:-}"
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -n "$STDIN_HEX" && -n "$STDIN_FILE" ]]; then
    echo "ERROR: use only one of --stdin-hex or --stdin-file" >&2
    exit 2
fi
if [[ -n "$STDIN_FILE" && ! -f "$STDIN_FILE" ]]; then
    echo "ERROR: stdin file not found: $STDIN_FILE" >&2
    exit 2
fi
if [[ -n "$ELF" && ! -f "$ELF" ]]; then
    echo "ERROR: elf not found: $ELF" >&2
    exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_DIR="$ROOT_DIR/scripts/tools/fixtures"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_cmd cargo
mkdir -p "$OUT_DIR"

ARGS=()
if [[ -n "$STDIN_HEX" ]]; then
    ARGS+=(--stdin-hex "$STDIN_HEX")
elif [[ -n "$STDIN_FILE" ]]; then
    ARGS+=(--stdin-file "$STDIN_FILE")
fi

if [[ -z "$ELF" ]]; then
    GUEST_DIR="$SCRIPT_DIR/guest"
    ELF_REL="elf-compilation/riscv32im-succinct-zkvm-elf/release/sp1-fixture-guest"
    ELF_PATH="$GUEST_DIR/target/$ELF_REL"
    if command -v cargo-prove >/dev/null 2>&1; then
        if [[ ! -f "$ELF_PATH" ]]; then
            (cd "$GUEST_DIR" && cargo prove build)
        fi
        if [[ ! -f "$ELF_PATH" ]]; then
            ALT_ELF="$ROOT_DIR/target/$ELF_REL"
            if [[ -f "$ALT_ELF" ]]; then
                ELF_PATH="$ALT_ELF"
            else
                echo "ERROR: SP1 guest build failed: elf not found at $ELF_PATH or $ALT_ELF" >&2
                exit 2
            fi
        fi
        ELF="$ELF_PATH"
    else
        (cd "$SCRIPT_DIR" && cargo run --release --bin build_guest)
        ELF="$SCRIPT_DIR/guest/elf/sp1_fixture_guest"
    fi
fi

GROTH_OUT="$OUT_DIR/sp1_groth16_receipt.txt"
cargo run --release --bin sp1_fixture_gen -- --elf "$ELF" --mode groth16 --out "$GROTH_OUT" "${ARGS[@]}"

PLONK_OUT="$OUT_DIR/sp1_plonk_receipt.txt"
cargo run --release --bin sp1_fixture_gen -- --elf "$ELF" --mode plonk --out "$PLONK_OUT" "${ARGS[@]}"
