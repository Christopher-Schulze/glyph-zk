#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/build/glyph_build.sh [options]

Options:
  --preset NAME        Build preset (default: default)
  --adapters LIST      Adapter list (comma-separated or "all")
  --features LIST      Extra cargo feature list (comma-separated)
  --profile NAME       Cargo profile (release-fast, release, etc)
  --release            Use --release for builds
  --cmd CMD            Override cargo subcommand (default: build)
  -h, --help           Show this help text

Key env:
  RUST_MIN_STACK (default: 16777216)
  RUSTUP_TOOLCHAIN

Outputs:
  Build artifacts under ./target

Exit codes:
  0 on success
  2 on invalid input
  1 on runtime failure
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

PRESET="default"
ADAPTERS=""
FEATURES=""
PROFILE=""
RELEASE=0
CMD="build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset)
            PRESET="${2:-}"
            shift 2
            ;;
        --adapters)
            ADAPTERS="${2:-}"
            shift 2
            ;;
        --features)
            FEATURES="${2:-}"
            shift 2
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --release)
            RELEASE=1
            shift
            ;;
        --cmd)
            CMD="${2:-}"
            shift 2
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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
require_cmd cargo

if [[ -z "${RUST_MIN_STACK:-}" ]]; then
    export RUST_MIN_STACK=16777216
fi

merge_features() {
    local base="$1"
    local extra="$2"
    local combined=""
    local item
    for item in ${base//,/ } ${extra//,/ }; do
        item="$(echo "$item" | tr '[:upper:]' '[:lower:]' | xargs)"
        [[ -z "$item" ]] && continue
        if [[ ",$combined," != *",$item,"* ]]; then
            if [[ -z "$combined" ]]; then
                combined="$item"
            else
                combined="${combined},${item}"
            fi
        fi
    done
    echo "$combined"
}

NO_DEFAULT=0
PRESET_FEATURES=""
ADAPTER_FEATURES=""

case "$PRESET" in
    default)
        NO_DEFAULT=0
        PRESET_FEATURES=""
        ;;
    core)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core"
        ;;
    snark)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,snark"
        ;;
    ivc)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,ivc"
        ;;
    hash)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,hash"
        ;;
    binius)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,binius"
        ;;
    stark-babybear)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,stark-babybear"
        ;;
    stark-goldilocks)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,stark-goldilocks"
        ;;
    stark-m31)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,stark-m31"
        ;;
    cuda)
        NO_DEFAULT=1
        PRESET_FEATURES="adapter-core,cuda"
        ;;
    full)
        NO_DEFAULT=1
        PRESET_FEATURES="full"
        ;;
    *)
        echo "ERROR: unknown preset: $PRESET" >&2
        exit 2
        ;;
esac

if [[ -n "$ADAPTERS" ]]; then
    NO_DEFAULT=1
    if [[ "$ADAPTERS" == "all" ]]; then
        ADAPTER_FEATURES="adapter-core,snark,ivc,hash,binius,stark-babybear,stark-goldilocks,stark-m31"
    else
        ADAPTER_FEATURES="adapter-core"
        IFS=',' read -r -a items <<< "$ADAPTERS"
        for item in "${items[@]}"; do
            item="$(echo "$item" | tr '[:upper:]' '[:lower:]' | xargs)"
            case "$item" in
                snark) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "snark")" ;;
                ivc) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "ivc")" ;;
                hash) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "hash")" ;;
                binius) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "binius")" ;;
                stark-babybear) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "stark-babybear")" ;;
                stark-goldilocks) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "stark-goldilocks")" ;;
                stark-m31) ADAPTER_FEATURES="$(merge_features "$ADAPTER_FEATURES" "stark-m31")" ;;
                *)
                    echo "ERROR: unknown adapter name: $item" >&2
                    exit 2
                    ;;
            esac
        done
    fi
fi

if [[ "$RELEASE" -eq 1 && -n "$PROFILE" ]]; then
    echo "ERROR: use either --release or --profile, not both" >&2
    exit 2
fi

BASE_FEATURES="$PRESET_FEATURES"
if [[ -n "$ADAPTER_FEATURES" ]]; then
    BASE_FEATURES="$ADAPTER_FEATURES"
fi

MERGED_FEATURES="$(merge_features "$BASE_FEATURES" "$FEATURES")"

USE_NIGHTLY=0
if [[ "$NO_DEFAULT" -eq 0 ]]; then
    USE_NIGHTLY=1
elif [[ -n "$MERGED_FEATURES" ]]; then
    if [[ "$MERGED_FEATURES" == *"full"* || "$MERGED_FEATURES" == *"stwo-prover"* || "$MERGED_FEATURES" == *"stark-babybear"* || "$MERGED_FEATURES" == *"stark-goldilocks"* || "$MERGED_FEATURES" == *"stark-m31"* ]]; then
        USE_NIGHTLY=1
    fi
fi

CMD_ARGS=("$CMD")
if [[ "$NO_DEFAULT" -eq 1 ]]; then
    CMD_ARGS+=(--no-default-features)
fi
if [[ -n "$MERGED_FEATURES" ]]; then
    CMD_ARGS+=(--features "$MERGED_FEATURES")
fi
if [[ -n "$ADAPTERS" ]]; then
    CMD_ARGS+=(--lib)
fi
if [[ "$NO_DEFAULT" -eq 1 && "$PRESET" != "full" ]]; then
    CMD_ARGS+=(--lib)
fi
if [[ "$RELEASE" -eq 1 ]]; then
    CMD_ARGS+=(--release)
fi
if [[ -n "$PROFILE" ]]; then
    CMD_ARGS+=(--profile "$PROFILE")
fi

CARGO_ARGS=()
if [[ -n "${RUSTUP_TOOLCHAIN:-}" ]]; then
    require_cmd rustup
    CARGO_ARGS+=(+"${RUSTUP_TOOLCHAIN}")
elif [[ "$USE_NIGHTLY" -eq 1 ]]; then
    require_cmd rustup
    CARGO_ARGS+=(+nightly)
fi
CARGO_ARGS+=("${CMD_ARGS[@]}")

echo "Preset: $PRESET"
if [[ "$USE_NIGHTLY" -eq 1 ]]; then
    echo "Toolchain: nightly"
fi
echo "Command: cargo ${CARGO_ARGS[*]}"

cargo "${CARGO_ARGS[@]}"
