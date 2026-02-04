#!/bin/bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  scripts/utils/cuda/check_cuda_toolkit.sh [--quiet]

Env:
  CUDA_PATH
  CUDA_ROOT
  CUDA_TOOLKIT_ROOT_DIR

Outputs:
  Prints CUDA detection and version warnings to stdout/stderr.

Exit codes:
  0 on success (even if CUDA is missing, with warnings).
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
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

warn_if_missing_dir() {
    local label="$1"
    local path="$2"
    if [[ -n "$path" && ! -d "$path" ]]; then
        echo "WARNING: $label is set but not a directory: $path" >&2
    fi
}

QUIET=0
if [[ "${1:-}" == "--quiet" ]]; then
    QUIET=1
fi

CUDA_PATH="${CUDA_PATH:-}"
CUDA_ROOT="${CUDA_ROOT:-}"
CUDA_TOOLKIT_ROOT_DIR="${CUDA_TOOLKIT_ROOT_DIR:-}"

if [[ "$QUIET" -eq 0 ]]; then
    echo "CUDA_PATH=$CUDA_PATH"
    echo "CUDA_ROOT=$CUDA_ROOT"
    echo "CUDA_TOOLKIT_ROOT_DIR=$CUDA_TOOLKIT_ROOT_DIR"
fi

warn_if_missing_dir "CUDA_PATH" "$CUDA_PATH"
warn_if_missing_dir "CUDA_ROOT" "$CUDA_ROOT"
warn_if_missing_dir "CUDA_TOOLKIT_ROOT_DIR" "$CUDA_TOOLKIT_ROOT_DIR"

if command -v nvcc >/dev/null 2>&1; then
    NVCC_OUT="$(nvcc --version 2>/dev/null || true)"
    if [[ "$QUIET" -eq 0 ]]; then
        echo "nvcc --version:"
        echo "$NVCC_OUT"
    fi
    if [[ "$NVCC_OUT" =~ release[[:space:]]+([0-9]+)\.([0-9]+) ]]; then
        MAJOR="${BASH_REMATCH[1]}"
        MINOR="${BASH_REMATCH[2]}"
        if [[ "$QUIET" -eq 0 ]]; then
            echo "Detected CUDA version: ${MAJOR}.${MINOR}"
        fi
        if [[ "$MAJOR" -ge 13 ]]; then
            echo "WARNING: CUDA >= 13 detected. cudarc may fail to build. Consider installing a supported CUDA toolkit." >&2
        fi
    elif [[ "$QUIET" -eq 0 ]]; then
        echo "WARNING: Could not parse CUDA version from nvcc output." >&2
    fi
else
    if [[ -n "$CUDA_PATH" || -n "$CUDA_ROOT" || -n "$CUDA_TOOLKIT_ROOT_DIR" ]]; then
        echo "WARNING: CUDA paths are set but nvcc is not on PATH." >&2
        echo "WARNING: Consider updating PATH to include the CUDA bin directory." >&2
    fi
    echo "WARNING: nvcc not found. CUDA toolkit not detected." >&2
fi
