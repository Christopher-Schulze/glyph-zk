#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/da/providers/check_providers.sh

Purpose:
  Smoke-check local DA provider helpers without network calls.
  Verifies toolchains, module wiring, and required local assets.

Outputs:
  Prints "ok" on success. Errors are printed to stderr.

Exit codes:
  2 on missing tools or missing assets.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

check_go_module() {
  local label="$1"
  local dir="$2"
  if [ ! -d "$dir" ]; then
    echo "ERROR: $label directory missing: $dir" >&2
    exit 2
  fi
  (cd "$dir" && go list ./... >/dev/null 2>&1) || {
    echo "ERROR: $label go module check failed (run 'go list ./...' in $dir)" >&2
    exit 1
  }
}

check_node_modules() {
  local label="$1"
  local dir="$2"
  if [ ! -d "$dir" ]; then
    echo "ERROR: $label directory missing: $dir" >&2
    exit 2
  fi
  if [ ! -d "$dir/node_modules" ]; then
    echo "ERROR: $label node_modules missing. Run 'bun install' or 'npm ci' in $dir" >&2
    exit 2
  fi
}

check_srs() {
  local srs_dir="${EIGENDA_V2_SRS_DIR:-$ROOT_DIR/scripts/da/srs/eigenda_v2}"
  local needed=(
    "g1.point"
    "g2.point"
    "g2.trailing.point"
    "g2.point.powerOf2"
    "SRSTables/dimE2.coset2"
  )
  for path in "${needed[@]}"; do
    if [ ! -f "$srs_dir/$path" ]; then
      echo "ERROR: missing SRS file: $srs_dir/$path" >&2
      echo "Run scripts/da/fetch_eigenda_v2_srs.sh to populate the SRS cache." >&2
      exit 2
    fi
  done
}

echo "=== DA provider helper smoke checks ==="

require_cmd go
check_go_module "eigenda_v1" "$ROOT_DIR/scripts/da/providers/eigenda_v1"
check_go_module "eigenda_v2" "$ROOT_DIR/scripts/da/providers/eigenda_v2"
check_srs

if command -v bun >/dev/null 2>&1; then
  : # bun available
else
  require_cmd node
fi
check_node_modules "arweave_turbo_upload" "$ROOT_DIR/scripts/da/providers"

echo "ok"
