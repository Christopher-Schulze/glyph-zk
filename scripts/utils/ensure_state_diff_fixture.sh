#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/utils/ensure_state_diff_fixture.sh <path>

Outputs:
  Writes a deterministic 1 MiB fixture to <path> if missing.

Exit codes:
  2 on missing args or missing tools.
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

TARGET="${1:-}"
if [[ "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  usage
  exit 0
fi
if [ -z "$TARGET" ]; then
  usage >&2
  exit 2
fi

require_cmd python3

if [ -f "$TARGET" ]; then
  exit 0
fi

mkdir -p "$(dirname "$TARGET")"

python3 - <<'PY' "$TARGET"
import sys

path = sys.argv[1]
seed = 1
size = 1024 * 1024
data = bytearray(size)
val = seed & 0xff
for i in range(size):
    data[i] = val
    val = (val * 1103515245 + 12345) & 0xff
with open(path, "wb") as handle:
    handle.write(data)
PY
