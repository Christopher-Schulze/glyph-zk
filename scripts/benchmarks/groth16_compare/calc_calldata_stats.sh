#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/groth16_compare/calc_calldata_stats.sh

Optional env:
  ARTIFACT_DIR
  FOUNDRY_BIN

Outputs:
  Prints "bytes zero nonzero calldata_gas" to stdout.

Exit codes:
  2 on missing tools or missing calldata.txt.
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

require_cmd python3

PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$PROJECT_OUT/benchmarks/groth16_compare/artifacts}"

FOUNDRY_BIN="${FOUNDRY_BIN:-$HOME/.foundry/bin}"
if [ -d "$FOUNDRY_BIN" ]; then
    export PATH="$FOUNDRY_BIN:$PATH"
fi

require_cmd cast

if [ ! -f "$ARTIFACT_DIR/calldata.txt" ]; then
  echo "ERROR: missing calldata.txt in $ARTIFACT_DIR" >&2
  exit 2
fi

python3 - "$ARTIFACT_DIR/calldata.txt" <<'PY'
import ast
import subprocess
import sys

raw = open(sys.argv[1], "r", encoding="utf-8").read().strip()
items = ast.literal_eval(f"[{raw}]")

def fmt(value):
    if isinstance(value, list):
        return "[" + ",".join(fmt(v) for v in value) + "]"
    return str(value)

args = [fmt(x) for x in items]
pub_len = len(items[-1]) if items else 0
sig = f"verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[{pub_len}])"
cmd = ["cast", "calldata", sig, *args]
calldata = subprocess.check_output(cmd, text=True).strip()
if calldata.startswith("0x"):
    calldata = calldata[2:]
blob = bytes.fromhex(calldata)
zero = blob.count(0)
nonzero = len(blob) - zero
calldata_gas = zero * 4 + nonzero * 16
print(len(blob), zero, nonzero, calldata_gas)
PY
