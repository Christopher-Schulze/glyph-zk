#!/bin/bash
set -euo pipefail

EXIT_INVALID_INPUT=2
EXIT_RUNTIME=1

usage() {
  cat <<'USAGE'
Usage:
  source scripts/benchmarks/common.sh

Notes:
  This file provides shared helpers for benchmark scripts and is not meant
  to be executed directly.

Outputs:
  None. This file defines shared helpers for other scripts.

Exit codes:
  1 if executed directly.
USAGE
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  usage
  exit 1
fi

die_input() {
  echo "ERROR: $1" >&2
  exit "$EXIT_INVALID_INPUT"
}

die_runtime() {
  echo "ERROR: $1" >&2
  exit "$EXIT_RUNTIME"
}

bench_log_section() {
  echo "=== $1 ==="
}

bench_log_kv() {
  local key="$1"
  local value="$2"
  printf "%s=%s\n" "$key" "$value"
}

bench_log_basic() {
  bench_log_section "bench_context"
  bench_log_kv "bench_name" "${BENCH_NAME:-}"
  bench_log_kv "out_file" "${OUT_FILE:-}"
  if [ -n "${OUT_DIR:-}" ]; then
    bench_log_kv "out_dir" "$OUT_DIR"
  fi
  if [ -n "${RUN_ID:-}" ]; then
    bench_log_kv "run_id" "$RUN_ID"
  fi
}

bench_setup_logs() {
  local default_log="${1:-}"
  OUT_JSON="${OUT_JSON:-$OUT_FILE}"
  if [ -z "$default_log" ]; then
    default_log="$OUT_DIR/${BENCH_NAME}.log"
  fi
  OUT_LOG="${OUT_LOG:-${OUT_FILE_LOG:-$default_log}}"
  OUT_FILE_LOG="$OUT_LOG"
  mkdir -p "$(dirname "$OUT_LOG")"
  exec > >(tee "$OUT_LOG") 2>&1
}

bench_init() {
  local name="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    die_input "python3 not found in PATH"
  fi
  if [ -z "${RUN_ID:-}" ]; then
    RUN_ID="$(date -u +"%Y%m%dT%H%M%SZ")"
  fi
  if [ -z "${PROJECT_ROOT:-}" ]; then
    PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  fi
  PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
  BENCH_NAME="$name"
  OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
  OUT_FILE="${OUT_FILE:-$OUT_DIR/${BENCH_NAME}.json}"
  OUT_META="${OUT_META:-${OUT_FILE}.meta.json}"
  mkdir -p "$OUT_DIR"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    die_input "required command not found: $cmd"
  fi
}

require_rpc() {
  if [ -z "${RPC_URL:-}" ]; then
    die_input "RPC_URL not set"
  fi
}

require_wallet() {
  if [ -z "${PRIVATE_KEY:-}" ]; then
    die_input "PRIVATE_KEY not set"
  fi
}

bench_anvil_defaults() {
  ANVIL_PORT="${ANVIL_PORT:-8545}"
  ANVIL_CHAIN_ID="${ANVIL_CHAIN_ID:-31337}"
  RPC_URL="${RPC_URL:-http://127.0.0.1:${ANVIL_PORT}}"
  ANVIL_MNEMONIC="${ANVIL_MNEMONIC:-test test test test test test test test test test test junk}"
  DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
  FROM_ADDR="${FROM_ADDR:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
}

fail_if_call_fails() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "ERROR: $label failed" >&2
    exit 1
  fi
}

deploy_if_missing() {
  local label="$1"
  local addr="$2"
  local deploy_cmd="$3"
  if [ -z "$addr" ] || [ "$addr" = "0x0000000000000000000000000000000000000000" ]; then
    echo "ERROR: $label address missing" >&2
    exit 1
  fi
  if ! cast code --rpc-url "$RPC_URL" "$addr" >/dev/null 2>&1; then
    echo "WARN: $label code not found, deploying" >&2
    eval "$deploy_cmd"
  fi
}

bench_collect_rpc_meta() {
  RPC_HOST=""
  CHAIN_ID=""
  BLOCK_NUMBER=""
  BASE_FEE=""
  GAS_PRICE=""
  if [ -n "${RPC_URL:-}" ] && command -v cast >/dev/null 2>&1; then
    RPC_HOST="$(python3 - <<'PY' "${RPC_URL}"
import sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
print(u.hostname or "")
PY
)"
    CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)"
    BLOCK_NUMBER="$(cast block-number --rpc-url "$RPC_URL" 2>/dev/null || true)"
    BASE_FEE="$(cast block --rpc-url "$RPC_URL" latest --json 2>/dev/null | python3 - <<'PY'
import json, sys
try:
  data = json.load(sys.stdin)
  print(data.get("baseFeePerGas", ""))
except Exception:
  print("")
PY
)"
    GAS_PRICE="$(cast gas-price --rpc-url "$RPC_URL" 2>/dev/null || true)"
  fi
}

bench_toolchain_json() {
  local rustc_v="" cargo_v="" forge_v="" cast_v=""
  rustc_v="$(rustc -V 2>/dev/null || true)"
  cargo_v="$(cargo -V 2>/dev/null || true)"
  forge_v="$(forge --version 2>/dev/null || true)"
  cast_v="$(cast --version 2>/dev/null || true)"
  python3 - <<'PY' "$rustc_v" "$cargo_v" "$forge_v" "$cast_v"
import json, sys
print(json.dumps({
  "rustc": sys.argv[1],
  "cargo": sys.argv[2],
  "forge": sys.argv[3],
  "cast": sys.argv[4],
}))
PY
}

bench_host_json() {
  local os_name cpu_name
  os_name="$(uname -a 2>/dev/null || echo "unknown")"
  cpu_name=""
  if command -v lscpu >/dev/null 2>&1; then
    cpu_name="$(lscpu | awk -F: '/Model name/ {print $2}' | sed 's/^ *//g' | head -n 1)"
  elif command -v sysctl >/dev/null 2>&1; then
    cpu_name="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
  fi
  python3 - <<'PY' "$os_name" "$cpu_name"
import json, sys
print(json.dumps({
  "os": sys.argv[1],
  "cpu": sys.argv[2],
}))
PY
}

bench_finalize() {
  require_cmd python3
  if [ -z "${BENCH_NAME:-}" ]; then
    die_input "BENCH_NAME not set (bench_init)"
  fi
  if [ ! -f "$OUT_FILE" ]; then
    die_input "OUT_FILE missing: $OUT_FILE"
  fi
  if [ ! -s "$OUT_FILE" ]; then
    die_input "OUT_FILE empty: $OUT_FILE"
  fi

  bench_collect_rpc_meta

  local git_commit timestamp toolchain_json host_json
  git_commit="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  toolchain_json="$(bench_toolchain_json)"
  host_json="$(bench_host_json)"

  status="$(python3 - <<'PY' "$OUT_FILE" "$BENCH_NAME" "$timestamp" "$git_commit" "$RUN_ID" \
    "$toolchain_json" "$host_json" "$RPC_HOST" "$CHAIN_ID" "$BLOCK_NUMBER" \
    "$BASE_FEE" "$GAS_PRICE"
import json, sys, re
from pathlib import Path

out_path = Path(sys.argv[1])
bench_name = sys.argv[2]
timestamp = sys.argv[3]
git_commit = sys.argv[4]
run_id = sys.argv[5]
toolchain = json.loads(sys.argv[6])
host = json.loads(sys.argv[7])
rpc_host = sys.argv[8]
chain_id = sys.argv[9]
block_number = sys.argv[10]
base_fee = sys.argv[11]
gas_price = sys.argv[12]

raw = out_path.read_text(encoding="utf-8", errors="replace")
raw_json = None
status = "ok"

try:
  raw_json = json.loads(raw)
except Exception:
  # Try to find the first JSON object in stdout
  m = re.search(r'(\{.*\})', raw, re.DOTALL)
  if m:
    try:
      raw_json = json.loads(m.group(1))
    except Exception:
      raw_json = None

if raw_json is None:
  status = "parse_error"
elif not isinstance(raw_json, dict):
  status = "invalid_json"

data = raw_json if isinstance(raw_json, dict) else {}

def pick(*keys):
  for k in keys:
    if k in data:
      return data[k]
  return None

out = {
  "schema_version": "bench_v1",
  "bench_name": bench_name,
  "timestamp": timestamp,
  "run_id": run_id,
  "git_commit": git_commit,
  "toolchain": toolchain,
  "cpu": host.get("cpu", ""),
  "os": host.get("os", ""),
  "rpc_host": rpc_host,
  "chain_id": chain_id,
  "block_number": block_number,
  "base_fee": base_fee,
  "gas_price": gas_price,
  "case": pick("case", "profile", "preset"),
  "bytes": pick("bytes", "proof_bytes", "calldata_len"),
  "gas": pick("gas", "gas_used", "execution_gas"),
  "status": status,
  "data": data if isinstance(data, dict) else {},
}

out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
print(status)
PY
)"

  python3 - <<'PY' "$OUT_META" "$BENCH_NAME" "$timestamp" "$RUN_ID" "$git_commit" "$(basename "$0")" "$OUT_FILE" "$status"
import json
import sys

out_path = sys.argv[1]
bench_name = sys.argv[2]
timestamp = sys.argv[3]
run_id = sys.argv[4]
git_commit = sys.argv[5]
script = sys.argv[6]
out_file = sys.argv[7]
status = sys.argv[8]

out = {
  "schema_version": "bench_meta_v1",
  "bench_name": bench_name,
  "script": script,
  "out_file": out_file,
  "timestamp": timestamp,
  "run_id": run_id,
  "git_commit": git_commit,
  "status": status,
}

with open(out_path, "w", encoding="utf-8") as handle:
  json.dump(out, handle, indent=2)
PY
}
