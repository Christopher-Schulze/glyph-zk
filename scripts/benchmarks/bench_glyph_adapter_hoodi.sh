#!/bin/bash
# Bench GLYPH adapter-generated vectors against GLYPHVerifier on Hoodi.
# Uses GLYPH_* vectors and drops full-layout c3 words when needed.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_glyph_adapter_hoodi.sh

Optional env:
  TIMEOUT
  RPC_URL
  HOODI_RPC_URL
  HOODI_CHAIN_ID
  DEPLOY_FILE
  WALLET_ENV_FILE
  OUT_DIR
  OUT_LOG (alias: OUT_FILE_LOG)
  OUT_JSON
  OUT_META

Outputs:
  Writes bench_v1 JSON to OUT_JSON and a log to OUT_LOG.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

# Stabilize terminal size in non-interactive shells to avoid "bogus screen size" warnings.
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if [ -t 1 ]; then
    stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

# Timeout (default 5 minutes)
TIMEOUT="${TIMEOUT:-0}"
TIMEOUT_PID=""
if [ "${TIMEOUT}" -gt 0 ]; then
    (sleep "$TIMEOUT" && echo "FATAL: Timeout ($TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
    TIMEOUT_PID=$!
    trap "if [ -n "${TIMEOUT_PID:-}" ]; then kill $TIMEOUT_PID 2>/dev/null; fi" EXIT
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/bench_glyph_adapter_hoodi.json}"
OUT_JSON="${OUT_JSON:-$OUT_FILE}"
OUT_META="${OUT_META:-$OUT_JSON.meta.json}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "glyph_adapter_hoodi"
OUT_FILE="$OUT_JSON"
OUT_META="${OUT_JSON}.meta.json"
require_cmd cast
require_cmd jq
require_cmd python3
require_cmd cargo

HOODI_CHAIN_ID="${HOODI_CHAIN_ID:-560048}"
DEPLOY_FILE="${DEPLOY_FILE:-$PROJECT_ROOT/deployments/hoodi.json}"
WALLET_ENV_FILE="${WALLET_ENV_FILE:-$PROJECT_ROOT/docs/wallet/.env.wallet}"

RPC_URL="${RPC_URL:-${HOODI_RPC_URL:-}}"
if [ -z "$RPC_URL" ]; then
    die_input "RPC_URL or HOODI_RPC_URL must be set"
fi

RPC_HOST="$(printf '%s' "$RPC_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"

if [ ! -f "$WALLET_ENV_FILE" ]; then
    die_input "$WALLET_ENV_FILE not found. Create docs/wallet/.env.wallet and fill in deployer credentials."
fi

# shellcheck disable=SC1090
source "$WALLET_ENV_FILE"

if [ -z "${DEPLOYER_ADDRESS:-}" ] || [ -z "${DEPLOYER_PRIVATE_KEY:-}" ]; then
    die_input "DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY not set in $WALLET_ENV_FILE"
fi

CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" | tr -d '\\r\\n')"
if [ "$CHAIN_ID" != "$HOODI_CHAIN_ID" ]; then
    die_input "rpc chain-id=$CHAIN_ID expected=$HOODI_CHAIN_ID"
fi

RESULTS_TMP="$(mktemp)"
cleanup_tmp() {
    if [ -n "${RESULTS_TMP:-}" ] && [ -f "$RESULTS_TMP" ]; then
        rm -f "$RESULTS_TMP"
    fi
}
trap cleanup_tmp EXIT

if [ ! -f "$DEPLOY_FILE" ]; then
    die_input "truncated verifier deployment file not found: $DEPLOY_FILE"
fi

CONTRACT_ADDR="$(jq -r '.contract // empty' "$DEPLOY_FILE")"
if [ -z "$CONTRACT_ADDR" ]; then
    die_input "missing GLYPHVerifier address in $DEPLOY_FILE"
fi

CODE="$(cast code "$CONTRACT_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0x")"
if [ "$CODE" = "0x" ]; then
    die_input "no code at $CONTRACT_ADDR"
fi

bench_setup_logs "$OUT_DIR/bench_glyph_adapter_hoodi.log"
bench_log_basic
bench_log_kv "rpc_host" "$RPC_HOST"
bench_log_kv "chain_id" "$CHAIN_ID"
bench_log_kv "deployer" "$DEPLOYER_ADDRESS"
bench_log_kv "verifier" "$CONTRACT_ADDR"
bench_log_kv "out_json" "$OUT_JSON"
bench_log_kv "out_log" "$OUT_LOG"
echo ""

GEN_BIN="$PROJECT_ROOT/target/release/gen_glyph_gkr_proof"
if [ ! -x "$GEN_BIN" ]; then
    echo "Building gen_glyph_gkr_proof..."
    cargo build --release --bin gen_glyph_gkr_proof
fi

reprove_artifact_hex() {
    python3 - "$1" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
idx = text.find("bytes memory proof")
if idx < 0:
    raise SystemExit(f"no proof found in {path}")
end = text.find(";", idx)
if end < 0:
    raise SystemExit(f"no proof terminator in {path}")
segment = text[idx:end]
hex_parts = re.findall(r'hex\"([0-9a-fA-F]*)\"', segment)
if not hex_parts:
    raise SystemExit(f"no proof hex parts in {path}")
hex_str = ''.join(hex_parts)
data = bytes.fromhex(hex_str)

chainid = int(os.environ.get("GLYPH_CHAINID", "0"))
verifier = os.environ.get("GLYPH_VERIFIER", "")
if not verifier:
    raise SystemExit("missing GLYPH_VERIFIER")

if len(data) >= 64 and (len(data) - 64) % 32 == 0:
    tag = data[0:32]
    claim_initial = data[32:64]
    rounds = (len(data) - 64) // 32
elif len(data) >= 160 and (len(data) - 160) % 32 == 0:
    commitment = data[32:64]
    point = data[64:96]
    claim_initial = data[96:128]
    rounds = (len(data) - 160) // 32
    hex_payload = "0x" + (commitment + point).hex()
    tag_hex = subprocess.check_output(["cast", "keccak", hex_payload], text=True).strip()
    tag = bytes.fromhex(tag_hex.removeprefix("0x"))
else:
    raise SystemExit("unsupported proof layout")

claim = claim_initial[0:16]
claim_u128 = int.from_bytes(claim, "big")
claim_bytes32 = (b"\x00" * 16) + claim_u128.to_bytes(16, "big")

cmd = [
    "target/release/gen_glyph_gkr_proof",
    "--artifact-poly",
    "--artifact-tag",
    "0x" + tag.hex(),
    "--claim",
    "0x" + claim_bytes32.hex(),
    "--rounds",
    str(rounds),
    "--chainid",
    str(chainid),
    "--verifier",
    verifier,
    "--json",
]
out = subprocess.check_output(cmd, text=True)
data = json.loads(out)
calldata = data["calldata"]
print(calldata.removeprefix("0x"))
PY
}

bench_one() {
    local name="$1"
    local file="$2"

    local hex
    hex="$(GLYPH_CHAINID="$HOODI_CHAIN_ID" GLYPH_VERIFIER="$CONTRACT_ADDR" reprove_artifact_hex "$file")"
    local bytes=$(( ${#hex} / 2 ))

    if ! cast call "$CONTRACT_ADDR" --data "0x$hex" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
        echo "ERROR: eth_call failed for ${name}"
        return 1
    fi

    local params
    params="[{\"from\":\"$DEPLOYER_ADDRESS\",\"to\":\"$CONTRACT_ADDR\",\"data\":\"0x$hex\"}]"
    local gas_hex
    gas_hex="$(cast rpc --rpc-url "$RPC_URL" eth_estimateGas --raw "$params" | tr -d '\" \\n\\r')"

    local gas_breakdown
    gas_breakdown="$(python3 - <<'PY' "0x$hex" "$gas_hex"
import sys
calldata = sys.argv[1].lower().removeprefix("0x")
gas_used = int(sys.argv[2], 0) if sys.argv[2].startswith("0x") else int(sys.argv[2])
base_tx_gas = 21000
zero_bytes = 0
nonzero_bytes = 0
for i in range(0, len(calldata), 2):
  byte = calldata[i:i+2]
  if byte == "00":
    zero_bytes += 1
  else:
    nonzero_bytes += 1
calldata_gas = zero_bytes * 4 + nonzero_bytes * 16
execution_gas = max(gas_used - base_tx_gas - calldata_gas, 0)
print(f"{calldata_gas},{base_tx_gas},{execution_gas}")
PY
)"
    IFS="," read -r calldata_gas base_tx_gas execution_gas <<< "$gas_breakdown"
    printf "%-18s %8s %12s\\n" "$name" "$bytes" "$gas_hex"
    printf '{"adapter":"%s","calldata_bytes":%s,"estimate_gas":"%s","calldata_gas":%s,"base_tx_gas":%s,"execution_gas":%s}\n' "$name" "$bytes" "$gas_hex" "$calldata_gas" "$base_tx_gas" "$execution_gas" >> "$RESULTS_TMP"
}

printf "%-18s %8s %12s\\n" "adapter" "bytes" "estimate_gas"
printf "%-18s %8s %12s\\n" "------------------" "--------" "------------"

bench_one "SNARK_GROTH16_BN254" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_SNARK_GROTH16_Test.t.sol"
bench_one "SNARK_KZG_BN254" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_SNARK_KZG_Test.t.sol"
bench_one "IVC" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_IVC_Test.t.sol"
bench_one "SNARK_IPA" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_SNARK_IPA_Test.t.sol"
bench_one "STARK" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_STARK_Test.t.sol"
bench_one "HASH" "$PROJECT_ROOT/scripts/tests/foundry/GLYPH_HASH_Test.t.sol"

echo ""
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$RESULTS_TMP" "$OUT_JSON" "$CONTRACT_ADDR" "$CHAIN_ID" "$RPC_HOST" "$GIT_COMMIT" "$TIMESTAMP" <<'PY'
import json
import sys

tmp, out, contract, chain_id, rpc_host, git_commit, timestamp = sys.argv[1:]
cases = []
with open(tmp, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        cases.append(json.loads(line))

doc = {
    "bench": "bench_glyph_adapter_hoodi",
    "timestamp": timestamp,
    "git_commit": git_commit,
    "chain_id": chain_id,
    "rpc_host": rpc_host,
    "contract": contract,
    "cases": cases,
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2, sort_keys=True)
print(f"json_out={out}")
PY

cat > "$OUT_META" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "git_commit": "$GIT_COMMIT",
  "script": "$(basename "$0")",
  "json_out": "$(basename "$OUT_JSON")"
}
EOF

echo "Done."
bench_finalize
