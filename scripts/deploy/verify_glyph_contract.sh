#!/bin/bash
# Verify GLYPHVerifier on Etherscan (Sepolia, Hoodi, Mainnet).
#
# Usage:
#   NETWORK=sepolia ETHERSCAN_API_KEY=... ./scripts/deploy/verify_glyph_contract.sh
#   NETWORK=hoodi  ETHERSCAN_API_KEY=... ./scripts/deploy/verify_glyph_contract.sh

# Timeout (default 5 minutes)
TIMEOUT="${TIMEOUT:-300}"
(sleep "$TIMEOUT" && echo "FATAL: Timeout ($TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
TIMEOUT_PID=$!
trap "kill $TIMEOUT_PID 2>/dev/null" EXIT

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/deploy/verify_glyph_contract.sh

Key env:
  NETWORK (default: sepolia)
  ETHERSCAN_API_KEY
  DEPLOY_FILE (default: deployments/<network>.json)
  TIMEOUT

Outputs:
  Etherscan verification status via forge output.

Exit codes:
  0 on success
  2 on invalid input
  1 on runtime failure
USAGE
}

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK="${NETWORK:-sepolia}"
DEPLOY_FILE="${DEPLOY_FILE:-$PROJECT_ROOT/deployments/${NETWORK}.json}"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ -z "${ETHERSCAN_API_KEY:-}" ]; then
    echo "ERROR: ETHERSCAN_API_KEY not set"
    exit 2
fi

if [ ! -f "$DEPLOY_FILE" ]; then
    echo "ERROR: Deployment file not found: $DEPLOY_FILE"
    echo "Run: ./scripts/deploy/deploy_glyph_contract.sh ${NETWORK}"
    exit 2
fi

CONTRACT="$(jq -r '.contract // empty' "$DEPLOY_FILE" 2>/dev/null)"
if [ -z "$CONTRACT" ]; then
    echo "ERROR: No contract address in $DEPLOY_FILE"
    exit 2
fi

require_cmd forge
require_cmd jq

echo "=== GLYPH Etherscan Verification ($NETWORK) ==="
echo "=== verify_context ==="
echo "network=$NETWORK"
echo "deploy_file=$DEPLOY_FILE"
echo "contract=$CONTRACT"
echo "timeout=$TIMEOUT"
echo "Contract: $CONTRACT"
echo ""

cd "$PROJECT_ROOT/scripts/tests/foundry"

forge verify-contract \
    --chain "$NETWORK" \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --watch \
    "$CONTRACT" \
    "../../../contracts/GLYPHVerifier.sol:GLYPHVerifier"

echo ""
echo "Done."
