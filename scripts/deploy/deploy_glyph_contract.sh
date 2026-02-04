#!/bin/bash
# Deploy GLYPHVerifier to generic network (Sepolia, Hoodi, etc.).
#
# Prerequisites:
# 1. Create docs/wallet/.env.wallet with DEPLOYER_ADDRESS and DEPLOYER_PRIVATE_KEY
# 2. Set RPC_URL or create .env.$NETWORK with specific RPC_URL (e.g. SEPOLIA_RPC_URL)
# 3. Get Testnet ETH from a faucet
#
# Usage: 
#   ./scripts/deploy/deploy_glyph_contract.sh [network]
#   
#   Examples:
#     ./scripts/deploy/deploy_glyph_contract.sh sepolia
#     ./scripts/deploy/deploy_glyph_contract.sh hoodi
#
# Writes deployment metadata to deployments/${NETWORK}.json

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/deploy/deploy_glyph_contract.sh [network]

Args:
  network              Network name (default: sepolia)

Key env:
  NETWORK, RPC_URL, WALLET_ENV_FILE, OUT_FILE_BASE, TIMEOUT
  PACKED_CALLDATA, ALLOW_VERIFY_FAILURE
  CHAIN_ID_EXPECTED, EXPLORER_BASE_URL, NETWORK_ENV_FILE

Outputs:
  deployments/<network>.json (or deployments/<network>_<timestamp>.json)

Exit codes:
  0 on success
  2 on invalid input
  1 on runtime failure
USAGE
}

# Timeout (default 5 minutes)
TIMEOUT="${TIMEOUT:-300}"
(sleep "$TIMEOUT" && echo "FATAL: Timeout ($TIMEOUT s) exceeded" && kill -9 $$ 2>/dev/null) &
TIMEOUT_PID=$!
trap "kill $TIMEOUT_PID 2>/dev/null" EXIT

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd"
        exit 2
    fi
}

# Network Selection: Argument > Env Var > Default
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ -n "${1:-}" ]; then
    NETWORK="$1"
else
    NETWORK="${NETWORK:-sepolia}"
fi

WALLET_ENV_FILE="${WALLET_ENV_FILE:-$PROJECT_ROOT/docs/wallet/.env.wallet}"
OUT_FILE_BASE="${OUT_FILE_BASE:-$PROJECT_ROOT/deployments/${NETWORK}.json}"
mkdir -p "$(dirname "$OUT_FILE_BASE")"

# Network Defaults
case "$NETWORK" in
    sepolia)
        CHAIN_ID_EXPECTED="${CHAIN_ID_EXPECTED:-11155111}"
        EXPLORER_BASE_URL="${EXPLORER_BASE_URL:-https://sepolia.etherscan.io}"
        DEFAULT_RPC_VAR="SEPOLIA_RPC_URL"
        ;;
    hoodi)
        CHAIN_ID_EXPECTED="${CHAIN_ID_EXPECTED:-560048}"
        EXPLORER_BASE_URL="${EXPLORER_BASE_URL:-https://hoodi.etherscan.io}"
        DEFAULT_RPC_VAR="HOODI_RPC_URL"
        ;;
    slots)
        CHAIN_ID_EXPECTED="${CHAIN_ID_EXPECTED:-560048}" # Assuming slots mirrors Hoodi/Sepolia params or defined elsewhere
        EXPLORER_BASE_URL="${EXPLORER_BASE_URL:-}"
        DEFAULT_RPC_VAR="SLOTS_RPC_URL"
        ;;
    *)
        echo "WARNING: Unknown network '$NETWORK'. manual config required."
        CHAIN_ID_EXPECTED="${CHAIN_ID_EXPECTED:-}"
        EXPLORER_BASE_URL="${EXPLORER_BASE_URL:-}"
        DEFAULT_RPC_VAR="RPC_URL"
        ;;
esac

# Load RPC URL
RPC_URL="${RPC_URL:-}"
if [ -z "$RPC_URL" ]; then
    NETWORK_ENV_FILE="${NETWORK_ENV_FILE:-$PROJECT_ROOT/.env.$NETWORK}"
    if [ -f "$NETWORK_ENV_FILE" ]; then
        # shellcheck disable=SC1090
        source "$NETWORK_ENV_FILE"
        # Indirect variable expansion for defaults
        RPC_URL="${!DEFAULT_RPC_VAR:-}"
    fi
fi

# Fallback Public RPCs
if [ -z "$RPC_URL" ]; then
    case "$NETWORK" in
        sepolia)
            for candidate in \
                "https://ethereum-sepolia.publicnode.com" \
                "https://sepolia.drpc.org" \
                "https://sepolia.gateway.tenderly.co" \
                "https://1rpc.io/sepolia"; do
                if cast chain-id --rpc-url "$candidate" >/dev/null 2>&1; then
                    RPC_URL="$candidate"
                    break
                fi
            done
            ;;
        hoodi)
            for candidate in \
                "https://ethereum-hoodi.publicnode.com" \
                "https://hoodi.drpc.org" \
                "https://rpc.hoodi.ethpandaops.io"; do
                if cast chain-id --rpc-url "$candidate" >/dev/null 2>&1; then
                    RPC_URL="$candidate"
                    break
                fi
            done
            ;;
    esac
fi

if [ -z "$RPC_URL" ]; then
    echo "ERROR: RPC_URL not set and no fallback RPC reachable"
    echo "Get a free RPC URL from:"
    echo "  - https://www.alchemy.com/ (recommended)"
    echo ""
    echo "Then set it in .env.hoodi or run:"
    echo "  export RPC_URL='https://eth-hoodi.g.alchemy.com/v2/YOUR_API_KEY'"
    exit 2
fi

# Check dependencies
for cmd in cast forge jq python3; do
    require_cmd "$cmd"
done

RPC_HOST="$(printf '%s' "$RPC_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"

# Load wallet credentials
if [ ! -f "$WALLET_ENV_FILE" ]; then
    echo "ERROR: $WALLET_ENV_FILE not found"
    echo "Create docs/wallet/.env.wallet with DEPLOYER_ADDRESS and DEPLOYER_PRIVATE_KEY"
    exit 2
fi

# shellcheck disable=SC1090
source "$WALLET_ENV_FILE"

if [ -z "${DEPLOYER_ADDRESS:-}" ] || [ -z "${DEPLOYER_PRIVATE_KEY:-}" ]; then
    echo "ERROR: DEPLOYER_ADDRESS or DEPLOYER_PRIVATE_KEY not set in $WALLET_ENV_FILE"
    exit 2
fi

# Validate chain ID
CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null | tr -d '\r\n' || true)"
if [ -z "$CHAIN_ID" ]; then
    echo "ERROR: failed to fetch chain-id from RPC"
    exit 1
fi
if [ "$CHAIN_ID" != "$CHAIN_ID_EXPECTED" ]; then
    echo "ERROR: rpc chain-id=$CHAIN_ID expected=$CHAIN_ID_EXPECTED"
    exit 2
fi

echo "=== GLYPHVerifier Deploy (${NETWORK}) ==="
echo ""
echo "=== deploy_context ==="
echo "network=$NETWORK"
echo "rpc_host=$RPC_HOST"
echo "chain_id=$CHAIN_ID"
echo "deploy_file=$OUT_FILE_BASE"
echo "wallet_env_file=$WALLET_ENV_FILE"
echo "timeout=$TIMEOUT"
echo "packed_calldata=${PACKED_CALLDATA:-}"
echo "allow_verify_failure=${ALLOW_VERIFY_FAILURE:-}"
echo ""
echo "Deployer: $DEPLOYER_ADDRESS"
echo "RPC:      $RPC_HOST"
echo "Chain ID: $CHAIN_ID"
echo ""

# Check balance
echo "Checking balance..."
BALANCE="$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")"
echo "Balance: $BALANCE wei"

if [ "$BALANCE" = "0" ]; then
    echo ""
    echo "ERROR: No ETH in wallet!"
    echo ""
    case "$NETWORK" in
        sepolia)
            echo "Get free Sepolia ETH from:"
            echo "  - https://cloud.google.com/application/web3/faucet/ethereum/sepolia"
            echo "  - https://www.alchemy.com/faucets/ethereum-sepolia"
            echo "  - https://faucet.quicknode.com/ethereum/sepolia"
            ;;
        hoodi)
            echo "Get free Hoodi ETH from:"
            echo "  - https://cloud.google.com/application/web3/faucet/ethereum/hoodi"
            echo "  - https://hoodi-faucet.pk910.de/#/"
            echo "  - https://faucet.quicknode.com/ethereum/hoodi"
            ;;
        *)
            echo "Get testnet ETH for '$NETWORK' from your preferred faucet."
            ;;
    esac
    echo ""
    echo "Send to: $DEPLOYER_ADDRESS"
    exit 1
fi

echo ""
echo "Deploying GLYPHVerifier.sol..."

cd "$PROJECT_ROOT/scripts/tests/foundry"

# Deploy
DEPLOY_JSON="$(forge create ../../../contracts/GLYPHVerifier.sol:GLYPHVerifier \
    --rpc-url "$RPC_URL" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --broadcast \
    --json 2>/dev/null || true)"

DEPLOYED="$(echo "$DEPLOY_JSON" | jq -r '.deployedTo // empty' 2>/dev/null || true)"

if [ -z "$DEPLOYED" ] || [ "$DEPLOYED" = "null" ]; then
    echo "Deployment failed. Trying verbose mode..."
    forge create ../../../contracts/GLYPHVerifier.sol:GLYPHVerifier \
        --rpc-url "$RPC_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --broadcast
    exit 1
fi

# Verify bytecode
echo ""
BYTECODE="$(cast code "$DEPLOYED" --rpc-url "$RPC_URL" 2>/dev/null || true)"
if [ -z "$BYTECODE" ] || [ "$BYTECODE" = "0x" ]; then
    echo "ERROR: deployed bytecode empty for $DEPLOYED"
    exit 1
fi
CODE_LEN=$(( (${#BYTECODE} - 2) / 2 ))

# Get TX hash and gas
TX_HASH="$(echo "$DEPLOY_JSON" | jq -r '.transactionHash // .deploymentTransactionHash // empty' 2>/dev/null || true)"
DEPLOY_GAS="(unknown)"
if [ -n "$TX_HASH" ] && [ "$TX_HASH" != "null" ]; then
    DEPLOY_GAS="$(cast receipt "$TX_HASH" gasUsed --rpc-url "$RPC_URL" 2>/dev/null || echo "(unknown)")"
fi

echo "=== DEPLOYMENT SUCCESSFUL ==="
echo "Contract:   $DEPLOYED"
echo "TX:         ${TX_HASH:-"(unknown)"}"
echo "Deploy Gas: $DEPLOY_GAS"
echo "Code Bytes: $CODE_LEN"
echo "Explorer:   ${EXPLORER_BASE_URL}/address/$DEPLOYED"
echo ""

# Optional: verify packed calldata
VERIFY_RESULT="skipped"
if [ -n "${PACKED_CALLDATA:-}" ]; then
    echo "=== OPTIONAL: VERIFY PACKED CALLDATA ==="
    echo ""
    echo "Calling GLYPHVerifier with packed calldata..."
    RESULT="$(cast call "$DEPLOYED" --data "$PACKED_CALLDATA" --rpc-url "$RPC_URL" 2>/dev/null || true)"
    echo ""
    if [ "$RESULT" = "0x01" ] || [ "$RESULT" = "0x0000000000000000000000000000000000000000000000000000000000000001" ]; then
        echo "VERIFICATION SUCCESSFUL ON ${NETWORK}."
        VERIFY_RESULT="true"
    else
        echo "VERIFICATION FAILED."
        echo "Result: $RESULT"
        if [ "${ALLOW_VERIFY_FAILURE:-0}" = "0" ]; then
            exit 1
        fi
        VERIFY_RESULT="false"
    fi
    echo ""
fi

cd "$PROJECT_ROOT"

# Save deployment info
OUT_FILE="$OUT_FILE_BASE"
if [ -f "$OUT_FILE" ]; then
    TS="$(date -u +%Y%m%dT%H%M%SZ)"
    OUT_FILE="${OUT_FILE_BASE%.json}_${TS}.json"
fi

mkdir -p "$(dirname "$OUT_FILE")"
cat > "$OUT_FILE" <<EOF
{
  "network": "$NETWORK",
  "chain_id": "$CHAIN_ID",
  "rpc_host": "$RPC_HOST",
  "deployer": "$DEPLOYER_ADDRESS",
  "contract": "$DEPLOYED",
  "deploy_tx": "${TX_HASH:-""}",
  "deploy_gas": "$DEPLOY_GAS",
  "code_bytes": $CODE_LEN,
  "verify_result": "$VERIFY_RESULT",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "=== ${NETWORK} DEPLOYMENT COMPLETE ==="
echo "Deployment info saved to: $OUT_FILE"
echo ""
