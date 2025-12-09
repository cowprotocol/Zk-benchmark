#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Setup and Deploy MultischnorrVerifier to Sepolia via Foundry
Usage:
  bash ./setup_and_deploy_sepolia.sh \
    --private-key 0xYOUR_DEPLOYER_PK \
    --rpc-url https://sepolia.rpc.url \
    --threshold <uint256> \
    [--merkle-root <uint256-or-0xhex>] \
    --etherscan-api-key ETHERSCAN_API_KEY
EOF
}

PK="" RPC_URL="" THRESHOLD="" MERKLE_ROOT="" ETHERSCAN_API_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key)   PK="$2"; shift 2 ;;
    --rpc-url)       RPC_URL="$2"; shift 2 ;;
    --threshold)     THRESHOLD="$2"; shift 2 ;;
    --merkle-root)   MERKLE_ROOT="$2"; shift 2 ;;
    --etherscan-api-key) ETHERSCAN_API_KEY="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

[[ -n "$PK" && -n "$RPC_URL" && -n "$THRESHOLD" && -n "$ETHERSCAN_API_KEY" ]] || {
  echo "Usage: $0 --private-key <0xPK> --rpc-url <URL> --threshold <uint> [--merkle-root <uint|0xhex>] --etherscan-api-key <KEY>"
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_DIR="$ROOT/setup"
CONTRACT_DIR="$ROOT/contract"
MERKLE_FILE="$ROOT/merkle_root.txt"
DEPLOYMENT_FILE="$ROOT/deployment.json"

if [[ -z "$MERKLE_ROOT" ]]; then
  if [[ -f "$MERKLE_FILE" ]]; then
    MERKLE_ROOT="$(tr -d '[:space:]' < "$MERKLE_FILE")"
    echo ">> Using Merkle root from merkle_root.txt: $MERKLE_ROOT"
  else
    echo "Error: --merkle-root not provided and $MERKLE_FILE not found."
    echo "Provide --merkle-root <uint|0xhex> or run Keygen."
    exit 1
  fi
fi

echo ">> Running Go setup..."
pushd "$SETUP_DIR" >/dev/null
  go run .
popd >/dev/null

pushd "$CONTRACT_DIR" >/dev/null
  if [ ! -d "lib/openzeppelin-contracts" ]; then
    forge install OpenZeppelin/openzeppelin-contracts@v5.4.0 --no-commit
  fi
  echo ">> forge build"
  forge build

  echo ">> Deploying to Sepolia..."
  DEPLOY_OUTPUT=$(forge script script/DeployMultiSchnorrVerifier.s.sol:DeployMultischnorr \
      --rpc-url "$RPC_URL" \
      --private-key "$PK" \
      --broadcast \
      --sig "run(uint256,uint256)" "$THRESHOLD" "$MERKLE_ROOT" \
      --etherscan-api-key "$ETHERSCAN_API_KEY" \
      --verify \
      -vvvv 2>&1)

echo "$DEPLOY_OUTPUT"   

VERIFIER_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "Verifier deployed at:" | grep -oE "0x[a-fA-F0-9]{40}" | head -1)
MULTISCHNORR_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "MultischnorrVerifier deployed at:" | grep -oE "0x[a-fA-F0-9]{40}" | head -1)
OWNER_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "owner:" | grep -oE "0x[a-fA-F0-9]{40}" | head -1)

  if [[ -z "$VERIFIER_ADDR" || -z "$MULTISCHNORR_ADDR" ]]; then
    echo "Warning: Could not extract contract addresses from deployment output."
    echo "Please manually create $DEPLOYMENT_FILE with the following structure:"
    cat <<EOF
{
  "network": "sepolia",
  "verifier": "0x...",
  "multiSchnorrVerifier": "0x...",
  "owner": "0x...",
  "deployedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  else
    # Save deployment info to JSON file
    cat > "$DEPLOYMENT_FILE" <<EOF
{
  "network": "sepolia",
  "verifier": "$VERIFIER_ADDR",
  "multiSchnorrVerifier": "$MULTISCHNORR_ADDR",
  "owner": "$OWNER_ADDR",
  "deployedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo ">> Deployment info saved to $DEPLOYMENT_FILE"
  fi

popd >/dev/null

echo ">> Done."
