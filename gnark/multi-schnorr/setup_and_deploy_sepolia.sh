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

if [[ -z "$MERKLE_ROOT" ]]; then
  if [[ -f "$MERKLE_FILE" ]]; then
    MERKLE_ROOT="$(tr -d '[:space:]' < "$MERKLE_FILE")"
    echo ">> Using Merkle root from merkle_root.txt: $MERKLE_ROOT"
  else
    echo "Error: --merkle-root not provided and $MERKLE_FILE not found."
    echo "Provide --merkle-root <uint|0xhex> or create merkle_root.txt."
    exit 1
  fi
fi

echo ">> Running Go setup..."
pushd "$SETUP_DIR" >/dev/null
  go run .
popd >/dev/null

pushd "$CONTRACT_DIR" >/dev/null
  echo ">> forge build"
  forge build

  echo ">> Deploying to Sepolia..."
  forge script script/DeployMultiSchnorrVerifier.s.sol:DeployMultischnorr \
      --rpc-url "$RPC_URL" \
      --private-key "$PK" \
      --broadcast \
      --sig "run(uint256,uint256)" "$THRESHOLD" "$MERKLE_ROOT" \
      --etherscan-api-key "$ETHERSCAN_API_KEY" \
      --verify \
      -vvvv

popd >/dev/null

echo ">> Done."
