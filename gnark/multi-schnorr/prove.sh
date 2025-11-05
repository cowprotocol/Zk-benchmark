#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash ./prove.sh \
    --rpc-url <URL> \
    --private-key <0xPK> \
    [--multiSchnorrVerifier <0xVerifierAddress>]\
    --msg "<message string>" \
    --signers "space separated indices"
EOF
}

# ---- parse args ----
RPC_URL="" PK="" MULTISCHNORRVERIFIER="" MSG="" SIGNERS_STR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)       RPC_URL="$2"; shift 2 ;;
    --private-key)   PK="$2"; shift 2 ;;
    --multiSchnorrVerifier)      MULTISCHNORRVERIFIER="$2"; shift 2 ;;
    --msg)           MSG="$2"; shift 2 ;;
    --signers)       SIGNERS_STR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -n "$RPC_URL" && -n "$PK" && -n "$MSG" && -n "$SIGNERS_STR" ]] || { usage; exit 1; }


ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_JSON="$ROOT/deployment.json"
PROVER_DIR="$ROOT/prover"

if [[ -z "$MULTISCHNORRVERIFIER" ]]; then
  if [[ -f "$DEPLOY_JSON" ]]; then
    MULTISCHNORRVERIFIER="$(jq -r '.multiSchnorrVerifier // .verifier // empty' "$DEPLOY_JSON")"
  fi
  [[ -n "${MULTISCHNORRVERIFIER:-}" ]] || { echo "No verifier provided and none found in deployment.json (.multiSchnorrVerifier/.verifier)"; exit 1; }
fi

echo ">> Generating proof…"
# shellcheck disable=SC2206
pushd "$PROVER_DIR" >/dev/null
read -r -a SIGNERS_ARR <<< "$SIGNERS_STR"
  go run . "$MSG" "${SIGNERS_ARR[@]}"
popd >/dev/null

if [[ ! -f proof.json ]]; then
  echo "proof.json not found in repo root." >&2
  exit 1
fi

echo "✓ Proof generated successfully"
echo ">> Reading proof data…"

PROOF=$(jq -c '.proof' proof.json)
INPUT=$(jq -c '.input' proof.json)
MESSAGE_HEX=$(jq -r '.messageHex' proof.json)

MERKLE_ROOT=$(jq -r '.input[0]' proof.json)
SUM_VALID=$(jq -r '.input[2]' proof.json)

echo ">> Sending verifyProof tx…"
cast send \
  --rpc-url "$RPC_URL" \
  --private-key "$PK" \
  "$MULTISCHNORRVERIFIER" \
  "verify(uint256[8],bytes,uint256,uint256)" \
  "$PROOF" "$MESSAGE_HEX" "$MERKLE_ROOT" "$SUM_VALID"
echo ">> Done."