#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash ./prove.sh \
    --rpc-url <URL> \
    --private-key <0xPK> \
    --verifier <0xVerifierAddress> \
    --msg "<message string>" \
    --maxK <power-of-2> \
    --signers "space separated indices"
EOF
}

# ---- parse args ----
RPC_URL="" PK="" VERIFIER="" MSG="" MAXK="" SIGNERS_STR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)       RPC_URL="$2"; shift 2 ;;
    --private-key)   PK="$2"; shift 2 ;;
    --verifier)      VERIFIER="$2"; shift 2 ;;
    --msg)           MSG="$2"; shift 2 ;;
    --maxK)          MAXK="$2"; shift 2 ;;
    --signers)       SIGNERS_STR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -n "$RPC_URL" && -n "$PK" && -n "$VERIFIER" && -n "$MSG" && -n "$MAXK" && -n "$SIGNERS_STR" ]] || { usage; exit 1; }


ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVER_DIR="$ROOT/prover"
echo ">> Generating proof…"
# shellcheck disable=SC2206
pushd "$PROVER_DIR" >/dev/null
read -r -a SIGNERS_ARR <<< "$SIGNERS_STR"
  go run . "$MSG" "$MAXK" "${SIGNERS_ARR[@]}"
popd >/dev/null

if [[ ! -f proof.json ]]; then
  echo "proof.json not found in repo root." >&2
  exit 1
fi

PROOF=$(jq -c '.proof' proof.json)
INPUT=$(jq -c '.input' proof.json)

echo ">> Sending verifyProof tx…"
cast send \
  --rpc-url "$RPC_URL" \
  --private-key "$PK" \
  "$VERIFIER" \
  "verifyProof(uint256[8],uint256[3])" \
  "$PROOF" "$INPUT"
echo ">> Done."