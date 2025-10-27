#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Key Generation and Merkle Root Preparation for Multi-Schnorr Setup
Usage:
  bash ./keygen.sh \
    --num-validators <N> \
    --maxK <K>
EOF
}

NUM_VALIDATORS=""
MAXK=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --num-validators) NUM_VALIDATORS="$2"; shift 2 ;;
    --maxK)           MAXK="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

[[ -n "$NUM_VALIDATORS" && -n "$MAXK" ]] || usage

echo ">> Running keygen with $NUM_VALIDATORS validators (maxK=$MAXK)"
go run ./keygen/main.go "$NUM_VALIDATORS" "$MAXK"
