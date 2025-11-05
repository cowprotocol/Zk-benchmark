#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Key Generation and Merkle Root Preparation for Multi-Schnorr Setup
Usage:
  bash ./keygen.sh 
EOF
}

echo ">> Running keygen with depth from circuit..."
go run ./keygen/main.go
