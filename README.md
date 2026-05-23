# Zk-benchmark

This repository contains zero-knowledge benchmark and proof-of-concept implementations for validating different parts of (decentralised) CoW Protocol computation.

The repo currently focuses on three main tracks:

1. **Multi-Schnorr signature verification in gnark**
2. **Multi-zkVM multi-schnorr signature verification benchmarks**
3. **Combinatorial auction winner-selection circuits**

Each subproject has its own **README** with detailed setup, architecture, and running instructions. 

---

## Repository Structure

```text
.
├── gnark/
│   └── multi-schnorr/
│       └── README.md
├── multi-zkvm/
│   └── README.md
└── comb_auction/
    └── README.md
