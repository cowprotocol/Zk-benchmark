package main

import (
	"fmt"
	"math/big"
	"os"

	multischnorr "github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr"
	"github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr/utils"
)

func toHex32(x *big.Int) string {
	return "0x" + fmt.Sprintf("%064x", x)
}

func main() {
	// read depth from circuit.go
	depth := multischnorr.Depth

	// used for simplicity in testing
	// depth of merkle tree is fixed to 6 in circuit
	// if needed, can be modified to take depth and numValidators as input
	numValidators := 1 << depth

	var keys []utils.KeyPair
	var err error

	if _, err = os.Stat("keys.json"); err == nil {
		keys, err = utils.LoadKeysFromFile()
		if err != nil {
			panic(fmt.Errorf("failed to load keys: %w", err))
		}
		fmt.Println("Loaded existing keys.json")
	} else {
		keys, err = utils.GeneratePaddedKeyPairs(numValidators, depth)
		if err != nil {
			panic(fmt.Errorf("failed to generate keys: %w", err))
		}
		if err := utils.SaveKeysToFile(keys); err != nil {
			panic(fmt.Errorf("failed to save keys: %w", err))
		}
		fmt.Println("Generated and saved new keys.json")
	}

	if len(keys) != (1 << depth) {
		panic(fmt.Errorf("len(keys) must be %d, got %d", 1<<depth, len(keys)))
	}

	root, _, err := utils.BuildRoot(keys)
	if err != nil {
		panic(fmt.Errorf("failed to build merkle root: %w", err))
	}
	rootHex := toHex32(root.BigInt(new(big.Int)))

	if err := os.WriteFile("merkle_root.txt", []byte(rootHex+"\n"), 0o644); err != nil {
		panic(fmt.Errorf("failed to write merkle_root.txt: %w", err))
	}

	fmt.Println("Merkle root:", rootHex)
	fmt.Println("✅ merkle_root.txt written successfully")
}
