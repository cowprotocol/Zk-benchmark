package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr/utils"
)

func toHex32(x *big.Int) string {
	return "0x" + fmt.Sprintf("%064x", x)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run ./keygen/main.go <numValidators> <maxK>")
		os.Exit(1)
	}

	numValidators, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("invalid numValidators: %w", err))
	}

	maxK, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(fmt.Errorf("invalid maxK: %w", err))
	}

	var keys []utils.KeyPair

	if _, err = os.Stat("keys.json"); err == nil {
		keys, err = utils.LoadKeysFromFile()
		if err != nil {
			panic(fmt.Errorf("failed to load keys: %w", err))
		}
		fmt.Println("Loaded existing keys.json")
	} else {
		keys, err = utils.GeneratePaddedKeyPairs(numValidators, maxK)
		if err != nil {
			panic(fmt.Errorf("failed to generate keys: %w", err))
		}
		if err := utils.SaveKeysToFile(keys); err != nil {
			panic(fmt.Errorf("failed to save keys: %w", err))
		}
		fmt.Println("Generated and saved new keys.json")
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
