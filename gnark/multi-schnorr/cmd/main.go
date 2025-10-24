package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr/utils"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	const maxK = 64
	const numValidators = 50
	signerIndices := make([]int, 45)
	for i := 0; i < 45; i++ {
		signerIndices[i] = i
	}

	// Message to sign
	var message fr.Element
	_, _ = message.SetString("12345678901234567890")

	witnessData, err := utils.PrepareWitnessData(
		numValidators,
		maxK,
		signerIndices,
		message,
		rand.Reader,
		nil,
	)
	if err != nil {
		panic(fmt.Errorf("failed to prepare witness data: %w", err))
	}

	fmt.Printf("Root (public): 0x%s\n", witnessData.Root.BigInt(new(big.Int)).Text(16))
	fmt.Printf("Message (public): 0x%s\n", witnessData.Message.BigInt(new(big.Int)).Text(16))
	fmt.Printf("SumValid (public): %d\n", witnessData.SumValid)
}
