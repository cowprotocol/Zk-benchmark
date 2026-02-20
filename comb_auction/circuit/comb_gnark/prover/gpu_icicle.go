//go:build icicle

package main

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"

	icicle_bn254 "github.com/consensys/gnark/backend/groth16/bn254/icicle"
)

func loadProvingKey(pkPath string) (groth16.ProvingKey, error) {
	pk := new(icicle_bn254.ProvingKey)
	if err := readFromFile(pkPath, pk); err != nil {
		return nil, err
	}
	return pk, nil
}

func proveWithAccel(cs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	r1cs, ok := cs.(*cs_bn254.R1CS)
	if !ok {
		return nil, fmt.Errorf("icicle build: expected *bn254.R1CS, got %T", cs)
	}
	icpk, ok := pk.(*icicle_bn254.ProvingKey)
	if !ok {
		return nil, fmt.Errorf("icicle build: expected *icicle_bn254.ProvingKey, got %T", pk)
	}
	return icicle_bn254.Prove(r1cs, icpk, w)
}
