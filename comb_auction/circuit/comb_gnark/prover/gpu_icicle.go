//go:build icicle

package main

import (
	ecc "github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func loadProvingKey(pkPath string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readFromFile(pkPath, pk); err != nil {
		return nil, err
	}
	return pk, nil
}

func proveWithAccel(cs constraint.ConstraintSystem, pk groth16.ProvingKey, w witness.Witness) (groth16.Proof, error) {
	return groth16.Prove(cs, pk, w,
		backend.WithIcicleAcceleration(),
	)
}
