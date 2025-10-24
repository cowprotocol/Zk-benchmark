package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"

	multischnorr "github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr"
	"github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr/utils"
)

type SolidityOutput struct {
	A      [2]*big.Int
	B      [2][2]*big.Int
	C      [2]*big.Int
	Inputs [3]*big.Int // [Root, Message, SumValid]
}

type PublicInputs struct {
	Root     *big.Int
	Message  *big.Int
	SumValid *big.Int
}

const outputPath = "output.json"
const vkPath = "../setup/multischnorr.g16.vk"

func frFromStringMiMC(s string) fr.Element {
	h := mimc.NewMiMC()
	h.Write([]byte(s))
	sum := h.Sum(nil)
	var out fr.Element
	_ = out.SetBytes(sum)
	return out
}

// msgToHash is hashed to Fr with MiMC (must match challenge construction).
func GenerateProof(
	csPath string,
	pkPath string,
	numValidators int,
	maxK int,
	signerIndices []int,
	msgToHash string,
) (groth16.Proof, witness.Witness, PublicInputs, error) {

	wd, err := utils.PrepareWitnessData(
		numValidators,
		maxK,
		signerIndices,
		frFromStringMiMC(msgToHash),
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, PublicInputs{}, fmt.Errorf("prepare witness data: %w", err)
	}

	assignment := new(multischnorr.Circuit)
	assignment.Root = wd.Root.BigInt(new(big.Int))
	assignment.Message = wd.Message.BigInt(new(big.Int))
	assignment.SumValid = big.NewInt(int64(wd.SumValid))

	for i := 0; i < multischnorr.MaxK; i++ {
		c := wd.Candidates[i]
		assignment.S[i].Ax = c.Ax
		assignment.S[i].Ay = c.Ay
		assignment.S[i].Sig.Rx = c.Sig.Rx
		assignment.S[i].Sig.Ry = c.Sig.Ry
		assignment.S[i].Sig.S = c.Sig.S
		assignment.S[i].IsIgnore = big.NewInt(int64(c.IsIgnore))
	}

	fullW, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, PublicInputs{}, fmt.Errorf("NewWitness: %w", err)
	}

	cs := groth16.NewCS(ecc.BN254)
	if err := readFromFile(csPath, cs); err != nil {
		return nil, nil, PublicInputs{}, fmt.Errorf("read CS: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readFromFile(pkPath, pk); err != nil {
		return nil, nil, PublicInputs{}, fmt.Errorf("read PK: %w", err)
	}

	proof, err := groth16.Prove(cs, pk, fullW)
	if err != nil {
		return nil, nil, PublicInputs{}, fmt.Errorf("Prove: %w", err)
	}

	publics := PublicInputs{
		Root:     wd.Root.BigInt(new(big.Int)),
		Message:  wd.Message.BigInt(new(big.Int)),
		SumValid: big.NewInt(int64(wd.SumValid)),
	}

	println("proof", proof)
	return proof, fullW, publics, nil
}

func verifyProofLocally(
	proof *groth16.Proof,
	fullW witness.Witness,
) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFromFile(vkPath, vk); err != nil {
		log.Fatalf("read VK: %v", err)
	}
	pubW, err := fullW.Public()
	if err != nil {
		return fmt.Errorf("Public(): %w", err)
	}
	err = groth16.Verify(*proof, vk, pubW)
	if err != nil {
		log.Fatalf("Local verification failed: %v", err)
	}
	fmt.Println("✓ Local verification passed!")
	return nil
}

func convertProofToSolidityOutput(
	proof groth16.Proof,
	rootBI, msgBI, sumValidBI *big.Int,
) (SolidityOutput, error) {
	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		return SolidityOutput{}, fmt.Errorf("WriteRawTo: %w", err)
	}
	proofBytes := buf.Bytes()

	const fpSize = 32
	if len(proofBytes) < 8*fpSize {
		return SolidityOutput{}, fmt.Errorf("raw proof too small: %d bytes, expected at least %d", len(proofBytes), 8*fpSize)
	}

	var a [2]*big.Int
	var b [2][2]*big.Int
	var c [2]*big.Int

	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	output := SolidityOutput{
		A:      a,
		B:      b,
		C:      c,
		Inputs: [3]*big.Int{rootBI, msgBI, sumValidBI},
	}

	fmt.Println("\n=== Solidity Output ===")
	fmt.Printf("A (G1 Point):\n")
	fmt.Printf("  A[0]: %s\n", a[0].String())
	fmt.Printf("  A[1]: %s\n", a[1].String())

	fmt.Printf("\nB (G2 Point):\n")
	fmt.Printf("  B[0][0]: %s\n", b[0][0].String())
	fmt.Printf("  B[0][1]: %s\n", b[0][1].String())
	fmt.Printf("  B[1][0]: %s\n", b[1][0].String())
	fmt.Printf("  B[1][1]: %s\n", b[1][1].String())

	fmt.Printf("\nC (G1 Point):\n")
	fmt.Printf("  C[0]: %s\n", c[0].String())
	fmt.Printf("  C[1]: %s\n", c[1].String())

	fmt.Printf("\nPublic Inputs:\n")
	fmt.Printf("  Root:     %s\n", rootBI.String())
	fmt.Printf("  Message:  %s\n", msgBI.String())
	fmt.Printf("  SumValid: %s\n", sumValidBI.String())
	fmt.Println("======================\n")

	return output, nil
}

func readFromFile(path string, r interface {
	ReadFrom(io.Reader) (int64, error)
}) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = r.ReadFrom(f)
	return err
}

func main() {
	const (
		csPath = "../circuit.r1cs"
		pkPath = "../setup/multischnorr.g16.pk"

		numValidators = 50
		maxK          = 64
	)

	msgToHash := "Hello world"

	signerIndices := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 44, 45, 47, 48}

	fmt.Println("Generating proof...")
	proof, _, pubs, err := GenerateProof(
		csPath,
		pkPath,
		numValidators,
		maxK,
		signerIndices,
		msgToHash,
	)
	_, err = convertProofToSolidityOutput(
		proof,
		pubs.Root, pubs.Message, pubs.SumValid,
	)
	if err != nil {
		log.Fatalf("Failed to convert proof to Solidity output: %v", err)
	}
}
