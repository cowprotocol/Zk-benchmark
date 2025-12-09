package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"

	multischnorr "github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr"
	"github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr/utils"
)

type SolidityOutput struct {
	A          [2]*big.Int
	B          [2][2]*big.Int
	C          [2]*big.Int
	Inputs     [3]*big.Int // [Root, Message, SumValid]
	MessageHex string
}

type PublicInputs struct {
	Root     *big.Int
	Message  *big.Int
	SumValid *big.Int
}

const (
	csPath     = "../circuit.r1cs"
	pkPath     = "../setup/multischnorr.g16.pk"
	outputPath = "output.json"
	vkPath     = "../setup/multischnorr.g16.vk"
)

func frFromKeccak(input string) fr.Element {
	var bytes []byte
	if strings.HasPrefix(input, "0x") {
		hexStr := strings.TrimPrefix(input, "0x")
		decoded, err := hex.DecodeString(hexStr)
		if err != nil {
			bytes = []byte(input)
		} else {
			bytes = decoded
		}
	} else {
		bytes = []byte(input)
	}

	h := sha3.NewLegacyKeccak256()
	h.Write(bytes)
	digest := h.Sum(nil)
	r := fr.Modulus()
	bi := new(big.Int).SetBytes(digest)
	bi.Mod(bi, r)
	var out fr.Element
	out.SetBigInt(bi)
	return out
}

// msgToHash is hashed to Fr with Keccak.
func GenerateProof(
	csPath string,
	pkPath string,
	signerIndices []int,
	msgToHash string,
) (groth16.Proof, witness.Witness, PublicInputs, error) {

	wd, err := utils.PrepareWitnessData(
		signerIndices,
		frFromKeccak(msgToHash),
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
	msgToHash string,
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
	var messageHex string
	if strings.HasPrefix(msgToHash, "0x") {
		messageHex = msgToHash
	} else {
		messageHex = "0x" + hex.EncodeToString([]byte(msgToHash))
	}

	output := SolidityOutput{
		A:          a,
		B:          b,
		C:          c,
		Inputs:     [3]*big.Int{rootBI, msgBI, sumValidBI},
		MessageHex: messageHex,
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

	fmt.Printf("\nMessage:\n")
	fmt.Printf("  Original: %s\n", msgToHash)
	fmt.Printf("  Message in Bytes:      %s\n", messageHex)
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

	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: go run . <message> <signer_indices...>\n")
		fmt.Fprintf(os.Stderr, "Example: go run . 'Hello world' 0 1 2 3 4 5 6 7 8 9\n")
		os.Exit(1)
	}

	msgToHash := os.Args[1]

	signerIndices := make([]int, 0, len(os.Args)-2)
	for _, arg := range os.Args[2:] {
		signerIndices = append(signerIndices, atoiOrExit(arg, "signer index"))
	}

	fmt.Printf("Generating proof with msg=%q, signers=%v\n",
		msgToHash, signerIndices)

	proof, _, pubs, err := GenerateProof(csPath, pkPath, signerIndices, msgToHash)
	if err != nil {
		log.Fatalf("GenerateProof failed: %v", err)
	}

	solOut, err := convertProofToSolidityOutput(proof, pubs.Root, pubs.Message, pubs.SumValid, msgToHash)
	if err != nil {
		log.Fatalf("convertProofToSolidityOutput failed: %v", err)
	}
	writeProofJSON(solOut)
}

func atoiOrExit(s string, name string) int {
	val, ok := new(big.Int).SetString(s, 10)
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid %s: %q\n", name, s)
		os.Exit(1)
	}
	return int(val.Int64())
}

func writeProofJSON(out SolidityOutput) {
	data := fmt.Sprintf(`{
  	"proof": [%s,%s,%s,%s,%s,%s,%s,%s],
  	"input": [%s,%s,%s],
	"messageHex":"%s"
	}`,
		out.A[0], out.A[1],
		out.B[0][0], out.B[0][1],
		out.B[1][0], out.B[1][1],
		out.C[0], out.C[1],
		out.Inputs[0], out.Inputs[1], out.Inputs[2],
		out.MessageHex,
	)

	outPath := utils.RepoPath("../proof.json")
	if err := os.WriteFile(outPath, []byte(data), 0644); err != nil {
		log.Fatalf("failed to write %s: %v", outPath, err)
	}
	fmt.Println("Proof exported to", outPath)
}
