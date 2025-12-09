package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	multischnorr "github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var circuit multischnorr.Circuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	fmt.Println("Compiled OK")
	fmt.Printf("Constraints: %d\n", cs.GetNbConstraints())
	internal, secret, public := cs.GetNbVariables()
	fmt.Printf("Variables  : total=%d (internal=%d, secret=%d, public=%d)\n",
		internal+secret+public, internal, secret, public)
	fmt.Println("Writing circuit.r1cs...")

	r1cspath := repoPath("../circuit.r1cs")
	vkPath := "multischnorr.g16.vk"
	pkPath := "multischnorr.g16.pk"
	outDir := repoPath("../contract/src/")
	outPath := filepath.Join(outDir, "Verifier.sol")

	if err := writetoPath(r1cspath, func(f *os.File) error {
		_, err := cs.WriteTo(f)
		return err
	}); err != nil {
		return fmt.Errorf("write r1cs: %w", err)
	}

	fmt.Println("Running setup...")
	fmt.Println("writing proving and verification keys...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	if err := writetoPath(vkPath, func(f *os.File) error {
		_, err := vk.WriteRawTo(f)
		return err
	}); err != nil {
		return err
	}
	if err := writetoPath(pkPath, func(f *os.File) error {
		_, err := pk.WriteRawTo(f)
		return err
	}); err != nil {
		return err
	}

	// Export Solidity verifier
	var buf bytes.Buffer
	if err := vk.ExportSolidity(&buf); err != nil {
		return fmt.Errorf("export solidity: %w", err)
	}

	fmt.Println("writing Verifier contract...")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	if err := os.WriteFile(outPath, []byte(buf.String()), 0o644); err != nil {
		return err
	}

	fmt.Println("Wrote:", outPath)
	fmt.Println("Wrote: multischnorr.g16.vk")
	fmt.Println("Wrote: multischnorr.g16.pk")
	return nil
}

func writetoPath(path string, write func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return write(f)
}

func repoPath(rel string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Clean(filepath.Join(base, rel))
}
