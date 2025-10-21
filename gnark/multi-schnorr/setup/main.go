package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

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

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	if err := writeKey("multischnorr.g16.vk", func(f *os.File) error {
		_, err := vk.WriteRawTo(f)
		return err
	}); err != nil {
		return err
	}
	if err := writeKey("multischnorr.g16.pk", func(f *os.File) error {
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
	exported := buf.String()

	// Extract all uint256 verifier constants from gnark’s exported contract
	constantsBlock, err := extractUint256Constants(exported)
	if err != nil {
		return err
	}
	if !strings.Contains(constantsBlock, "ALPHA_") ||
		!strings.Contains(constantsBlock, "BETA_NEG_") ||
		!strings.Contains(constantsBlock, "GAMMA_NEG_") ||
		!strings.Contains(constantsBlock, "DELTA_NEG_") ||
		!strings.Contains(constantsBlock, "CONSTANT_") ||
		!strings.Contains(constantsBlock, "PUB_") {
		return fmt.Errorf("failed to find expected constants in exported verifier; got:\n%s", constantsBlock)
	}

	sol := strings.Replace(multischnorrTemplate, "/*{{CONSTANTS}}*/", constantsBlock, 1)

	// Write to contract/src/MultischnorrVerifier.sol
	outDir := repoPath("../contract/src/")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	outPath := filepath.Join(outDir, "MultischnorrVerifier.sol")
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("file already exists: %s (delete or move it first)", outPath)
	}
	if err := os.WriteFile(outPath, []byte(sol), 0o644); err != nil {
		return err
	}

	fmt.Println("Wrote:", outPath)
	fmt.Println("Wrote: multischnorr.g16.vk")
	fmt.Println("Wrote: multischnorr.g16.pk")
	return nil
}

// writeKey writes a key file, ensuring it does not already exist
func writeKey(path string, write func(*os.File) error) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("file already exists: %s", path)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return write(f)
}

// Scrape uint256 constants from gnark’s exported verifier
func extractUint256Constants(sol string) (string, error) {
	// locate the block of uint256 constant declarations
	start := strings.Index(sol, "uint256 constant ")
	if start == -1 {
		return "", fmt.Errorf("no uint256 constant block found in exported solidity")
	}
	end := strings.Index(sol[start:], "\n    function ")
	if end == -1 {
		end = len(sol)
	} else {
		end = start + end
	}
	block := sol[start:end]

	// regex to match uint256 constant lines
	re := regexp.MustCompile(`(?m)^\s*uint256\s+constant\s+([A-Za-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+);`)
	lines := re.FindAllStringSubmatch(block, -1)
	if len(lines) == 0 {
		return "", fmt.Errorf("no uint256 constants matched in exported solidity")
	}

	// decide which constants to keep
	keep := func(name string) bool {
		switch {
		case strings.HasPrefix(name, "ALPHA_"),
			strings.HasPrefix(name, "BETA_NEG_"),
			strings.HasPrefix(name, "GAMMA_NEG_"),
			strings.HasPrefix(name, "DELTA_NEG_"),
			strings.HasPrefix(name, "CONSTANT_"),
			strings.HasPrefix(name, "PUB_"),
			strings.HasPrefix(name, "FRACTION_"),
			strings.HasPrefix(name, "EXP_"):
			return true
		default:
			return false
		}
	}

	// filter and deduplicate
	seen := make(map[string]bool)
	var out []string
	for _, m := range lines {
		name := m[1]
		full := m[0]
		if !keep(name) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, full)
	}

	if len(out) == 0 {
		return "", fmt.Errorf("after filtering, no constants remained to inject")
	}
	return strings.Join(out, "\n"), nil
}

func repoPath(rel string) string {
	// Resolve relative to this source file (inside setup/)
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Clean(filepath.Join(base, rel))
}
