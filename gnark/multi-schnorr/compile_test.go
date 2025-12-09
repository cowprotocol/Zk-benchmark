package multischnorr

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestCompile(t *testing.T) {
	var c Circuit

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	fmt.Println("Compiled OK")
	t.Logf("Constraints: %d", cs.GetNbConstraints())
	internal, secret, public := cs.GetNbVariables()
	t.Logf("Variables  : total=%d (internal=%d, secret=%d, public=%d)",
		internal+secret+public, internal, secret, public)

	f, _ := os.Create("circuit.r1cs")
	defer f.Close()
	_, _ = cs.WriteTo(f)
}

// run the command to generate the r1cs file
// go test -v ./...
