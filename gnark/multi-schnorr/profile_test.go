package multischnorr

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

// run with: go test -run TestProfileCircuit -v
// View with: go tool pprof -http=:8080 gnark.pprof
func TestProfileCircuit(t *testing.T) {
	p := profile.Start()
	var c Circuit
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()

	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	t.Logf("profile constraints: %d", p.NbConstraints())
	t.Logf("\n%s", p.Top())
}
