package multischnorr

import (
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	Depth = 6          // Merkle depth
	MaxK  = 1 << Depth // used because we need to declare S of size K as input (MaxK = 2^Depth)
)

// follow Schnorr signature structure (R,s)
type SchnorrSignature struct {
	Rx frontend.Variable
	Ry frontend.Variable
	S  frontend.Variable
}

type Candidate struct {
	Ax, Ay   frontend.Variable // Public key A coordinates
	Sig      SchnorrSignature
	IsIgnore frontend.Variable // 1 if this candidate is to be ignored, 0 otherwise
}

type Circuit struct {
	Root     frontend.Variable `gnark:",public"` // Merkle root of valid public keys
	S        [MaxK]Candidate   // K candidates
	Message  frontend.Variable `gnark:",public"`
	SumValid frontend.Variable `gnark:",public"` // number of valid signatures found
}

func (c *Circuit) Define(api frontend.API) error {
	// Curve parameters (BabyJubJub over BN254 Fr)
	E, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	params, err := twistededwards.GetCurveParams(tedwards.BN254)
	if err != nil {
		return err
	}
	G := twistededwards.Point{X: params.Base[0], Y: params.Base[1]}

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Merkle membership of A under public Root
	// leaf = H(Ax, Ay)
	leaves := make([]frontend.Variable, MaxK)
	for i := 0; i < MaxK; i++ {
		wi := c.S[i]
		h.Reset()
		h.Write(wi.Ax, wi.Ay)
		leaves[i] = h.Sum()
	}

	// tree bottom-up: Since, in most cases we provide 2/3 signatures,
	// its is computationally cheaper to build the tree and then check membership,
	// rather than verifying a Merkle proof for each signature
	currentLevel := leaves
	for d := 0; d < Depth; d++ {
		next := make([]frontend.Variable, len(currentLevel)/2)
		for k := 0; k < len(next); k++ {
			h.Reset()
			h.Write(currentLevel[2*k], currentLevel[2*k+1])
			next[k] = h.Sum()
		}
		currentLevel = next
	}
	computedRoot := currentLevel[0]
	api.AssertIsEqual(computedRoot, c.Root)

	var sumValid frontend.Variable = 0

	// per-candidate checks
	for i := 0; i < MaxK; i++ {
		wi := c.S[i]

		A := twistededwards.Point{X: wi.Ax, Y: wi.Ay}
		R := twistededwards.Point{X: wi.Sig.Rx, Y: wi.Sig.Ry}

		// Safety: on-curve + subgroup (cofactor) checks
		api.AssertIsBoolean(wi.IsIgnore)
		active := api.Sub(1, wi.IsIgnore)

		// gated on-curve checks (A and R): a*x^2 + y^2 = 1 + d*x^2*y^2
		// A on-curve
		x2 := api.Mul(A.X, A.X)
		y2 := api.Mul(A.Y, A.Y)
		ax2 := api.Mul(params.A, x2)
		lhs := api.Add(ax2, y2)
		x2y2 := api.Mul(x2, y2)
		dx2y2 := api.Mul(params.D, x2y2)
		rhs := api.Add(1, dx2y2)
		api.AssertIsEqual(api.Mul(active, api.Sub(lhs, rhs)), 0)

		// R on-curve
		x2R := api.Mul(R.X, R.X)
		y2R := api.Mul(R.Y, R.Y)
		ax2R := api.Mul(params.A, x2R)
		lhsR := api.Add(ax2R, y2R)
		x2y2R := api.Mul(x2R, y2R)
		dx2y2R := api.Mul(params.D, x2y2R)
		rhsR := api.Add(1, dx2y2R)
		api.AssertIsEqual(api.Mul(active, api.Sub(lhsR, rhsR)), 0)

		// Schnorr challenge e = H(Rx, Ry, Ax, Ay, msg)
		h.Reset()
		h.Write(R.X, R.Y, A.X, A.Y, c.Message)
		e := h.Sum() // lives in Fr on BN254

		// check: [S]G == R + [e]A
		sG := E.ScalarMul(G, wi.Sig.S)
		eA := E.ScalarMul(A, e)
		rhsP := E.Add(R, eA)
		api.AssertIsEqual(api.Mul(active, api.Sub(sG.X, rhsP.X)), 0)
		api.AssertIsEqual(api.Mul(active, api.Sub(sG.Y, rhsP.Y)), 0)
		okX := api.IsZero(api.Sub(sG.X, rhsP.X))
		okY := api.IsZero(api.Sub(sG.Y, rhsP.Y))

		// valid = active ∧ okX ∧ okY  (AND via multiplication)
		valid := api.Mul(active, okX)
		valid = api.Mul(valid, okY)

		sumValid = api.Add(sumValid, valid)
	}

	api.AssertIsEqual(sumValid, c.SumValid)
	return nil
}
