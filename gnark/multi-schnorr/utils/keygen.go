package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	tebn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// compatible with the gnark circuit that uses twistededwards.NewEdCurve(api, tedwards.BN254)

// BabyJubJub private scalar
type PrivKey struct {
	Sk *big.Int // 1 <= Sk < Order
}

// BabyJubJub affine point
type PubKey struct {
	Ax *big.Int
	Ay *big.Int
}

type KeyPair struct {
	Priv PrivKey
	Pub  PubKey
}

// samples Sk uniformly in [1, order-1]
// where G is the BabyJub generator
func GenerateKeyPairs(n int) ([]KeyPair, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n must be > 0")
	}

	params := tebn254.GetEdwardsCurve()
	G := params.Base
	order := new(big.Int).Set(&params.Order)

	out := make([]KeyPair, 0, n)
	for i := 0; i < n; i++ {
		sk, err := rand.Int(rand.Reader, order)
		if err != nil {
			return nil, err
		}
		if sk.Sign() == 0 {
			i--
			continue
		}

		// A = [sk]G
		var A tebn254.PointAffine
		A.ScalarMultiplication(&G, sk)

		out = append(out, KeyPair{
			Priv: PrivKey{Sk: sk},
			Pub: PubKey{
				Ax: A.X.BigInt(new(big.Int)),
				Ay: A.Y.BigInt(new(big.Int)),
			},
		})
	}
	println("Generated", n, "key pairs")
	return out, nil
}

// returns a uniform scalar in [1, order-1]
func randScalar(order *big.Int) (*big.Int, error) {
	k, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Ax=0, Ay=1 is the identity point in BabyJubJub
// so that the circuit’s leaf H(Ax,Ay) matches the padded leaf
func GeneratePaddedKeyPairs(n, depth int) ([]KeyPair, error) {
	maxK := 1 << depth
	if n < 0 {
		return nil, fmt.Errorf("n must be >= 0")
	}
	if depth <= 0 {
		return nil, fmt.Errorf("depth must be > 0")
	}
	if n > maxK {
		return nil, fmt.Errorf("n (%d) > maxK (%d), cannot have more keys than maxK", n, maxK)
	}

	kps, err := GenerateKeyPairs(n)
	if err != nil {
		return nil, err
	}

	out := make([]KeyPair, 0, maxK)
	out = append(out, kps...)
	for len(out) < maxK {
		out = append(out, KeyPair{
			Priv: PrivKey{Sk: big.NewInt(0)},
			Pub:  PubKey{Ax: big.NewInt(0), Ay: big.NewInt(1)},
		})
	}
	return out, nil
}
