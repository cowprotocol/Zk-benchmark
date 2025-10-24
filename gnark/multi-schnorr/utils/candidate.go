package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tebn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type SchnorrSignature struct {
	Rx *big.Int
	Ry *big.Int
	S  *big.Int
}

type Candidate struct {
	Ax, Ay   *big.Int
	Sig      SchnorrSignature
	IsIgnore uint8 // 1 if this candidate is to be ignored, 0 otherwise
}

func Sign(sk *big.Int, pub PubKey, msg fr.Element, rng io.Reader, nonce *big.Int) (SchnorrSignature, error) {
	params := tebn254.GetEdwardsCurve()
	G := params.Base
	order := new(big.Int).Set(&params.Order)

	if rng == nil {
		rng = rand.Reader
	}

	// nonce k in [1, order-1]
	var k *big.Int
	if nonce != nil {
		k = new(big.Int).Mod(nonce, order) // reduce
		if k.Sign() == 0 {
			return SchnorrSignature{}, fmt.Errorf("nonce reduced to zero")
		}
	} else {
		var err error
		for {
			k, err = rand.Int(rng, order) // [0, order)
			if err != nil {
				return SchnorrSignature{}, err
			}
			if k.Sign() != 0 {
				break
			}
		}
	}

	// R = [k]G
	var R tebn254.PointAffine
	R.ScalarMultiplication(&G, k)

	// e = MiMC(Rx, Ry, Ax, Ay, msg) (Fr)
	var rx, ry, ax, ay fr.Element
	rx.SetBigInt(R.X.BigInt(new(big.Int)))
	ry.SetBigInt(R.Y.BigInt(new(big.Int)))
	ax.SetBigInt(pub.Ax)
	ay.SetBigInt(pub.Ay)

	e := hash5(rx, ry, ax, ay, msg)

	// S = k + e*sk (mod order)
	eBig := e.BigInt(new(big.Int))
	S := new(big.Int).Mul(eBig, sk)
	S.Mod(S, order)
	S.Add(S, k)
	S.Mod(S, order)

	return SchnorrSignature{
		Rx: R.X.BigInt(new(big.Int)),
		Ry: R.Y.BigInt(new(big.Int)),
		S:  S,
	}, nil
}

func hash5(x1, x2, x3, x4, x5 fr.Element) fr.Element {
	h := mimc.NewMiMC()
	h.Write(x1.Marshal())
	h.Write(x2.Marshal())
	h.Write(x3.Marshal())
	h.Write(x4.Marshal())
	h.Write(x5.Marshal())
	sum := h.Sum(nil)
	var out fr.Element
	_ = out.SetBytes(sum)
	return out
}

func addAffine(P, Q tebn254.PointAffine) tebn254.PointAffine {
	var R tebn254.PointAffine
	R.Add(&P, &Q)
	return R
}

func zeroSig() SchnorrSignature { return SchnorrSignature{big.NewInt(0), big.NewInt(1), big.NewInt(1)} }

// assumes KeyPairs are padded already (MaxK length, with zeroed keys at the end)
func BuildCandidates(
	keys []KeyPair,
	signerIdx []int,
	msg fr.Element,
	rng io.Reader,
	nonce *big.Int,
) ([]Candidate, int, error) {

	if len(keys) == 0 {
		return nil, 0, fmt.Errorf("no keys provided")
	}

	signerSet := make(map[int]struct{}, len(signerIdx))
	for _, i := range signerIdx {
		if i < 0 || i >= len(keys) {
			return nil, 0, fmt.Errorf("signer index %d out of range [0,%d)", i, len(keys))
		}
		signerSet[i] = struct{}{}
	}

	out := make([]Candidate, len(keys))
	sumValid := 0

	for i := range keys {
		ax := keys[i].Pub.Ax
		ay := keys[i].Pub.Ay

		// default: ignored with zero sig
		c := Candidate{
			Ax: ax, Ay: ay,
			Sig:      zeroSig(),
			IsIgnore: 1,
		}

		if _, want := signerSet[i]; want {
			if keys[i].Priv.Sk.Cmp(big.NewInt(0)) == 0 {
				return nil, 0, fmt.Errorf("index %d marked as signer but has nil/zero SK", i)
			}
			sig, err := Sign(keys[i].Priv.Sk, keys[i].Pub, msg, rng, nonce)
			if err != nil {
				return nil, 0, fmt.Errorf("sign(%d): %w", i, err)
			}
			c.Sig = SchnorrSignature{sig.Rx, sig.Ry, sig.S}
			c.IsIgnore = 0
			sumValid++
		}

		out[i] = c
	}

	return out, sumValid, nil
}
