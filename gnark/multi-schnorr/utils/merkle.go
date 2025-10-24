package utils

import (
	"errors"
	"fmt"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func BuildRoot(keys []KeyPair) (root fr.Element, leaves []fr.Element, err error) {
	if len(keys) == 0 {
		return fr.Element{}, nil, errors.New("no keys provided")
	}
	if (len(keys) & (len(keys) - 1)) != 0 {
		return fr.Element{}, nil, fmt.Errorf("len(keys) must be a power of two, got %d", len(keys))
	}

	leaves = make([]fr.Element, 0, len(keys))
	for _, k := range keys {
		var ax, ay fr.Element
		ax.SetBigInt(k.Pub.Ax)
		ay.SetBigInt(k.Pub.Ay)

		leaves = append(leaves, hash2(ax, ay))
	}

	cur := make([]fr.Element, len(leaves))
	copy(cur, leaves)

	for w := len(cur); w > 1; w >>= 1 {
		next := make([]fr.Element, w/2)
		for i := 0; i < w/2; i++ {
			next[i] = hash2(cur[2*i], cur[2*i+1])
		}
		cur = next
	}

	fmt.Printf("%v\n", cur[0])
	return cur[0], leaves, nil
}

func hash2(x, y fr.Element) fr.Element {
	h := mimc.NewMiMC()
	h.Write(x.Marshal())
	h.Write(y.Marshal())
	sum := h.Sum(nil)
	var out fr.Element
	_ = out.SetBytes(sum)
	return out
}
