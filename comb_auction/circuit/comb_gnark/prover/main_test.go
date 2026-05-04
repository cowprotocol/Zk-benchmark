package main

//run with go test -v -tags=debug -run TestIsSolved

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	comb "github.com/cowprotocol/Zk-benchmark/comb_auction/gnark"
)

func TestIsSolved(t *testing.T) {
	data, err := os.ReadFile("../../../data/auctions_12310225_12311225.json")
	if err != nil {
		t.Fatal(err)
	}

	var af AuctionsFile
	if err := json.Unmarshal(data, &af); err != nil {
		t.Fatal(err)
	}

	// find auction 12310253
	var auc Auction
	for _, a := range af.Auctions {
		if a.AuctionID == 12310253 {
			auc = a
			break
		}
	}
	if auc.AuctionID == 0 {
		t.Fatal("auction 12310253 not found")
	}

	assignment, _, err := buildWitnessForAuction(auc)
	if err != nil {
		t.Fatal(err)
	}

	err = test.IsSolved(&comb.Circuit{}, assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}
