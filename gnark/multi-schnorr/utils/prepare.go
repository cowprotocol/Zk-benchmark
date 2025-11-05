package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"

	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	multischnorr "github.com/cowprotocol/Zk-benchmark/gnark/multi-schnorr"
)

type WitnessData struct {
	Root       fr.Element
	Candidates []Candidate
	Message    fr.Element
	SumValid   int
}

type SerializableKeyPair struct {
	PrivSk string `json:"priv_sk"`
	PubAx  string `json:"pub_ax"`
	PubAy  string `json:"pub_ay"`
}

type SerializableKeys struct {
	Keys []SerializableKeyPair `json:"keys"`
}

var keyPath = RepoPath("../keys.json")

func toSerializable(keys []KeyPair) SerializableKeys {
	sk := SerializableKeys{
		Keys: make([]SerializableKeyPair, len(keys)),
	}
	for i, k := range keys {
		sk.Keys[i] = SerializableKeyPair{
			PrivSk: k.Priv.Sk.Text(16),
			PubAx:  k.Pub.Ax.Text(16),
			PubAy:  k.Pub.Ay.Text(16),
		}
	}
	return sk
}

func fromSerializable(sk SerializableKeys) ([]KeyPair, error) {
	keys := make([]KeyPair, len(sk.Keys))
	for i, k := range sk.Keys {
		privSk, ok := new(big.Int).SetString(k.PrivSk, 16)
		if !ok {
			return nil, fmt.Errorf("failed to parse private key at index %d", i)
		}
		pubAx, ok := new(big.Int).SetString(k.PubAx, 16)
		if !ok {
			return nil, fmt.Errorf("failed to parse public key Ax at index %d", i)
		}
		pubAy, ok := new(big.Int).SetString(k.PubAy, 16)
		if !ok {
			return nil, fmt.Errorf("failed to parse public key Ay at index %d", i)
		}

		keys[i] = KeyPair{
			Priv: PrivKey{Sk: privSk},
			Pub:  PubKey{Ax: pubAx, Ay: pubAy},
		}
	}
	return keys, nil
}

func SaveKeysToFile(keys []KeyPair) error {
	sk := toSerializable(keys)
	data, err := json.MarshalIndent(sk, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	err = os.WriteFile(keyPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write keys to file: %w", err)
	}

	fmt.Printf("Saved %d keys to %s\n", len(keys), keyPath)
	return nil
}

func LoadKeysFromFile() ([]KeyPair, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var sk SerializableKeys
	err = json.Unmarshal(data, &sk)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	keys, err := fromSerializable(sk)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Loaded %d keys from %s\n", len(keys), keyPath)
	return keys, nil
}

func PrepareWitnessData(
	signerIndices []int,
	message fr.Element,
	rng io.Reader,
	nonce *big.Int,
) (*WitnessData, error) {
	maxK := multischnorr.MaxK
	if len(signerIndices) > maxK {
		return nil, fmt.Errorf("signerindices (%d) > maxK (%d)", len(signerIndices), maxK)
	}
	if len(signerIndices) < 0 {
		return nil, fmt.Errorf("signerindices must be >= 0")
	}

	var keys []KeyPair
	var err error

	if _, err := os.Stat(keyPath); err == nil {
		fmt.Println("Key file found, loading keys...")
		keys, err = LoadKeysFromFile()
		if err != nil {
			return nil, fmt.Errorf("failed to load keys: %w", err)
		}
		if len(keys) != maxK {
			return nil, fmt.Errorf("keys.json has %d keys, expected maxK=%d; regenerate keys.json", len(keys), maxK)
		}
	} else {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("keys.json not found at %s; run keygen first", keyPath)
		}
		return nil, fmt.Errorf("stat %s: %w", keyPath, err)
	}

	fmt.Println("Building Merkle root...")
	root, _, err := BuildRoot(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to build merkle root: %w", err)
	}

	fmt.Printf("Generating signatures for %d signers...\n", len(signerIndices))
	candidates, sumValid, err := BuildCandidates(keys, signerIndices, message, rng, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to build candidates: %w", err)
	}

	witnessData := &WitnessData{
		Root:       root,
		Candidates: candidates,
		Message:    message,
		SumValid:   sumValid,
	}

	fmt.Printf("Witness data prepared: root=%s, sumValid=%d\n", root.String(), sumValid)
	return witnessData, nil
}

func RepoPath(rel string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	base := filepath.Dir(thisFile)
	return filepath.Clean(filepath.Join(base, rel))
}
