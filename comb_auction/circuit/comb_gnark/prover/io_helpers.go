package main

import (
	"io"
	"os"
	"path/filepath"
)

func readFromFile(path string, r interface {
	ReadFrom(io.Reader) (int64, error)
}) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = r.ReadFrom(f)
	return err
}
