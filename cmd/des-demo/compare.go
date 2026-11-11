package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

func compareFiles(left, right string) (err error) {
	first, err := os.Open(left)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, first.Close())
	}()
	second, err := os.Open(right)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, second.Close())
	}()
	if err := compareReaders(first, second); err != nil {
		return fmt.Errorf("compare %q and %q: %w", left, right, err)
	}
	return nil
}

func compareReaders(left, right io.Reader) error {
	first, second := make([]byte, 65536), make([]byte, 65536)
	for {
		n, err := readComparisonChunk(left, first)
		if err != nil {
			return err
		}
		m, err := readComparisonChunk(right, second)
		if err != nil {
			return err
		}
		if n != m || !bytes.Equal(first[:n], second[:m]) {
			return fmt.Errorf("restored file differs from input")
		}
		if n < len(first) {
			return nil
		}
	}
}

func readComparisonChunk(input io.Reader, buffer []byte) (int, error) {
	n, err := io.ReadFull(input, buffer)
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		return n, nil
	}
	return n, err
}
