package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCompareFilesExact(t *testing.T) {
	for _, plain := range [][]byte{nil, []byte("small"), bytes.Repeat([]byte{0x41}, 2*65536+17)} {
		dir := t.TempDir()
		left, right := filepath.Join(dir, "left"), filepath.Join(dir, "right")
		if err := os.WriteFile(left, plain, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(right, plain, 0600); err != nil {
			t.Fatal(err)
		}
		if err := compareFiles(left, right); err != nil {
			t.Fatalf("equal files rejected: %v", err)
		}
		changed := append(bytes.Clone(plain), 1)
		if err := os.WriteFile(right, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := compareFiles(left, right); err == nil {
			t.Fatal("different lengths accepted")
		}
		if len(plain) > 0 {
			changed = bytes.Clone(plain)
			changed[len(changed)-1] ^= 0xff
			if err := os.WriteFile(right, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if err := compareFiles(left, right); err == nil {
				t.Fatal("different last byte accepted")
			}
		}
		if err := compareFiles(filepath.Join(dir, "missing"), right); err == nil {
			t.Fatal("missing source accepted")
		}
		if err := compareFiles(left, filepath.Join(dir, "missing")); err == nil {
			t.Fatal("missing restored file accepted")
		}
	}
}

type brokenReader struct{ err error }

func (r brokenReader) Read([]byte) (int, error) { return 0, r.err }

func TestCompareReadersPropagatesReadErrors(t *testing.T) {
	sentinel := errors.New("comparison read failed")
	for _, readers := range [][2]io.Reader{{brokenReader{sentinel}, bytes.NewReader(nil)}, {bytes.NewReader(nil), brokenReader{sentinel}}} {
		if err := compareReaders(readers[0], readers[1]); !errors.Is(err, sentinel) {
			t.Fatalf("comparison error=%v", err)
		}
	}
}
