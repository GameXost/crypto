package symmetric

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileContentReportsIOErrorsAndClosesHandles(t *testing.T) {
	for _, stage := range []string{"read", "write", "sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "input")
			data := []byte("input")
			if stage == "sync" {
				data = nil
			}
			if err := os.WriteFile(inputPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			input, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			output, err := os.Create(filepath.Join(dir, "output"))
			if err != nil {
				input.Close()
				t.Fatal(err)
			}
			if stage == "read" {
				if err := input.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := output.Close(); err != nil {
					t.Fatal(err)
				}
			}
			c := newECBDESContext(t, Zeros)
			if err := c.writeFileContent(input, output, false); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("%s error = %v", stage, err)
			}
			for _, file := range []*os.File{input, output} {
				if _, err := file.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("handle not closed: %v", err)
				}
			}
		})
	}
}

func TestTemporaryCleanupErrorsAreReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned-temp")
	if err := os.WriteFile(path, []byte("temporary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeTempFile(path); err != nil {
		t.Fatal(err)
	}
	if err := removeTempFile(path); err != nil {
		t.Fatalf("missing temp cleanup = %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(path, "keep")
	if err := os.WriteFile(child, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeTempFile(path); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	if data, err := os.ReadFile(child); err != nil || string(data) != "keep" {
		t.Fatal("failed cleanup changed contents")
	}
}
