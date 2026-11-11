package symmetric

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFileOutputRejectsEmptyPath(t *testing.T) {
	if err := checkFileOutput("", nil, false); err == nil {
		t.Fatal("empty output path accepted")
	}
}

func TestPublishFileDoesNotReplaceLateDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	temporary := filepath.Join(dir, "temporary")
	destination := filepath.Join(dir, "destination")
	if err := os.WriteFile(source, []byte("input"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFileOutput(destination, info, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporary, []byte("completed result"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("another writer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishFile(temporary, destination, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("publishFile() = %v; want os.ErrExist", err)
	}
	for path, want := range map[string]string{
		temporary:   "completed result",
		destination: "another writer",
	} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("ReadFile(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
}
