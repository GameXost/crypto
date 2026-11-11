package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCipherDemo(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		blockSize int
	}{
		{"DES", nil, 8},
		{"DEAL", []string{"-cipher", "deal"}, 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.bin")
			plain := []byte{1, 2, 3, 0, 4, 5, 0}
			if err := os.WriteFile(input, plain, 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "results")
			var report bytes.Buffer
			args := append([]string{"-out", out, "-workers", "1"}, test.args...)
			if err := run(append(args, input), &report); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"} {
				data, err := os.ReadFile(filepath.Join(out, mode, "restored-01-input.bin"))
				if err != nil || !bytes.Equal(data, plain) {
					t.Fatalf("%s restore=%x,%v", mode, data, err)
				}
				info, err := os.Stat(filepath.Join(out, mode, "01-input.bin.enc"))
				if err != nil {
					t.Fatal(err)
				}
				wantSize := test.blockSize * 2
				if mode == "ECB" {
					wantSize = test.blockSize
				}
				if info.Size() != int64(wantSize) {
					t.Fatalf("%s encrypted size=%d, want %d", mode, info.Size(), wantSize)
				}
				if !strings.Contains(report.String(), mode) {
					t.Fatalf("report omits %s", mode)
				}
			}
			if !strings.Contains(report.String(), out) {
				t.Fatal("report omits output location")
			}
			if !strings.Contains(report.String(), test.name+" | PKCS7 | workers=1") {
				t.Fatalf("wrong cipher in report: %s", report.String())
			}
			if got, err := os.ReadFile(input); err != nil || !bytes.Equal(got, plain) {
				t.Fatal("demo changed original input")
			}
		})
	}
}

func TestRunRejectsInvalidArgumentsWithoutOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("input"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-cipher", "unknown", input}, {"-cipher", "", input}, {"-workers", "0", input}, {"-workers", "-1", input}, {"-workers", "oops", input}, {"-unknown"}, {filepath.Join(dir, "missing")}, {dir}} {
		out := filepath.Join(dir, "output")
		all := append([]string{"-out", out}, args...)
		if err := run(all, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid arguments created output: %v", err)
		}
	}
	if err := run([]string{"-h"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("help error=%v", err)
	}
}

func TestRunRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("input"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(output, "keep")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-out", output, input}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing output accepted")
	}
	if got, err := os.ReadFile(keep); err != nil || string(got) != "keep" {
		t.Fatal("existing content changed")
	}
}

type failedReport struct{ err error }

func (w failedReport) Write([]byte) (int, error) { return 0, w.err }

func TestRunReportsOutputFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("input"), 0600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("report failed")
	if err := run([]string{"-out", filepath.Join(dir, "result"), input}, failedReport{sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("report error=%v", err)
	}
}

func TestRunHandlesInputsWithSameName(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 2)
	for i, name := range []string{"first", "second"} {
		parent := filepath.Join(dir, name)
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		paths[i] = filepath.Join(parent, "same.txt")
		if err := os.WriteFile(paths[i], []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "results")
	var report bytes.Buffer
	if err := run(append([]string{"-out", output}, paths...), &report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "Проверено: 7 массивов байтов, 14 файлов.") {
		t.Fatalf("wrong summary: %s", report.String())
	}
	for _, mode := range []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"} {
		for i, want := range []string{"first", "second"} {
			name := []string{"restored-01-same.txt", "restored-02-same.txt"}[i]
			data, err := os.ReadFile(filepath.Join(output, mode, name))
			if err != nil || string(data) != want {
				t.Fatalf("%s/%s=%q,%v", mode, name, data, err)
			}
		}
	}
}

func TestHelpReportsOutputFailure(t *testing.T) {
	sentinel := errors.New("help output failed")
	if err := run([]string{"-h"}, failedReport{sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("help output error=%v", err)
	}
}
