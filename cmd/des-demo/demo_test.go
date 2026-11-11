package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"cryp/symmetric"
)

type demoTestCipher struct {
	encryptError error
	decryptError error
	changePlain  bool
}

func (*demoTestCipher) SetKey([]byte) error { return nil }
func (*demoTestCipher) BlockSize() int      { return 8 }
func (c *demoTestCipher) EncryptBlock(data []byte) ([]byte, error) {
	return bytes.Clone(data), c.encryptError
}
func (c *demoTestCipher) DecryptBlock(data []byte) ([]byte, error) {
	result := bytes.Clone(data)
	if c.changePlain {
		result[0] ^= 1
	}
	return result, c.decryptError
}

func TestDemoReportsCryptoFailureOrMismatch(t *testing.T) {
	for _, stage := range []string{"encrypt", "decrypt", "mismatch"} {
		t.Run(stage, func(t *testing.T) {
			sentinel := errors.New("demo cipher failed")
			cipher := &demoTestCipher{}
			switch stage {
			case "encrypt":
				cipher.encryptError = sentinel
			case "decrypt":
				cipher.decryptError = sentinel
			case "mismatch":
				cipher.changePlain = true
			}
			c, err := symmetric.NewCipherContext(nil, cipher, symmetric.ECB, symmetric.PKCS7, nil)
			if err != nil {
				t.Fatal(err)
			}
			plain := []byte("sample")
			if err := demoBytes(c, plain); err == nil || (stage != "mismatch" && !errors.Is(err, sentinel)) {
				t.Fatalf("byte failure=%v", err)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			if err := os.WriteFile(input, plain, 0600); err != nil {
				t.Fatal(err)
			}
			if err := demoFile(c, input, filepath.Join(dir, "encrypted"), filepath.Join(dir, "restored")); err == nil || (stage != "mismatch" && !errors.Is(err, sentinel)) {
				t.Fatalf("file failure=%v", err)
			}
			if got, err := os.ReadFile(input); err != nil || !bytes.Equal(got, plain) {
				t.Fatal("failed demo changed input")
			}
		})
	}
}

func TestDemoFileDoesNotReplaceOutputs(t *testing.T) {
	for _, existing := range []string{"encrypted", "restored"} {
		t.Run(existing, func(t *testing.T) {
			c, err := symmetric.NewCipherContext(nil, &demoTestCipher{}, symmetric.ECB, symmetric.PKCS7, nil)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input, encrypted, restored := filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "restored")
			if err := os.WriteFile(input, []byte("sample"), 0600); err != nil {
				t.Fatal(err)
			}
			keep := filepath.Join(dir, existing)
			if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := demoFile(c, input, encrypted, restored); !errors.Is(err, os.ErrExist) {
				t.Fatalf("overwrite error=%v", err)
			}
			if data, err := os.ReadFile(keep); err != nil || string(data) != "keep" {
				t.Fatal("demo overwrote an existing result")
			}
		})
	}
}
