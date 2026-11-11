package symmetric

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoFileTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".cryp-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, %v", matches, err)
	}
}

func newFileTestContext(t *testing.T, mode Mode, padding Padding, automatic bool) *CipherContext {
	t.Helper()
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 9}
	if automatic || mode == ECB {
		iv = nil
	}
	cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		result := bytes.Clone(data)
		for i := range result {
			result[i] ^= byte(i + 1)
		}
		return result, nil
	}}
	c, err := NewCipherContext(nil, cipher, mode, padding, iv)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCipherContextFilesMatchByteAPI(t *testing.T) {
	sizes := []int{0, 1, 8, 65535, 65536, 65537, 2*65536 + 19}
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		for _, padding := range []Padding{Zeros, ANSIX923, PKCS7, ISO10126} {
			for _, automatic := range []bool{false, true} {
				t.Run(fmt.Sprintf("mode_%d/padding_%d/auto_%v", mode, padding, automatic), func(t *testing.T) {
					c := newFileTestContext(t, mode, padding, automatic)
					plain := bytes.Repeat([]byte{0x41}, sizes[(int(mode)+int(padding))%len(sizes)])
					dir := t.TempDir()
					input, encrypted, output := filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "output")
					writeTestFile(t, input, plain)
					if err := c.EncryptFile(input, encrypted, false); err != nil {
						t.Fatal(err)
					}
					fileCiphertext := readTestFile(t, encrypted)
					fromFile, err := c.Decrypt(fileCiphertext)
					if err != nil || !bytes.Equal(fromFile, plain) {
						t.Fatalf("byte decode of file = %x, %v", fromFile, err)
					}
					byteCiphertext, err := c.Encrypt(plain)
					if err != nil {
						t.Fatal(err)
					}
					if !automatic && padding != ISO10126 && !bytes.Equal(fileCiphertext, byteCiphertext) {
						t.Fatal("file ciphertext differs from byte API")
					}
					if err := c.DecryptFile(encrypted, output, false); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(readTestFile(t, output), plain) {
						t.Fatal("file round trip differs")
					}
					writeTestFile(t, encrypted, byteCiphertext)
					if err := c.DecryptFile(encrypted, output, true); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(readTestFile(t, output), plain) || !bytes.Equal(readTestFile(t, input), plain) {
						t.Fatal("byte/file compatibility or input preservation failed")
					}
					assertNoFileTemps(t, dir)
				})
			}
		}
	}
}

func TestCipherContextFilesZeroTailAcrossChunks(t *testing.T) {
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := newFileTestContext(t, mode, Zeros, true)
			dir := t.TempDir()
			input, encoded, output := filepath.Join(dir, "input"), filepath.Join(dir, "encoded"), filepath.Join(dir, "output")
			plain := append([]byte{'A', 0, 'B'}, make([]byte, 3*65536+1)...)
			writeTestFile(t, input, plain)
			if err := c.EncryptFile(input, encoded, false); err != nil {
				t.Fatal(err)
			}
			if err := c.DecryptFile(encoded, output, false); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readTestFile(t, output), []byte{'A', 0, 'B'}) {
				t.Fatal("Zeros did not remove entire trailing run or removed internal zero")
			}
			assertNoFileTemps(t, dir)
		})
	}
}

func TestCipherContextFileDESKnownAnswer(t *testing.T) {
	c := newECBDESContext(t, Zeros)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	writeTestFile(t, input, []byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	if err := c.EncryptFile(input, output, false); err != nil {
		t.Fatal(err)
	}
	want := []byte{0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05}
	if !bytes.Equal(readTestFile(t, output), want) {
		t.Fatal("file DES known answer differs")
	}
}

func TestCipherContextFileOverwriteAndAliases(t *testing.T) {
	c := newFileTestContext(t, ECB, PKCS7, false)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	plain, old := []byte("source must survive"), []byte("previous output")
	writeTestFile(t, input, plain)
	writeTestFile(t, output, old)
	if err := c.EncryptFile(input, output, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite=false error = %v", err)
	}
	if !bytes.Equal(readTestFile(t, output), old) {
		t.Fatal("existing output changed after refusal")
	}
	if err := c.EncryptFile(input, output, true); err != nil {
		t.Fatal(err)
	}
	want, err := c.Encrypt(plain)
	if err != nil || !bytes.Equal(readTestFile(t, output), want) {
		t.Fatalf("overwrite result differs: %v", err)
	}
	aliases := []string{input, dir + string(os.PathSeparator) + "." + string(os.PathSeparator) + "input"}
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(input, hardlink); err == nil {
		aliases = append(aliases, hardlink)
	}
	for _, alias := range aliases {
		for _, overwrite := range []bool{false, true} {
			if err := c.EncryptFile(input, alias, overwrite); err == nil {
				t.Fatalf("same file accepted: %s", alias)
			}
			if err := c.DecryptFile(input, alias, overwrite); err == nil {
				t.Fatalf("same file accepted for decryption: %s", alias)
			}
			if !bytes.Equal(readTestFile(t, input), plain) {
				t.Fatal("input destroyed by alias")
			}
		}
	}
	assertNoFileTemps(t, dir)
}

func TestCipherContextFilePathErrors(t *testing.T) {
	c := newFileTestContext(t, ECB, PKCS7, false)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	writeTestFile(t, input, []byte("input"))
	for _, paths := range [][2]string{{filepath.Join(dir, "missing"), output}, {dir, output}, {input, dir}, {input, ""}, {input, filepath.Join(dir, "missing", "output")}} {
		if err := c.EncryptFile(paths[0], paths[1], true); err == nil {
			t.Fatalf("invalid paths accepted: %v", paths)
		}
	}
	for _, c := range []*CipherContext{nil, {}} {
		if err := c.EncryptFile(input, output, false); err == nil {
			t.Fatal("uninitialized file encrypt accepted")
		}
		if err := c.DecryptFile(input, output, false); err == nil {
			t.Fatal("uninitialized file decrypt accepted")
		}
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed operation created output: %v", err)
	}
	assertNoFileTemps(t, dir)
}

func TestCipherContextFileFailuresPreserveDestination(t *testing.T) {
	for _, kind := range []string{"bad_padding", "truncated", "cipher_error", "encrypt_cipher_error"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing_%v", kind, existing), func(t *testing.T) {
				dir := t.TempDir()
				input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
				c := newFileTestContext(t, ECB, PKCS7, false)
				data, err := c.Encrypt(bytes.Repeat([]byte{0x41}, 2*65536+17))
				if err != nil {
					t.Fatal(err)
				}
				sentinel := errors.New("cipher failed after first chunk")
				switch kind {
				case "bad_padding":
					data[len(data)-1] ^= 0xff
				case "truncated":
					data = data[:len(data)-1]
				case "cipher_error", "encrypt_cipher_error":
					calls := 0
					c.cipher = &ecbTestCipher{transform: func(p []byte) ([]byte, error) {
						calls++
						if calls > 8192 {
							return nil, sentinel
						}
						return p, nil
					}}
				}
				writeTestFile(t, input, data)
				old := []byte("preserve prior destination")
				if existing {
					writeTestFile(t, output, old)
				}
				if kind == "encrypt_cipher_error" {
					err = c.EncryptFile(input, output, existing)
				} else {
					err = c.DecryptFile(input, output, existing)
				}
				if err == nil || ((kind == "cipher_error" || kind == "encrypt_cipher_error") && !errors.Is(err, sentinel)) {
					t.Fatalf("failure = %v", err)
				}
				if existing {
					if !bytes.Equal(readTestFile(t, output), old) {
						t.Fatal("failure replaced prior destination")
					}
				} else if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failure exposed partial output: %v", err)
				}
				if !bytes.Equal(readTestFile(t, input), data) {
					t.Fatal("failure changed input")
				}
				assertNoFileTemps(t, dir)
			})
		}
	}
}

func TestCipherContextFileRechecksDestination(t *testing.T) {
	for _, hardlink := range []bool{false, true} {
		t.Run(fmt.Sprintf("hardlink_%v", hardlink), func(t *testing.T) {
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
			plain, rival := []byte("input stays safe"), []byte("created during processing")
			writeTestFile(t, input, plain)
			calls := 0
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				calls++
				if calls == 1 {
					if hardlink {
						if err := os.Link(input, output); err != nil {
							t.Skipf("hardlink unavailable: %v", err)
						}
					} else {
						writeTestFile(t, output, rival)
					}
				}
				return data, nil
			}}
			c, err := NewCipherContext(nil, cipher, ECB, Zeros, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = c.EncryptFile(input, output, hardlink)
			if err == nil || (!hardlink && !errors.Is(err, os.ErrExist)) {
				t.Fatalf("late destination error = %v", err)
			}
			want := rival
			if hardlink {
				want = plain
			}
			if !bytes.Equal(readTestFile(t, output), want) || !bytes.Equal(readTestFile(t, input), plain) {
				t.Fatal("late destination or input changed")
			}
			if calls == 0 {
				t.Fatal("test did not reach processing")
			}
			assertNoFileTemps(t, dir)
		})
	}
}

func TestCipherContextFileRejectsOutputSymlink(t *testing.T) {
	dir := t.TempDir()
	input, target, link := filepath.Join(dir, "input"), filepath.Join(dir, "target"), filepath.Join(dir, "link")
	writeTestFile(t, input, []byte("input"))
	writeTestFile(t, target, []byte("target"))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	c := newFileTestContext(t, ECB, PKCS7, false)
	if err := c.EncryptFile(input, link, true); err == nil {
		t.Fatal("output symlink accepted")
	}
	if !bytes.Equal(readTestFile(t, target), []byte("target")) {
		t.Fatal("symlink target changed")
	}
	assertNoFileTemps(t, dir)
}
