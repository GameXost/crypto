package symmetric

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cryp/block"
)

func newDEALContext(t *testing.T, keySize int, mode Mode, workers int, iv []byte) *CipherContext {
	t.Helper()
	cipher, err := block.NewDEAL()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := NewCipherContext(key, cipher, mode, PKCS7, iv, WithWorkers(workers))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDEALWorksWithAllModesAndWorkers(t *testing.T) {
	plain := make([]byte, 111)
	for i := range plain {
		plain[i] = byte(i*13 + 7)
	}
	plain[len(plain)-1] = 0
	for _, size := range []int{16, 24, 32} {
		for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
			t.Run(fmt.Sprintf("key_%d/mode_%d", size, mode), func(t *testing.T) {
				iv := bytes.Repeat([]byte{0xff}, 16)
				if mode == ECB {
					iv = nil
				}
				serial := newDEALContext(t, size, mode, 1, iv)
				parallel := newDEALContext(t, size, mode, 4, iv)
				want, err := serial.Encrypt(plain)
				if err != nil {
					t.Fatal(err)
				}
				encrypted := <-parallel.EncryptAsync(plain)
				if encrypted.Err != nil || !bytes.Equal(encrypted.Data, want) {
					t.Fatalf("parallel encryption differs: %v", encrypted.Err)
				}
				decoded := <-parallel.DecryptAsync(want)
				if decoded.Err != nil || !bytes.Equal(decoded.Data, plain) {
					t.Fatalf("DEAL mode roundtrip failed: %v", decoded.Err)
				}
			})
		}
	}
}

func TestDEALStreamingFileWithGeneratedIV(t *testing.T) {
	c := newDEALContext(t, 32, CTR, 4, nil)
	dir := t.TempDir()
	input, encrypted, restored := filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "restored")
	plain := make([]byte, 65536+37)
	for i := range plain {
		plain[i] = byte(i * 11)
	}
	if err := os.WriteFile(input, plain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-c.EncryptFileAsync(input, encrypted, false); err != nil {
		t.Fatal(err)
	}
	if err := <-c.DecryptFileAsync(encrypted, restored, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restored)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("streaming DEAL roundtrip differs: %v", err)
	}
	assertNoFileTemps(t, dir)
}
