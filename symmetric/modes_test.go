package symmetric

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"cryp/block"
)

func newModeDESContext(t *testing.T, mode Mode, padding Padding, iv []byte) *CipherContext {
	t.Helper()
	cipher, err := block.NewDES()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCipherContext([]byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, cipher, mode, padding, iv)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCipherContextModesDESKnownAnswers(t *testing.T) {
	// Векторы рассчитаны независимо; один round trip не выявляет взаимно обратные ошибки.
	for _, tt := range []struct {
		mode Mode
		want string
	}{
		{CBC, "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"},
		{PCBC, "e5c7cdde872bf27ccb70b78c59494228265f223fc0c655a5"},
		{CFB, "f3096249c7f46e51a69e839b1a92f78403467133898ea622"},
		{OFB, "f3096249c7f46e5135f24a242eeb3d3f3d6d5be3255af8c3"},
		{CTR, "f3096249c7f46e51163a8ca0ffc94c27fa2f80f480b86f75"},
		{RandomDelta, "bd661569ae874e25e5c7cdde872bf27c02a142cb08bb4ae6ae38d488b6d07413"},
	} {
		t.Run(fmt.Sprint(tt.mode), func(t *testing.T) {
			iv := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
			c := newModeDESContext(t, tt.mode, Zeros, iv)
			iv[0] ^= 0xff
			plain := []byte("Now is the time for all ")
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				encrypted, err := c.Encrypt(plain)
				if err != nil || !bytes.Equal(encrypted, want) {
					t.Fatalf("Encrypt() = %x, %v; want %x", encrypted, err, want)
				}
				decrypted, err := c.Decrypt(want)
				if err != nil || !bytes.Equal(decrypted, plain) {
					t.Fatalf("Decrypt() = %x, %v; want %x", decrypted, err, plain)
				}
			}
		})
	}
}

func TestCipherContextModesRoundTrip(t *testing.T) {
	for _, mode := range []Mode{CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		for _, padding := range []Padding{Zeros, ANSIX923, PKCS7, ISO10126} {
			for n, data := range [][]byte{nil, {0x41}, {1, 2, 3, 4, 5, 6, 7, 8}, bytes.Repeat([]byte{0x41}, 49), {0x41, 0, 0}} {
				t.Run(fmt.Sprintf("mode_%d/padding_%d/input_%d", mode, padding, n), func(t *testing.T) {
					iv := []byte{8, 7, 6, 5, 4, 3, 2, 1}
					originalIV := bytes.Clone(iv)
					c := newModeDESContext(t, mode, padding, iv)
					original := bytes.Clone(data)
					encrypted, err := c.Encrypt(data)
					if err != nil {
						t.Fatal(err)
					}
					originalEncrypted := bytes.Clone(encrypted)
					got, err := c.Decrypt(encrypted)
					if err != nil {
						t.Fatal(err)
					}
					want := original
					if padding == Zeros {
						want = bytes.TrimRight(want, "\x00")
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("round trip = %x, want %x", got, want)
					}
					if len(got) > 0 {
						got[0] ^= 0xff
					}
					if !bytes.Equal(data, original) || !bytes.Equal(encrypted, originalEncrypted) || !bytes.Equal(iv, originalIV) || !bytes.Equal(c.iv, originalIV) {
						t.Fatal("operation changed input, IV, or returned an alias")
					}
					if len(encrypted) > 0 {
						encrypted[0] ^= 0xff
					}
					if !bytes.Equal(data, original) {
						t.Fatal("encrypted result shares input memory")
					}
				})
			}
		}
	}
}

func TestCipherContextModesRejectCipherFailures(t *testing.T) {
	sentinel := errors.New("cipher failed")
	for _, mode := range []Mode{CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		for _, operation := range []struct {
			name string
			run  func(*CipherContext, []byte) ([]byte, error)
		}{{"encrypt", (*CipherContext).Encrypt}, {"decrypt", (*CipherContext).Decrypt}} {
			for _, failure := range []struct {
				name   string
				result []byte
				err    error
				at     int
			}{
				{"first_error", nil, sentinel, 1}, {"first_short_block", make([]byte, 7), nil, 1}, {"first_long_block", make([]byte, 9), nil, 1},
				{"error", nil, sentinel, 2}, {"short_block", make([]byte, 7), nil, 2}, {"long_block", make([]byte, 9), nil, 2},
			} {
				t.Run(fmt.Sprintf("mode_%d/%s/%s", mode, operation.name, failure.name), func(t *testing.T) {
					calls := 0
					cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
						calls++
						if calls == failure.at {
							return failure.result, failure.err
						}
						return data, nil
					}}
					c, err := NewCipherContext(nil, cipher, mode, Zeros, []byte{8, 7, 6, 5, 4, 3, 2, 1})
					if err != nil {
						t.Fatal(err)
					}
					data := bytes.Repeat([]byte{0x41}, 16)
					original := bytes.Clone(data)
					got, err := operation.run(c, data)
					if err == nil || got != nil || (failure.err != nil && !errors.Is(err, sentinel)) {
						t.Fatalf("result = %x, %v; want nil and wrapped error", got, err)
					}
					if calls != failure.at || !bytes.Equal(data, original) {
						t.Fatal("did not stop at failing block or changed input")
					}
				})
			}
		}
	}
}

type encryptOnlyCipher struct {
	ecbTestCipher
	t *testing.T
}

func (c *encryptOnlyCipher) DecryptBlock([]byte) ([]byte, error) {
	c.t.Fatal("stream mode invoked DecryptBlock")
	return nil, nil
}

func TestCipherContextStreamModesUseEncryptionInBothDirections(t *testing.T) {
	for _, mode := range []Mode{CFB, OFB, CTR} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			cipher := &encryptOnlyCipher{t: t, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				result := bytes.Clone(data)
				for i := range result {
					result[i]++
				}
				return result, nil
			}}}
			c, err := NewCipherContext(nil, cipher, mode, PKCS7, []byte{8, 7, 6, 5, 4, 3, 2, 1})
			if err != nil {
				t.Fatal(err)
			}
			plain := []byte("three full blocks of input")
			encoded, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := c.Decrypt(encoded)
			if err != nil || !bytes.Equal(decoded, plain) {
				t.Fatalf("round trip = %x, %v", decoded, err)
			}
		})
	}
}

func TestCipherContextCTRCounterCarry(t *testing.T) {
	var counters [][]byte
	cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		counters = append(counters, bytes.Clone(data))
		return data, nil
	}}
	c, err := NewCipherContext(nil, cipher, CTR, Zeros, []byte{0, 0, 0, 0, 0, 0xff, 0xff, 0xfe})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Encrypt(make([]byte, 24)); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{{0, 0, 0, 0, 0, 0xff, 0xff, 0xfe}, {0, 0, 0, 0, 0, 0xff, 0xff, 0xff}, {0, 0, 0, 0, 1, 0, 0, 0}}
	if len(counters) != len(want) {
		t.Fatalf("counter count = %d", len(counters))
	}
	for i := range want {
		if !bytes.Equal(counters[i], want[i]) {
			t.Fatalf("counter %d = %x, want %x", i, counters[i], want[i])
		}
	}
}
