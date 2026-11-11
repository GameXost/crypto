package symmetric

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"cryp/block"
)

func newECBDESContext(t *testing.T, padding Padding) *CipherContext {
	t.Helper()
	cipher, err := block.NewDES()
	if err != nil {
		t.Fatal(err)
	}
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	c, err := NewCipherContext(key, cipher, ECB, padding, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCipherContextECBDESKnownAnswer(t *testing.T) {
	c := newECBDESContext(t, Zeros)
	plain := bytes.Repeat([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}, 2)
	want := bytes.Repeat([]byte{0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05}, 2)
	encrypted, err := c.Encrypt(plain)
	if err != nil || !bytes.Equal(encrypted, want) {
		t.Fatalf("Encrypt() = %X, %v; want %X", encrypted, err, want)
	}
	decrypted, err := c.Decrypt(want)
	if err != nil || !bytes.Equal(decrypted, plain) {
		t.Fatalf("Decrypt() = %X, %v; want %X", decrypted, err, plain)
	}
}

func TestCipherContextECBRoundTrip(t *testing.T) {
	inputs := [][]byte{nil, {0x41}, {1, 2, 3, 4, 5, 6, 7, 8}, bytes.Repeat([]byte{0x41}, 49), {0x41, 0, 0}}
	for _, padding := range []Padding{Zeros, ANSIX923, PKCS7, ISO10126} {
		for i, data := range inputs {
			t.Run(fmt.Sprintf("padding_%d/input_%d", padding, i), func(t *testing.T) {
				c := newECBDESContext(t, padding)
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
					t.Fatalf("round trip = %X, want %X", got, want)
				}
				if len(got) > 0 {
					got[0] ^= 0xFF
				}
				if !bytes.Equal(data, original) || !bytes.Equal(encrypted, originalEncrypted) {
					t.Fatal("operation changed input or returned an alias")
				}
				if len(encrypted) > 0 {
					encrypted[0] ^= 0xFF
				}
				if !bytes.Equal(data, original) {
					t.Fatal("encrypted result shares input memory")
				}
			})
		}
	}
}

type ecbTestCipher struct {
	transform func([]byte) ([]byte, error)
}

func (*ecbTestCipher) SetKey([]byte) error { return nil }
func (*ecbTestCipher) BlockSize() int      { return 8 }
func (c *ecbTestCipher) EncryptBlock(data []byte) ([]byte, error) {
	return c.transform(data)
}
func (c *ecbTestCipher) DecryptBlock(data []byte) ([]byte, error) {
	return c.transform(data)
}

func TestCipherContextECBRejectsCipherFailures(t *testing.T) {
	sentinel := errors.New("cipher failed")
	for _, operation := range []struct {
		name string
		run  func(*CipherContext, []byte) ([]byte, error)
	}{
		{"encrypt", (*CipherContext).Encrypt},
		{"decrypt", (*CipherContext).Decrypt},
	} {
		for _, failure := range []struct {
			name   string
			result []byte
			err    error
		}{
			{"error", nil, sentinel},
			{"short_block", make([]byte, 7), nil},
			{"long_block", make([]byte, 9), nil},
		} {
			t.Run(operation.name+"/"+failure.name, func(t *testing.T) {
				calls := 0
				cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
					calls++
					if calls == 2 {
						return failure.result, failure.err
					}
					return data, nil
				}}
				c := &CipherContext{cipher: cipher, mode: ECB, padding: Zeros}
				data := bytes.Repeat([]byte{0x41}, 16)
				original := bytes.Clone(data)
				got, err := operation.run(c, data)
				if err == nil || got != nil {
					t.Fatalf("result = %X, %v; want nil, error", got, err)
				}
				if failure.err != nil && !errors.Is(err, sentinel) {
					t.Fatalf("error %v does not wrap cipher error", err)
				}
				if calls != 2 || !bytes.Equal(data, original) {
					t.Fatal("did not process both blocks or changed input")
				}
			})
		}
	}
}

func TestCipherContextECBOutputIndependent(t *testing.T) {
	c := &CipherContext{cipher: &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		return data, nil
	}}, mode: ECB, padding: Zeros}
	for _, run := range []func(*CipherContext, []byte) ([]byte, error){(*CipherContext).Encrypt, (*CipherContext).Decrypt} {
		data := bytes.Repeat([]byte{0x41}, 8)
		original := bytes.Clone(data)
		got, err := run(c, data)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("result = %X, %v; want %X", got, err, data)
		}
		got[0] ^= 0xFF
		if !bytes.Equal(data, original) {
			t.Fatal("result shares input memory")
		}
	}
}

func TestCipherContextRejectsUnknownModesAndMissingCipher(t *testing.T) {
	for _, mode := range []Mode{RandomDelta + 1, 255} {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				t.Fatal("unsupported mode invoked block cipher")
				return nil, nil
			}}
			if c, err := NewCipherContext(nil, cipher, mode, Zeros, nil); err == nil || c != nil {
				t.Fatalf("NewCipherContext() = %v, %v; want nil, error", c, err)
			}
			c := &CipherContext{cipher: cipher, mode: mode, padding: Zeros}
			if got, err := c.Encrypt([]byte{0x41}); err == nil || got != nil {
				t.Fatalf("Encrypt() = %X, %v; want nil, error", got, err)
			}
			if got, err := c.Decrypt(make([]byte, 8)); err == nil || got != nil {
				t.Fatalf("Decrypt() = %X, %v; want nil, error", got, err)
			}
		})
	}
	for _, c := range []*CipherContext{nil, {}} {
		if got, err := c.Encrypt([]byte{0x41}); err == nil || got != nil {
			t.Fatalf("Encrypt() = %X, %v; want nil, error", got, err)
		}
		if got, err := c.Decrypt(make([]byte, 8)); err == nil || got != nil {
			t.Fatalf("Decrypt() = %X, %v; want nil, error", got, err)
		}
	}
}

func TestCipherContextECBRejectsMalformedCiphertext(t *testing.T) {
	tests := []struct {
		name    string
		padding Padding
		data    []byte
	}{
		{"unaligned_zeros", Zeros, make([]byte, 7)},
		{"unaligned_pkcs", PKCS7, make([]byte, 9)},
		{"empty_ansi", ANSIX923, nil},
		{"empty_pkcs", PKCS7, nil},
		{"empty_iso", ISO10126, nil},
		{"ansi_zero_count", ANSIX923, make([]byte, 8)},
		{"pkcs_zero_count", PKCS7, make([]byte, 8)},
		{"iso_zero_count", ISO10126, make([]byte, 8)},
		{"ansi_bad_bytes", ANSIX923, []byte{1, 2, 3, 4, 5, 6, 1, 2}},
		{"pkcs_bad_bytes", PKCS7, []byte{1, 2, 3, 4, 5, 6, 0, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CipherContext{cipher: &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				return data, nil
			}}, mode: ECB, padding: tt.padding}
			original := bytes.Clone(tt.data)
			if got, err := c.Decrypt(tt.data); err == nil || got != nil {
				t.Fatalf("Decrypt() = %X, %v; want nil, error", got, err)
			}
			if !bytes.Equal(tt.data, original) {
				t.Fatal("failed decryption changed input")
			}
		})
	}
}

type constructorTestCipher struct {
	sizedModeCipher
	setKey func([]byte) error
}

func (c *constructorTestCipher) SetKey(key []byte) error { return c.setKey(key) }

func TestCipherContextConstructorValidation(t *testing.T) {
	validCipher := &sizedModeCipher{size: 8}
	for _, tt := range []struct {
		name    string
		cipher  block.BlockCipher
		padding Padding
		options []Option
	}{
		{"missing_cipher", nil, Zeros, nil},
		{"zero_block", &sizedModeCipher{size: 0}, Zeros, nil},
		{"oversized_block", &sizedModeCipher{size: 256}, Zeros, nil},
		{"unknown_padding", validCipher, Padding(255), nil},
		{"nil_option", validCipher, Zeros, []Option{nil}},
		{"zero_workers", validCipher, Zeros, []Option{WithWorkers(0)}},
		{"negative_workers", validCipher, Zeros, []Option{WithWorkers(-1)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if c, err := NewCipherContext(nil, tt.cipher, ECB, tt.padding, nil, tt.options...); err == nil || c != nil {
				t.Fatalf("NewCipherContext() = %v, %v; want nil, error", c, err)
			}
		})
	}
	key := []byte{1, 2, 3}
	setKeyErr := errors.New("bad key")
	cipher := &constructorTestCipher{sizedModeCipher: sizedModeCipher{size: 8}, setKey: func(received []byte) error {
		if !bytes.Equal(received, key) {
			t.Fatalf("SetKey received %x, want %x", received, key)
		}
		received[0] = 0xff
		return setKeyErr
	}}
	if c, err := NewCipherContext(key, cipher, ECB, Zeros, nil); c != nil || !errors.Is(err, setKeyErr) {
		t.Fatalf("constructor = %v, %v; want wrapped key error", c, err)
	}
	if !bytes.Equal(key, []byte{1, 2, 3}) {
		t.Fatal("SetKey modified caller key")
	}
	cipher.setKey = func([]byte) error { return nil }
	c, err := NewCipherContext(key, cipher, ECB, Zeros, nil, WithWorkers(3))
	if err != nil || c.workers != 3 {
		t.Fatalf("worker option not retained: %v, %v", c, err)
	}
	c.padding = Padding(255)
	if got, err := c.Encrypt([]byte{1}); err == nil || got != nil {
		t.Fatalf("invalid padding result = %x, %v; want nil, error", got, err)
	}
}

func TestCipherContextMaximumBlockSize(t *testing.T) {
	cipher := &sizedModeCipher{size: 255, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		return data, nil
	}}}
	c, err := NewCipherContext(nil, cipher, ECB, PKCS7, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x41}, 255)
	encoded, err := c.Encrypt(plain)
	if err != nil || len(encoded) != 510 || !bytes.Equal(encoded[255:], bytes.Repeat([]byte{255}, 255)) {
		t.Fatalf("maximum block padding: length %d, %v", len(encoded), err)
	}
	got, err := c.Decrypt(encoded)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %x, %v; want %x", got, err, plain)
	}
}
