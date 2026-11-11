package symmetric

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestCipherContextGeneratedIV(t *testing.T) {
	for _, mode := range []Mode{CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := newModeDESContext(t, mode, PKCS7, nil)
			plain := []byte("fresh IV for each message")
			first, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			second, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			if len(first) != 40 || bytes.Equal(first[:8], second[:8]) || c.iv != nil {
				t.Fatalf("invalid generated IV framing/state: %x, %x, %x", first, second, c.iv)
			}
			for _, encrypted := range [][]byte{first, second} {
				decoder := newModeDESContext(t, mode, PKCS7, nil)
				got, err := decoder.Decrypt(encrypted)
				if err != nil || !bytes.Equal(got, plain) {
					t.Fatalf("Decrypt() = %x, %v; want %x", got, err, plain)
				}
			}
			for _, malformed := range [][]byte{nil, make([]byte, 7), make([]byte, 9)} {
				if got, err := c.Decrypt(malformed); err == nil || got != nil {
					t.Fatalf("Decrypt(%x) = %x, %v; want nil, error", malformed, got, err)
				}
			}
		})
	}
}

func TestCipherContextGeneratedIVEmptyMessage(t *testing.T) {
	for _, mode := range []Mode{CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := newModeDESContext(t, mode, Zeros, nil)
			encoded, err := c.Encrypt(nil)
			if err != nil || len(encoded) != 8 {
				t.Fatalf("empty message frame = %x, %v; want IV only", encoded, err)
			}
			got, err := c.Decrypt(encoded)
			if err != nil || len(got) != 0 {
				t.Fatalf("empty message = %x, %v", got, err)
			}
			counted := newModeDESContext(t, mode, PKCS7, nil)
			if got, err := counted.Decrypt(encoded); err == nil || got != nil {
				t.Fatalf("missing PKCS7 block = %x, %v; want nil, error", got, err)
			}
		})
	}
}

type sizedModeCipher struct {
	ecbTestCipher
	size int
}

func (c *sizedModeCipher) BlockSize() int { return c.size }

func TestCipherContextCTRPeriod(t *testing.T) {
	calls := 0
	cipher := &sizedModeCipher{size: 1, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		calls++
		return data, nil
	}}}
	c, err := NewCipherContext(nil, cipher, CTR, Zeros, []byte{0xfe})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Encrypt(make([]byte, 256))
	if err != nil || len(got) != 256 || calls != 256 {
		t.Fatalf("full period = %x, %v; calls %d", got, err, calls)
	}
	for i, v := range got {
		if v != byte(0xfe+i) {
			t.Fatalf("counter %d = %x", i, v)
		}
	}
	calls = 0
	if got, err := c.Encrypt(make([]byte, 257)); err == nil || got != nil || calls != 0 {
		t.Fatalf("exceeded period = %x, %v; calls %d", got, err, calls)
	}
}

func TestCipherContextRandomDeltaPeriod(t *testing.T) {
	calls := 0
	cipher := &sizedModeCipher{size: 2, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
		calls++
		return data, nil
	}}}
	c, err := NewCipherContext(nil, cipher, RandomDelta, Zeros, []byte{0xff, 1})
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x41}, 2*65536)
	got, err := c.Encrypt(plain)
	if err != nil || len(got) != 2+2*65536 || calls != 65537 {
		t.Fatalf("full period: length %d, %v; calls %d", len(got), err, calls)
	}
	calls = 0
	decoded, err := c.Decrypt(got)
	if err != nil || !bytes.Equal(decoded, plain) || calls != 65537 {
		t.Fatalf("full period decrypt: length %d, %v; calls %d", len(decoded), err, calls)
	}
	calls = 0
	if got, err := c.Encrypt(make([]byte, 2*65537)); err == nil || got != nil || calls != 0 {
		t.Fatalf("exceeded period: length %d, %v; calls %d", len(got), err, calls)
	}
	if got, err := c.Decrypt(make([]byte, 2+2*65537)); err == nil || got != nil || calls != 0 {
		t.Fatalf("exceeded period decrypt: length %d, %v; calls %d", len(got), err, calls)
	}
}

type deltaTestCipher struct{}

func (*deltaTestCipher) SetKey([]byte) error { return nil }
func (*deltaTestCipher) BlockSize() int      { return 2 }
func (*deltaTestCipher) EncryptBlock(data []byte) ([]byte, error) {
	return []byte{data[0] + 1, data[1] + 1}, nil
}
func (*deltaTestCipher) DecryptBlock(data []byte) ([]byte, error) {
	return []byte{data[0] - 1, data[1] - 1}, nil
}

func TestCipherContextRandomDeltaKnownAnswerAndHeader(t *testing.T) {
	iv := []byte{0xff, 0xfd}
	c, err := NewCipherContext(nil, &deltaTestCipher{}, RandomDelta, Zeros, iv)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{1, 2, 3, 4, 5, 6}
	want := []byte{0, 0xfe, 0xff, 0, 4, 0xff, 5, 0xf2}
	got, err := c.Encrypt(plain)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Encrypt() = %x, %v; want %x", got, err, want)
	}
	decoder, err := NewCipherContext(nil, &deltaTestCipher{}, RandomDelta, Zeros, []byte{1, 3})
	if err != nil {
		t.Fatal(err)
	}
	got, err = decoder.Decrypt(want)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Decrypt() = %x, %v; want %x", got, err, plain)
	}
	if !bytes.Equal(iv, []byte{0xff, 0xfd}) || !bytes.Equal(decoder.iv, []byte{1, 3}) {
		t.Fatal("operation changed configured IV")
	}
	for _, malformed := range [][]byte{nil, {0}, {0, 0xfe, 1}, {0, 0xff, 1, 2}} {
		if got, err := decoder.Decrypt(malformed); err == nil || got != nil {
			t.Fatalf("Decrypt(%x) = %x, %v; want nil, error", malformed, got, err)
		}
	}
}

func TestCipherContextIVValidation(t *testing.T) {
	for _, tt := range []struct {
		mode Mode
		size int
		iv   []byte
	}{
		{ECB, 8, []byte{1}}, {CBC, 8, []byte{}}, {CBC, 8, make([]byte, 7)}, {CFB, 8, make([]byte, 9)},
		{RandomDelta, 1, []byte{1}}, {RandomDelta, 3, []byte{1, 2, 3}}, {RandomDelta, 2, []byte{1, 2}},
		{RandomDelta, 2, []byte{1, 0}}, {RandomDelta, 3, nil},
	} {
		t.Run(fmt.Sprintf("mode_%d/size_%d/iv_%x", tt.mode, tt.size, tt.iv), func(t *testing.T) {
			cipher := &sizedModeCipher{size: tt.size}
			if c, err := NewCipherContext(nil, cipher, tt.mode, Zeros, tt.iv); err == nil || c != nil {
				t.Fatalf("NewCipherContext() = %v, %v; want nil, error", c, err)
			}
		})
	}
}

func TestCipherContextModesAliasingCipher(t *testing.T) {
	for _, mode := range []Mode{CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) { return data, nil }}
			iv := []byte{1, 2, 3, 4, 5, 6, 7, 9}
			c, err := NewCipherContext(nil, cipher, mode, Zeros, iv)
			if err != nil {
				t.Fatal(err)
			}
			plain := []byte("Now is the time for all ")
			original := bytes.Clone(plain)
			encoded, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			originalEncoded := bytes.Clone(encoded)
			decoded, err := c.Decrypt(encoded)
			if err != nil || !bytes.Equal(decoded, original) {
				t.Fatalf("round trip = %x, %v; want %x", decoded, err, original)
			}
			decoded[0] ^= 0xff
			if !bytes.Equal(encoded, originalEncoded) || !bytes.Equal(plain, original) || !bytes.Equal(c.iv, iv) {
				t.Fatal("operation changed input/state or output aliases input")
			}
		})
	}
}

func TestCipherContextModesCipherReusesOutput(t *testing.T) {
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			buffer := make([]byte, 8)
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				for i := range buffer {
					buffer[i] = data[i] ^ byte(i+1)
				}
				return buffer, nil
			}}
			iv := []byte{1, 2, 3, 4, 5, 6, 7, 9}
			if mode == ECB {
				iv = nil
			}
			c, err := NewCipherContext(nil, cipher, mode, PKCS7, iv)
			if err != nil {
				t.Fatal(err)
			}
			plain := []byte("Now is the time for all ")
			encoded, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Decrypt(encoded)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("round trip = %x, %v; want %x", got, err, plain)
			}
		})
	}
}

func TestCipherContextModesConcurrentOperations(t *testing.T) {
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		for _, automatic := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode_%d/automatic_%v", mode, automatic), func(t *testing.T) {
				iv := []byte{1, 2, 3, 4, 5, 6, 7, 9}
				if automatic || mode == ECB {
					iv = nil
				}
				c := newModeDESContext(t, mode, PKCS7, iv)
				plain := []byte("separate state for concurrent messages")
				var wg sync.WaitGroup
				for worker := 0; worker < 4; worker++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for attempt := 0; attempt < 3; attempt++ {
							encoded, err := c.Encrypt(plain)
							if err != nil {
								t.Error(err)
								return
							}
							got, err := c.Decrypt(encoded)
							if err != nil || !bytes.Equal(got, plain) {
								t.Errorf("round trip = %x, %v; want %x", got, err, plain)
								return
							}
						}
					}()
				}
				wg.Wait()
				if !bytes.Equal(c.iv, iv) {
					t.Fatal("concurrent operation changed configured IV")
				}
			})
		}
	}
}
