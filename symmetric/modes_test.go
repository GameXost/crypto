package symmetric

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"cryp/block"
)

var testModes = []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta}
var testPaddings = []Padding{Zeros, ANSIX923, PKCS7, ISO10126}

func decodeTestHex(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestContext(t *testing.T, algorithm string, mode Mode, padding Padding, iv []byte, workers int) *CipherContext {
	t.Helper()
	var cipher block.BlockCipher
	var key []byte
	var err error
	if algorithm == "DES" {
		cipher, err = block.NewDES()
		key = decodeTestHex(t, "0123456789abcdef")
	} else {
		cipher, err = block.NewDEAL()
		key = []byte("0123456789abcdef")
	}
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCipherContext(key, cipher, mode, padding, iv, WithWorkers(workers))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func checkRoundTrip(t *testing.T, c *CipherContext, plain []byte) []byte {
	t.Helper()
	encoded, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Decrypt(encoded)
	want := plain
	if c.padding == Zeros {
		want = bytes.TrimRight(want, "\x00")
	}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("round trip = %x, %v; want %x", got, err, want)
	}
	return encoded
}

func TestModesDESKnownAnswers(t *testing.T) {
	for _, tt := range []struct {
		mode Mode
		want string
	}{
		{ECB, "85e813540f0ab40585e813540f0ab405"},

		{CBC, "e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6"},
		{PCBC, "e5c7cdde872bf27ccb70b78c59494228265f223fc0c655a5"},
		{CFB, "f3096249c7f46e51a69e839b1a92f78403467133898ea622"},
		{OFB, "f3096249c7f46e5135f24a242eeb3d3f3d6d5be3255af8c3"},
		{CTR, "f3096249c7f46e51163a8ca0ffc94c27fa2f80f480b86f75"},
		{RandomDelta, "f3096249c7f46e5120ada677eae9a705f3b370a6b1e067df"},
	} {
		t.Run(fmt.Sprint(tt.mode), func(t *testing.T) {
			plain := []byte("Now is the time for all ")
			key := decodeTestHex(t, "0123456789abcdef")
			iv := decodeTestHex(t, "1234567890abcdef")
			if tt.mode == ECB {
				plain = decodeTestHex(t, "0123456789abcdef0123456789abcdef")
				key = decodeTestHex(t, "133457799bbcdff1")
				iv = nil
			}
			cipher, err := block.NewDES()
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCipherContext(key, cipher, tt.mode, Zeros, iv)
			if err != nil {
				t.Fatal(err)
			}
			want := decodeTestHex(t, tt.want)
			got, err := c.Encrypt(plain)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("Encrypt = %x, %v; want %x", got, err, want)
			}
			got, err = c.Decrypt(want)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("Decrypt = %x, %v; want %x", got, err, plain)
			}
		})
	}
}

func TestModesDEALKnownAnswers(t *testing.T) {

	for _, tt := range []struct{ key, want string }{
		{"80000000000000000000000000000000", "eec0df4759817d07b747d5ae8e2e99d8"},
		{"800000000000000000000000000000000000000000000000", "35359bc13966119241aa81f2637996fd"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "fb9fe58485db9ae8b50a426112daaaef"},
	} {
		t.Run(fmt.Sprint(len(tt.key)/2), func(t *testing.T) {
			cipher, err := block.NewDEAL()
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCipherContext(decodeTestHex(t, tt.key), cipher, ECB, PKCS7, nil)
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, 16)
			encoded := checkRoundTrip(t, c, plain)

			if len(encoded) != 32 || !bytes.Equal(encoded[:16], decodeTestHex(t, tt.want)) {
				t.Fatalf("ECB ciphertext = %x; want first block %s", encoded, tt.want)
			}
		})
	}
}

func TestModesAndPaddings(t *testing.T) {

	plain := make([]byte, 31)
	for i := range plain {
		plain[i] = byte(i * 17)
	}
	plain[len(plain)-1] = 0
	for _, algorithm := range []string{"DES", "DEAL"} {
		for _, mode := range testModes {
			for _, padding := range testPaddings {
				t.Run(fmt.Sprintf("%s/mode_%d/padding_%d", algorithm, mode, padding), func(t *testing.T) {
					size := 8
					if algorithm == "DEAL" {
						size = 16
					}
					iv := bytes.Repeat([]byte{9}, size)
					if mode == ECB {
						iv = nil
					}
					serial := newTestContext(t, algorithm, mode, padding, iv, 1)
					parallel := newTestContext(t, algorithm, mode, padding, iv, 4)
					want := checkRoundTrip(t, serial, plain)
					got := checkRoundTrip(t, parallel, plain)
					if !bytes.Equal(got, want) {
						t.Fatal("ciphertext differs for workers=1 and workers=4")
					}
				})
			}
		}
	}
}

func TestModesPayloadEdges(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	for _, algorithm := range []string{"DES", "DEAL"} {
		size := 8
		if algorithm == "DEAL" {
			size = 16
		}
		inputs := []struct {
			name string
			data []byte
		}{
			{"nil", nil}, {"empty", []byte{}}, {"one_zero", []byte{0}},
			{"all_zeros", make([]byte, 2*size)}, {"all_byte_values", allBytes},
			{"before_block", bytes.Repeat([]byte{0xff}, size-1)},
			{"full_block", bytes.Repeat([]byte{0x80}, size)},
			{"after_block", bytes.Repeat([]byte{1}, size+1)},
			{"two_blocks", bytes.Repeat([]byte{2}, 2*size)},
			{"zero_tail", []byte{1, 0, 2, 0, 0}},
		}

		for _, padding := range testPaddings {
			for _, input := range inputs {
				t.Run(fmt.Sprintf("%s/padding_%d/%s", algorithm, padding, input.name), func(t *testing.T) {
					checkRoundTrip(t, newTestContext(t, algorithm, ECB, padding, nil, 1), input.data)
				})
			}
		}
	}
}

func TestModesGeneratedIV(t *testing.T) {
	plain := []byte("fresh IV for each message")
	for _, mode := range testModes[1:] {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			c := newTestContext(t, "DES", mode, PKCS7, nil, 4)
			first := checkRoundTrip(t, c, plain)
			second := checkRoundTrip(t, c, plain)
			if bytes.Equal(first[:8], second[:8]) {
				t.Fatal("messages reused the same IV")
			}
			withIV := newTestContext(t, "DES", mode, PKCS7, first[:8], 1)
			if got := checkRoundTrip(t, withIV, plain); !bytes.Equal(got, first[8:]) {
				t.Fatal("open IV prefix does not reproduce the ciphertext")
			}
			for _, malformed := range [][]byte{nil, first[:7], first[:len(first)-1]} {
				if _, err := c.Decrypt(malformed); err == nil {
					t.Fatal("truncated ciphertext accepted")
				}
			}
			if mode == RandomDelta {
				malformed := bytes.Clone(first)
				malformed[7] &^= 1
				if _, err := c.Decrypt(malformed); err == nil {
					t.Fatal("even delta in IV accepted")
				}
			}
		})
	}
}

type counterTestCipher struct{}

func (*counterTestCipher) SetKey([]byte) error { return nil }
func (*counterTestCipher) BlockSize() int      { return 2 }
func (*counterTestCipher) EncryptBlock(data []byte) ([]byte, error) {
	return []byte{data[0] + 1, data[1] + 1}, nil
}
func (*counterTestCipher) DecryptBlock([]byte) ([]byte, error) {
	return nil, fmt.Errorf("counter mode must use EncryptBlock in both directions")
}

func TestModesRandomDeltaCounter(t *testing.T) {
	iv := []byte{0xff, 0xfd}
	plain := []byte{1, 2, 3, 4, 5, 6}

	want := []byte{1, 0xfc, 2, 0xff, 7, 0xfe}
	c, err := NewCipherContext(nil, &counterTestCipher{}, RandomDelta, Zeros, iv, WithWorkers(4))
	if err != nil {
		t.Fatal(err)
	}
	if got := checkRoundTrip(t, c, plain); !bytes.Equal(got, want) {
		t.Fatalf("RandomDelta ciphertext = %x, want %x", got, want)
	}
	decoder, err := NewCipherContext(nil, &counterTestCipher{}, RandomDelta, Zeros, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decoder.Decrypt(append(bytes.Clone(iv), want...))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open IV frame = %x, %v; want %x", got, err, plain)
	}
}
