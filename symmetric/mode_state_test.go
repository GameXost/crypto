package symmetric

import (
	"bytes"
	"fmt"
	"testing"
)

func TestModeStateChunkedMatchesByteAPI(t *testing.T) {
	plain := []byte("Now is the time for all Now is the time for all ")
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			iv := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
			if mode == ECB {
				iv = nil
			}
			c := newModeDESContext(t, mode, Zeros, iv)
			want, err := c.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			if mode == RandomDelta {
				want = want[8:]
			}
			for _, decrypt := range []bool{false, true} {
				state := newModeState(c.cipher, mode, iv, decrypt)
				input, expected := plain, want
				if decrypt {
					input, expected = want, plain
				}
				original := bytes.Clone(input)
				var got []byte
				for _, span := range [][2]int{{0, 8}, {8, 8}, {8, 32}, {32, len(input)}} {
					part, err := state.transform(input[span[0]:span[1]])
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, part...)
				}
				if !bytes.Equal(got, expected) || !bytes.Equal(input, original) || !bytes.Equal(iv, c.iv) {
					t.Fatalf("mode %d decrypt %v chunked = %x, want %x; input/IV must remain unchanged", mode, decrypt, got, expected)
				}
			}
		})
	}
}

func TestModeStateCumulativeCounterPeriod(t *testing.T) {
	for _, tt := range []struct {
		mode Mode
		size int
		iv   []byte
	}{{CTR, 1, []byte{0xfe}}, {RandomDelta, 2, []byte{0xfe, 0xfd}}} {
		for _, decrypt := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode_%d/decrypt_%v", tt.mode, decrypt), func(t *testing.T) {
				calls := 0
				cipher := &sizedModeCipher{size: tt.size, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
					calls++
					return data, nil
				}}}
				state := newModeState(cipher, tt.mode, tt.iv, decrypt)
				period := 1 << (8 * tt.size)
				for part := 0; part < 2; part++ {
					got, err := state.transform(make([]byte, period/2*tt.size))
					if err != nil || len(got) != period/2*tt.size {
						t.Fatalf("half-period %d = %d bytes, %v", part, len(got), err)
					}
				}
				if calls != period {
					t.Fatalf("calls = %d, want %d", calls, period)
				}
				if got, err := state.transform(make([]byte, tt.size)); err == nil || got != nil || calls != period {
					t.Fatalf("repeated counter: %x, %v, calls %d", got, err, calls)
				}
			})
		}
	}
}

func TestModeStateRejectsCountOverflowAndUnknownMode(t *testing.T) {
	cipher := &ecbTestCipher{transform: func([]byte) ([]byte, error) {
		t.Fatal("invalid operation invoked cipher")
		return nil, nil
	}}
	for _, mode := range []Mode{CTR, RandomDelta} {
		state := newModeState(cipher, mode, []byte{1, 2, 3, 4, 5, 6, 7, 9}, false)
		state.processed = ^uint64(0)
		if got, err := state.transform(make([]byte, 8)); err == nil || got != nil {
			t.Fatalf("overflow = %x, %v", got, err)
		}
	}
	for _, decrypt := range []bool{false, true} {
		state := newModeState(cipher, Mode(255), nil, decrypt)
		if got, err := state.transform(make([]byte, 8)); err == nil || got != nil {
			t.Fatalf("unknown mode = %x, %v", got, err)
		}
	}
}

func TestModeStateAcceptsLastCountBeforeOverflow(t *testing.T) {
	for _, mode := range []Mode{CTR, RandomDelta} {
		calls := 0
		cipher := &ecbTestCipher{transform: func(p []byte) ([]byte, error) { calls++; return p, nil }}
		state := newModeState(cipher, mode, []byte{1, 2, 3, 4, 5, 6, 7, 9}, false)
		state.processed = ^uint64(0) - 1
		if _, err := state.transform(make([]byte, 8)); err != nil || calls != 1 {
			t.Fatalf("last representable block rejected: %v", err)
		}
		if _, err := state.transform(nil); err != nil || calls != 1 {
			t.Fatalf("empty final chunk rejected: %v", err)
		}
		if _, err := state.transform(make([]byte, 8)); err == nil || calls != 1 {
			t.Fatal("overflow did not stop cipher calls")
		}
	}
}
