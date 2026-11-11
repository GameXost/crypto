package symmetric

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
)

func TestParallelStateMatchesSequentialAcrossChunks(t *testing.T) {
	for _, size := range []int{1, 2, 8, 16, 254, 255} {
		for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
			if mode == RandomDelta && size%2 != 0 {
				continue
			}
			for _, decrypt := range []bool{false, true} {
				for _, workers := range []int{2, 4, 99} {
					t.Run(fmt.Sprintf("size_%d/mode_%d/decrypt_%v/workers_%d", size, mode, decrypt, workers), func(t *testing.T) {
						cipher := &sizedModeCipher{size: size, ecbTestCipher: ecbTestCipher{transform: func(data []byte) ([]byte, error) {
							result := bytes.Clone(data)
							for i := range result {
								result[i] ^= byte(0xa5 + i)
							}
							return result, nil
						}}}
						iv := bytes.Repeat([]byte{0xff}, size)
						iv[size-1] = 0xfd
						if mode == ECB {
							iv = nil
						}
						serial := newModeState(cipher, mode, iv, decrypt)
						parallel := newModeState(cipher, mode, iv, decrypt)
						parallel.workers = workers
						for _, blocks := range []int{0, 1, 3, 8, 19} {
							input := make([]byte, blocks*size)
							for i := range input {
								input[i] = byte(i%251 + 1)
							}
							original := bytes.Clone(input)
							want, err := serial.transform(input)
							if err != nil {
								t.Fatal(err)
							}
							got, err := parallel.transform(input)
							if err != nil || !bytes.Equal(got, want) || !bytes.Equal(input, original) {
								t.Fatalf("blocks %d parallel result differs from sequential or changed input: %v", blocks, err)
							}
							if len(got) != 0 {
								got[0] ^= 0xff
								if !bytes.Equal(input, original) {
									t.Fatal("parallel result aliases input")
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestAdvanceCounterMatchesModularArithmetic(t *testing.T) {
	for _, size := range []int{1, 2, 8, 16, 254, 255} {
		for _, step := range [][]byte{{1}, bytes.Repeat([]byte{0xfd}, max(1, size/2)), bytes.Repeat([]byte{0xff}, max(1, size/2))} {
			for _, count := range []uint64{0, 1, 2, 257, ^uint64(0)} {
				t.Run(fmt.Sprintf("size_%d/step_%x/count_%d", size, step, count), func(t *testing.T) {
					counter := bytes.Repeat([]byte{0xff}, size)
					counter[size-1] = 0xfe
					originalStep := bytes.Clone(step)
					want := new(big.Int).SetBytes(counter)
					term := new(big.Int).Mul(new(big.Int).SetBytes(step), new(big.Int).SetUint64(count))
					want.Add(want, term)
					want.Mod(want, new(big.Int).Lsh(big.NewInt(1), uint(8*size)))
					expected := want.FillBytes(make([]byte, size))
					advanceCounter(counter, step, count)
					if !bytes.Equal(counter, expected) || !bytes.Equal(step, originalStep) {
						t.Fatalf("counter = %x, want %x; step must remain unchanged", counter, expected)
					}
				})
			}
		}
	}
}

func TestParallelStateFailureDoesNotCommitState(t *testing.T) {
	sentinel := errors.New("parallel block failed")
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			var calls atomic.Int32
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) {
				if calls.Add(1) == 2 {
					return nil, sentinel
				}
				return bytes.Clone(data), nil
			}}
			iv := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd}
			if mode == ECB {
				iv = nil
			}
			state := newModeState(cipher, mode, iv, true)
			state.workers = 4
			got, err := state.transform(make([]byte, 64))
			if got != nil || !errors.Is(err, sentinel) {
				t.Fatalf("transform = %x, %v; want nil, wrapped error", got, err)
			}
			if !bytes.Equal(state.feedback, iv) || state.processed != 0 {
				t.Fatal("failed parallel operation committed state")
			}
		})
	}
}
