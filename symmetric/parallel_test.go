package symmetric

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type parallelTestCipher struct {
	size      int
	transform func([]byte) ([]byte, error)
	decrypt   func([]byte) ([]byte, error)
}

func (*parallelTestCipher) SetKey([]byte) error                        { return nil }
func (c *parallelTestCipher) BlockSize() int                           { return c.size }
func (c *parallelTestCipher) EncryptBlock(data []byte) ([]byte, error) { return c.transform(data) }
func (c *parallelTestCipher) DecryptBlock(data []byte) ([]byte, error) {
	if c.decrypt != nil {
		return c.decrypt(data)
	}
	return c.transform(data)
}

func TestCipherContextWorkersActuallyOverlap(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	cipher := &parallelTestCipher{size: 8, transform: func(data []byte) ([]byte, error) {
		if calls.Add(1) <= 2 {
			entered <- struct{}{}
			<-release
		}
		return bytes.Clone(data), nil
	}}
	c, err := NewCipherContext(nil, cipher, ECB, Zeros, nil, WithWorkers(4))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Encrypt(bytes.Repeat([]byte{0x41}, 32)); done <- err }()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	arrivals := 0
wait:
	for arrivals < 2 {
		select {
		case <-entered:
			arrivals++
		case <-timer.C:
			break wait
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not finish after release")
	}
	if arrivals != 2 {
		t.Fatal("WithWorkers(4) did not run independent blocks concurrently")
	}
}

func parallelTestTransform(data []byte) ([]byte, error) {
	result := bytes.Clone(data)
	for i := range result {
		result[i] ^= byte(i + 1)
	}
	return result, nil
}

func newParallelTestContext(t *testing.T, mode Mode, workers int, cipher *parallelTestCipher) *CipherContext {
	t.Helper()
	if cipher == nil {
		cipher = &parallelTestCipher{size: 8, transform: parallelTestTransform}
	}
	iv := []byte{1, 2, 3, 4, 5, 6, 7, 9}
	if mode == ECB {
		iv = nil
	}
	c, err := NewCipherContext(nil, cipher, mode, Zeros, iv, WithWorkers(workers))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCipherContextParallelModeDirections(t *testing.T) {
	plain := []byte("first---second--third---fourth--!")
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		for _, decrypt := range []bool{false, true} {
			for _, workers := range []int{1, 4} {
				t.Run(fmt.Sprintf("mode_%d/decrypt_%v/workers_%d", mode, decrypt, workers), func(t *testing.T) {
					reference := newParallelTestContext(t, mode, 1, nil)
					encoded, err := reference.Encrypt(plain)
					if err != nil {
						t.Fatal(err)
					}
					input, want := plain, encoded
					if decrypt {
						input, want = encoded, plain
					}
					parallel := workers > 1 && (mode == ECB || mode == CTR || mode == RandomDelta || (decrypt && mode != OFB))
					var calls, active, peak atomic.Int32
					entered, release := make(chan struct{}, 4), make(chan struct{})
					skip := int32(0)
					if mode == RandomDelta {
						skip = 1
					}
					cipher := &parallelTestCipher{size: 8, transform: func(data []byte) ([]byte, error) {
						n := active.Add(1)
						defer active.Add(-1)
						for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
						}
						call := calls.Add(1)
						if parallel && call > skip && call <= skip+4 {
							entered <- struct{}{}
							<-release
						}
						return parallelTestTransform(data)
					}}
					c := newParallelTestContext(t, mode, workers, cipher)
					type result struct {
						data []byte
						err  error
					}
					done := make(chan result, 1)
					go func() {
						if decrypt {
							data, err := c.Decrypt(input)
							done <- result{data, err}
							return
						}
						data, err := c.Encrypt(input)
						done <- result{data, err}
					}()
					arrivals := 0
					if parallel {
						timer := time.NewTimer(2 * time.Second)
					wait:
						for arrivals < 4 {
							select {
							case <-entered:
								arrivals++
							case <-timer.C:
								break wait
							}
						}
						timer.Stop()
					}
					close(release)
					select {
					case got := <-done:
						if got.err != nil || !bytes.Equal(got.data, want) {
							t.Fatalf("result = %x, %v; want %x", got.data, got.err, want)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("operation did not finish")
					}
					if active.Load() != 0 || peak.Load() > int32(workers) {
						t.Fatalf("active=%d, peak=%d, workers=%d", active.Load(), peak.Load(), workers)
					}
					if parallel && arrivals != 4 {
						t.Fatalf("only %d workers entered concurrently", arrivals)
					}
					if !parallel && peak.Load() != 1 {
						t.Fatalf("dependent mode ran %d calls concurrently", peak.Load())
					}
				})
			}
		}
	}
}

func TestCipherContextParallelPreservesBlockOrder(t *testing.T) {
	firstEntered, secondFinished := make(chan struct{}), make(chan struct{})
	cipher := &parallelTestCipher{size: 8, transform: func(data []byte) ([]byte, error) {
		switch data[0] {
		case 1:
			close(firstEntered)
			select {
			case <-secondFinished:
			case <-time.After(2 * time.Second):
				return nil, errors.New("second block never finished")
			}
		case 2:
			select {
			case <-firstEntered:
			case <-time.After(2 * time.Second):
				return nil, errors.New("first block never entered")
			}
			close(secondFinished)
		}
		return bytes.Clone(data), nil
	}}
	c := newParallelTestContext(t, ECB, 4, cipher)
	plain := append(bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 8)...)
	got, err := c.Encrypt(plain)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("out of order completion = %x, %v; want %x", got, err, plain)
	}
}

func TestCipherContextParallelErrorWaitsForWorkers(t *testing.T) {
	sentinel := errors.New("parallel block failure")
	entered := make(chan byte, 2)
	release := make(chan struct{})
	otherStarted := make(chan struct{})
	var active atomic.Int32
	cipher := &parallelTestCipher{size: 8, transform: func(data []byte) ([]byte, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- data[0]
		if data[0] == 1 {
			select {
			case <-otherStarted:
			case <-time.After(2 * time.Second):
				return nil, errors.New("other worker never started")
			}
			return nil, sentinel
		}
		close(otherStarted)
		<-release
		return bytes.Clone(data), nil
	}}
	c := newParallelTestContext(t, ECB, 2, cipher)
	data := append(bytes.Repeat([]byte{2}, 8), bytes.Repeat([]byte{1}, 8)...)
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { data, err := c.Encrypt(data); done <- result{data, err} }()
	arrivals := 0
	timer := time.NewTimer(2 * time.Second)
wait:
	for arrivals < 2 {
		select {
		case <-entered:
			arrivals++
		case <-timer.C:
			break wait
		}
	}
	timer.Stop()
	if arrivals == 2 {
		select {
		case got := <-done:
			close(release)
			t.Fatalf("returned before active worker finished: %x, %v; active=%d", got.data, got.err, active.Load())
		case <-time.After(100 * time.Millisecond):
		}
	}
	close(release)
	select {
	case got := <-done:
		if got.data != nil || !errors.Is(got.err, sentinel) || active.Load() != 0 {
			t.Fatalf("result=%x, %v; active=%d", got.data, got.err, active.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not finish after error")
	}
	if arrivals != 2 {
		t.Fatal("error test did not start both workers")
	}
}

func TestCipherContextParallelFilesCarryStateAcrossChunks(t *testing.T) {
	plain := make([]byte, 2*65536+17)
	for i := range plain {
		plain[i] = byte(i%251 + 1)
	}
	for _, mode := range []Mode{ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			// Длинный цикл гаммы нужен, чтобы сброс состояния на границе чанка был заметен.
			cipher := &parallelTestCipher{size: 8, transform: func(data []byte) ([]byte, error) {
				result := make([]byte, 8)
				binary.BigEndian.PutUint64(result, bits.RotateLeft64(binary.BigEndian.Uint64(data), 17)+0x9e3779b97f4a7c15)
				return result, nil
			}, decrypt: func(data []byte) ([]byte, error) {
				result := make([]byte, 8)
				binary.BigEndian.PutUint64(result, bits.RotateLeft64(binary.BigEndian.Uint64(data)-0x9e3779b97f4a7c15, -17))
				return result, nil
			}}
			reference, parallel := newParallelTestContext(t, mode, 1, cipher), newParallelTestContext(t, mode, 4, cipher)
			want, err := reference.Encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input, encrypted, output := filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "output")
			writeTestFile(t, input, plain)
			if err := parallel.EncryptFile(input, encrypted, false); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readTestFile(t, encrypted), want) {
				t.Fatal("parallel file encryption lost chunk state")
			}
			if err := parallel.DecryptFile(encrypted, output, false); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readTestFile(t, output), plain) {
				t.Fatal("parallel file decryption lost chunk state")
			}
		})
	}
}

func TestCipherContextParallelRejectsCounterPeriodBeforeCalls(t *testing.T) {
	for _, tt := range []struct {
		mode         Mode
		size, length int
		iv           []byte
	}{{CTR, 1, 257, []byte{0xff}}, {RandomDelta, 2, 2 * 65537, []byte{1, 1}}} {
		t.Run(fmt.Sprint(tt.mode), func(t *testing.T) {
			var calls atomic.Int32
			cipher := &parallelTestCipher{size: tt.size, transform: func(data []byte) ([]byte, error) { calls.Add(1); return bytes.Clone(data), nil }}
			c, err := NewCipherContext(nil, cipher, tt.mode, Zeros, tt.iv, WithWorkers(4))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := c.Encrypt(make([]byte, tt.length)); err == nil || got != nil || calls.Load() != 0 {
				t.Fatalf("period error=%x, %v; calls=%d", got, err, calls.Load())
			}
			length := tt.length
			if tt.mode == RandomDelta {
				length += tt.size
			}
			if got, err := c.Decrypt(make([]byte, length)); err == nil || got != nil || calls.Load() != 0 {
				t.Fatalf("decrypt period error=%x, %v; calls=%d", got, err, calls.Load())
			}
		})
	}
}
