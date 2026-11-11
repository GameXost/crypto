package symmetric

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAsyncBytesReturnBeforeCompletionAndOwnInput(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		t.Run(map[bool]string{false: "encrypt", true: "decrypt"}[decrypt], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) { close(entered); <-release; return bytes.Clone(data), nil }}
			c, err := NewCipherContext(nil, cipher, ECB, Zeros, nil)
			if err != nil {
				t.Fatal(err)
			}
			input := []byte("snapshot")
			original := bytes.Clone(input)
			run := c.EncryptAsync
			if decrypt {
				run = c.DecryptAsync
			}
			returned := make(chan (<-chan Result), 1)
			go func() { returned <- run(input) }()
			var result <-chan Result
			select {
			case result = <-returned:
			case <-time.After(2 * time.Second):
				t.Fatal("async call waited for cipher completion")
			}
			select {
			case <-entered:
			case got := <-result:
				t.Fatalf("finished before cipher: %v", got.Err)
			case <-time.After(2 * time.Second):
				t.Fatal("cipher was never entered")
			}
			input[0] ^= 0xff
			once.Do(func() { close(release) })
			select {
			case got := <-result:
				if got.Err != nil || !bytes.Equal(got.Data, original) {
					t.Fatalf("snapshot result = %x, %v", got.Data, got.Err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no async result")
			}
			if _, ok := <-result; ok {
				t.Fatal("channel contains more than one result")
			}
		})
	}
}

func TestAsyncBytesPropagateErrors(t *testing.T) {
	sentinel := errors.New("async cipher failed")
	c, err := NewCipherContext(nil, &ecbTestCipher{transform: func([]byte) ([]byte, error) { return nil, sentinel }}, ECB, Zeros, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func([]byte) <-chan Result{c.EncryptAsync, c.DecryptAsync} {
		got := <-run(make([]byte, 8))
		if got.Data != nil || !errors.Is(got.Err, sentinel) {
			t.Fatalf("result=%x,%v", got.Data, got.Err)
		}
	}
	var missing *CipherContext
	if got := <-missing.EncryptAsync(nil); got.Err == nil || got.Data != nil {
		t.Fatal("nil context error missing")
	}
}

func TestAsyncFilesReturnBeforeCompletion(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		t.Run(map[bool]string{false: "encrypt", true: "decrypt"}[decrypt], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			cipher := &ecbTestCipher{transform: func(data []byte) ([]byte, error) { close(entered); <-release; return bytes.Clone(data), nil }}
			c, err := NewCipherContext(nil, cipher, ECB, PKCS7, nil)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
			plain := []byte("hello")
			padded, err := PKCS7.Pad(plain, 8)
			if err != nil {
				t.Fatal(err)
			}
			data, want := plain, padded
			if decrypt {
				data, want = padded, plain
			}
			writeTestFile(t, input, data)
			run := c.EncryptFileAsync
			if decrypt {
				run = c.DecryptFileAsync
			}
			returned := make(chan (<-chan error), 1)
			go func() { returned <- run(input, output, false) }()
			var result <-chan error
			select {
			case result = <-returned:
			case <-time.After(2 * time.Second):
				t.Fatal("file async waited for completion")
			}
			select {
			case <-entered:
			case err := <-result:
				t.Fatalf("file operation stopped early: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("cipher never entered")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unfinished output published: %v", err)
			}
			once.Do(func() { close(release) })
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("file async did not finish")
			}
			if _, ok := <-result; ok {
				t.Fatal("file channel not closed after one result")
			}
			if !bytes.Equal(readTestFile(t, output), want) {
				t.Fatal("wrong async file output")
			}
			assertNoFileTemps(t, dir)
		})
	}
}

func TestAsyncFileErrors(t *testing.T) {
	c := newECBDESContext(t, PKCS7)
	dir := t.TempDir()
	for _, run := range []func(string, string, bool) <-chan error{c.EncryptFileAsync, c.DecryptFileAsync} {
		if err := <-run(filepath.Join(dir, "missing"), filepath.Join(dir, "output"), false); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing input error=%v", err)
		}
	}
	assertNoFileTemps(t, dir)
}

func TestAsyncResultCanWaitWithoutReader(t *testing.T) {
	c := newECBDESContext(t, PKCS7)
	result := c.EncryptAsync([]byte("unread result"))
	defer func() {
		for range result {
		}
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for len(result) == 0 {
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("completed operation cannot queue its result without a reader")
		}
	}
	got := <-result
	if got.Err != nil || len(got.Data) == 0 {
		t.Fatalf("queued result = %x, %v", got.Data, got.Err)
	}
	if _, open := <-result; open {
		t.Fatal("channel must close after one queued result")
	}
}
