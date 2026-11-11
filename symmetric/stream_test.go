package symmetric

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type checkedStreamReader struct {
	data    []byte
	written *bool
	t       *testing.T
}

func (r *checkedStreamReader) Read(p []byte) (int, error) {
	if len(p) > 65536+255 {
		r.t.Fatalf("read buffer grew to %d bytes", len(p))
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(r.data) < 65536 && !*r.written {
		r.t.Fatal("read entire input before producing output")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type checkedStreamWriter struct {
	bytes.Buffer
	written bool
}

func (w *checkedStreamWriter) Write(p []byte) (int, error) {
	w.written = true
	return w.Buffer.Write(p)
}

func TestStreamProcessesBeforeEOF(t *testing.T) {
	c, err := NewCipherContext(nil, &ecbTestCipher{transform: func(p []byte) ([]byte, error) { return p, nil }}, ECB, PKCS7, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x41}, 3*65536+17)
	w := &checkedStreamWriter{}
	r := &checkedStreamReader{data: plain, written: &w.written, t: t}
	if err := c.transformStream(r, w, false); err != nil {
		t.Fatal(err)
	}
	want, err := c.Encrypt(plain)
	if err != nil || !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("stream differs from bytes API: %v", err)
	}
}

type failingStreamReader struct{ err error }

func (r failingStreamReader) Read([]byte) (int, error) { return 0, r.err }

type failingStreamWriter struct {
	err   error
	short bool
}

func (w failingStreamWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, w.err
}

func TestStreamIOFailures(t *testing.T) {
	sentinel := errors.New("stream IO failed")
	for _, decrypt := range []bool{false, true} {
		c := newECBDESContext(t, PKCS7)
		if err := c.transformStream(failingStreamReader{sentinel}, io.Discard, decrypt); !errors.Is(err, sentinel) {
			t.Fatalf("read error = %v", err)
		}
		input, err := c.Encrypt([]byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		for _, writer := range []failingStreamWriter{{err: sentinel}, {short: true}} {
			want := sentinel
			if writer.short {
				want = io.ErrShortWrite
			}
			if err := c.transformStream(bytes.NewReader(input), writer, decrypt); !errors.Is(err, want) {
				t.Fatalf("write error = %v; want %v", err, want)
			}
		}
	}
}

func TestStreamZerosAcrossChunks(t *testing.T) {
	c, err := NewCipherContext(nil, &ecbTestCipher{transform: func(p []byte) ([]byte, error) { return p, nil }}, ECB, Zeros, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{0x41}, make([]byte, 3*65536)...)
	plain = append(plain, 0x42)
	want := bytes.Clone(plain)
	plain = append(plain, make([]byte, 4*65536)...)
	encoded, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	if err := c.transformStream(bytes.NewReader(encoded), &result, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Bytes(), want) {
		t.Fatalf("zero runs changed: got %d bytes, want %d", result.Len(), len(want))
	}
	var zeroResult bytes.Buffer
	if err := c.transformStream(bytes.NewReader(make([]byte, 3*65536)), &zeroResult, true); err != nil || zeroResult.Len() != 0 {
		t.Fatalf("all-zero message = %d bytes, %v", zeroResult.Len(), err)
	}
}

func TestStreamHeaderFailures(t *testing.T) {
	sentinel := errors.New("header failed")
	for _, mode := range []Mode{CBC, RandomDelta} {
		c := newModeDESContext(t, mode, PKCS7, nil)
		if err := c.transformStream(bytes.NewReader(nil), failingStreamWriter{err: sentinel}, false); !errors.Is(err, sentinel) {
			t.Fatalf("header write = %v", err)
		}
		if err := c.transformStream(failingStreamReader{sentinel}, io.Discard, true); !errors.Is(err, sentinel) {
			t.Fatalf("header read = %v", err)
		}
	}
	for _, decrypt := range []bool{false, true} {
		cipher := &ecbTestCipher{transform: func([]byte) ([]byte, error) { return nil, sentinel }}
		c, err := NewCipherContext(nil, cipher, RandomDelta, PKCS7, []byte{1, 2, 3, 4, 5, 6, 7, 9})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.transformStream(bytes.NewReader(make([]byte, 8)), io.Discard, decrypt); !errors.Is(err, sentinel) {
			t.Fatalf("RD header transform = %v", err)
		}
	}
}

func TestZeroTailWriterFailures(t *testing.T) {
	sentinel := errors.New("zero run write failed")
	writer := &zeroTailWriter{output: failingStreamWriter{err: sentinel}}
	if _, err := writer.Write(make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte{1}); n != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("flush zero run = %d, %v; no input consumed", n, err)
	}
	writer = &zeroTailWriter{output: failingStreamWriter{err: sentinel}}
	if n, err := writer.Write([]byte{1}); n != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("write nonzero = %d, %v; no input consumed", n, err)
	}
}

func TestStreamRejectsInvalidDataAndCipherFailures(t *testing.T) {
	for _, decrypt := range []bool{false, true} {
		for _, size := range []int{8, 2 * 65536} {
			sentinel := errors.New("block failed during stream")
			cipher := &ecbTestCipher{transform: func([]byte) ([]byte, error) { return nil, sentinel }}
			c, err := NewCipherContext(nil, cipher, ECB, PKCS7, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.transformStream(bytes.NewReader(make([]byte, size)), io.Discard, decrypt); !errors.Is(err, sentinel) {
				t.Fatalf("cipher error decrypt=%v size=%d: %v", decrypt, size, err)
			}
		}
	}
	for _, c := range []*CipherContext{nil, {}} {
		if err := c.transformStream(bytes.NewReader(nil), io.Discard, false); err == nil {
			t.Fatal("uninitialized stream accepted")
		}
	}
	c := newECBDESContext(t, PKCS7)
	for _, data := range [][]byte{nil, make([]byte, 7), make([]byte, 8)} {
		if err := c.transformStream(bytes.NewReader(data), io.Discard, true); err == nil {
			t.Fatal("bad ciphertext accepted")
		}
	}
	c.padding = Padding(255)
	if err := c.transformStream(bytes.NewReader(nil), io.Discard, false); err == nil {
		t.Fatal("unknown padding accepted")
	}
	c, err := NewCipherContext(nil, &ecbTestCipher{transform: func(p []byte) ([]byte, error) { return p, nil }}, RandomDelta, PKCS7, []byte{1, 2, 3, 4, 5, 6, 7, 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.transformStream(bytes.NewReader(make([]byte, 16)), io.Discard, true); err == nil {
		t.Fatal("even decoded RD delta accepted")
	}
}

func TestStreamSupportsNonPowerOfTwoBlocks(t *testing.T) {
	for _, tt := range []struct {
		mode Mode
		size int
	}{{ECB, 1}, {CBC, 3}, {PCBC, 255}, {CFB, 255}, {OFB, 255}, {CTR, 255}, {RandomDelta, 254}} {
		cipher := &sizedModeCipher{size: tt.size, ecbTestCipher: ecbTestCipher{transform: func(p []byte) ([]byte, error) { return bytes.Clone(p), nil }}}
		iv := bytes.Repeat([]byte{1}, tt.size)
		if tt.mode == ECB {
			iv = nil
		}
		c, err := NewCipherContext(nil, cipher, tt.mode, PKCS7, iv)
		if err != nil {
			t.Fatal(err)
		}
		plain := bytes.Repeat([]byte{0x41}, 2*65536+17)
		var encrypted bytes.Buffer
		if err := c.transformStream(bytes.NewReader(plain), &encrypted, false); err != nil {
			t.Fatalf("mode=%d B=%d encrypt: %v", tt.mode, tt.size, err)
		}
		want, err := c.Encrypt(plain)
		if err != nil || !bytes.Equal(encrypted.Bytes(), want) {
			t.Fatalf("mode=%d B=%d byte/stream differ: %v", tt.mode, tt.size, err)
		}
		var result bytes.Buffer
		if err := c.transformStream(bytes.NewReader(want), &result, true); err != nil || !bytes.Equal(result.Bytes(), plain) {
			t.Fatalf("mode=%d B=%d decrypt: %v", tt.mode, tt.size, err)
		}
	}
}

func TestStreamPreservesOneZeroAtChunkBoundary(t *testing.T) {
	c, err := NewCipherContext(nil, &ecbTestCipher{transform: func(p []byte) ([]byte, error) { return p, nil }}, ECB, Zeros, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := append(bytes.Repeat([]byte{0x41}, 65535), 0, 0x42)
	encoded, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	if err := c.transformStream(bytes.NewReader(encoded), &result, true); err != nil || !bytes.Equal(result.Bytes(), plain) {
		t.Fatalf("single internal zero at chunk boundary changed: %v", err)
	}
}
