package symmetric

import (
	"bytes"
	"fmt"
	"io"
)

func (c *CipherContext) transformStream(input io.Reader, output io.Writer, decrypt bool) error {
	if c == nil || c.cipher == nil {
		return fmt.Errorf("cipher context is not initialized")
	}
	iv, err := c.streamIV(input, output, decrypt)
	if err != nil {
		return err
	}
	state := c.operationState(iv, decrypt)
	if decrypt {
		return c.decryptStream(input, output, state)
	}
	return c.encryptStream(input, output, state)
}

func (c *CipherContext) streamIV(input io.Reader, output io.Writer, decrypt bool) ([]byte, error) {
	if decrypt {
		return c.readStreamIV(input)
	}
	iv := c.encryptionIV()
	if c.prefixesIV() {
		if err := writeStream(output, iv); err != nil {
			return nil, err
		}
	}
	return iv, nil
}

func (c *CipherContext) readStreamIV(input io.Reader) ([]byte, error) {
	if !c.prefixesIV() {
		return c.iv, nil
	}
	iv := make([]byte, c.cipher.BlockSize())
	if _, err := io.ReadFull(input, iv); err != nil {
		return nil, fmt.Errorf("read IV: %w", err)
	}
	if err := validateIV(c.mode, iv, c.cipher.BlockSize()); err != nil {
		return nil, err
	}
	return iv, nil
}

func (c *CipherContext) encryptStream(input io.Reader, output io.Writer, state *modeState) error {
	blockSize := c.cipher.BlockSize()
	buffer := make([]byte, 65536/blockSize*blockSize)
	for {
		n, final, err := readStreamChunk(input, buffer)
		if err != nil {
			return fmt.Errorf("read plaintext: %w", err)
		}
		data := buffer[:n]
		if final {
			data, err = c.padding.Pad(data, blockSize)
			if err != nil {
				return err
			}
			return transformStreamChunk(state, output, data)
		}
		if err := transformStreamChunk(state, output, data); err != nil {
			return err
		}
	}
}

func (c *CipherContext) decryptStream(input io.Reader, output io.Writer, state *modeState) error {
	blockSize := c.cipher.BlockSize()
	buffer := make([]byte, 65536/blockSize*blockSize+blockSize)
	if c.padding == Zeros {
		output = &zeroTailWriter{output: output}
	}
	pending := 0
	for {
		n, final, err := readStreamChunk(input, buffer[pending:])
		n += pending
		if err != nil {
			return fmt.Errorf("read ciphertext: %w", err)
		}
		if n%blockSize != 0 {
			return fmt.Errorf("ciphertext length must be a multiple of block size")
		}
		if final {
			return c.finishDecryptStream(state, output, buffer[:n])
		}
		if err := transformStreamChunk(state, output, buffer[:n-blockSize]); err != nil {
			return err
		}
		copy(buffer, buffer[n-blockSize:n])
		pending = blockSize
	}
}

func readStreamChunk(input io.Reader, buffer []byte) (int, bool, error) {
	n, err := io.ReadFull(input, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, false, err
	}
	return n, err != nil, nil
}

func (c *CipherContext) finishDecryptStream(state *modeState, output io.Writer, data []byte) error {
	result, err := state.transform(data)
	if err != nil {
		return err
	}
	result, err = c.padding.UnPad(result, c.cipher.BlockSize())
	if err != nil {
		return err
	}
	return writeStream(output, result)
}

func transformStreamChunk(state *modeState, output io.Writer, data []byte) error {
	result, err := state.transform(data)
	if err != nil {
		return err
	}
	return writeStream(output, result)
}

func writeStream(output io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	n, err := output.Write(data)
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

type zeroTailWriter struct {
	output  io.Writer
	pending uint64
}

func (w *zeroTailWriter) Write(data []byte) (int, error) {
	trimmed := bytes.TrimRight(data, "\x00")
	if len(trimmed) != 0 {
		if err := w.flushZeros(); err != nil {
			return 0, err
		}
		if err := writeStream(w.output, trimmed); err != nil {
			return 0, err
		}
	}
	w.pending += uint64(len(data) - len(trimmed))
	return len(data), nil
}

func (w *zeroTailWriter) flushZeros() error {
	var zeros [4096]byte
	for w.pending > 0 {
		n := min(w.pending, uint64(len(zeros)))
		if err := writeStream(w.output, zeros[:n]); err != nil {
			return err
		}
		w.pending -= n
	}
	return nil
}
