package symmetric

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"cryp/block"
)

type CipherContext struct {
	cipher  block.BlockCipher
	mode    Mode
	padding Padding
	iv      []byte
	workers int
}

type Option func(*CipherContext)

func WithWorkers(n int) Option {
	return func(c *CipherContext) { c.workers = n }
}

func NewCipherContext(key []byte, cipher block.BlockCipher, mode Mode, padding Padding, iv []byte, options ...Option) (*CipherContext, error) {
	if cipher == nil {
		return nil, fmt.Errorf("cipher is required")
	}
	if mode > RandomDelta || padding > ISO10126 {
		return nil, fmt.Errorf("unknown mode or padding")
	}
	blockSize := cipher.BlockSize()
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("block size must be in 1..255 bytes")
	}
	if err := validateIV(mode, iv, blockSize); err != nil {
		return nil, err
	}

	c := &CipherContext{
		cipher:  cipher,
		mode:    mode,
		padding: padding,
		iv:      bytes.Clone(iv),
		workers: 1,
	}
	if err := c.applyOptions(options); err != nil {
		return nil, err
	}
	if err := cipher.SetKey(bytes.Clone(key)); err != nil {
		return nil, fmt.Errorf("set cipher key: %w", err)
	}
	return c, nil
}

func (c *CipherContext) applyOptions(options []Option) error {
	for _, option := range options {
		if option == nil {
			return fmt.Errorf("nil option")
		}
		option(c)
	}
	if c.workers < 1 {
		return fmt.Errorf("workers must be positive")
	}
	return nil
}

func (c *CipherContext) prefixesIV() bool {
	return c.mode != ECB && c.mode != RandomDelta && c.iv == nil
}

func (c *CipherContext) Encrypt(data []byte) ([]byte, error) {
	if c == nil || c.cipher == nil {
		return nil, fmt.Errorf("cipher context is not initialized")
	}
	blockSize := c.cipher.BlockSize()
	padded, err := c.padding.Pad(data, blockSize)
	if err != nil {
		return nil, fmt.Errorf("pad data: %w", err)
	}
	iv := c.encryptionIV()
	result, err := c.transformMode(padded, iv, false)
	if err != nil {
		return nil, err
	}
	if c.prefixesIV() {
		result = append(iv, result...)
	}
	return result, nil
}

func (c *CipherContext) encryptionIV() []byte {
	iv := c.iv
	if c.mode != ECB && iv == nil {
		iv = make([]byte, c.cipher.BlockSize())
		rand.Read(iv)
		if c.mode == RandomDelta {
			iv[len(iv)-1] |= 1
		}
	}
	return iv
}

func (c *CipherContext) operationState(iv []byte, decrypt bool) *modeState {
	state := newModeState(c.cipher, c.mode, iv, decrypt)
	state.workers = c.workers
	return state
}

func (c *CipherContext) transformMode(data, iv []byte, decrypt bool) ([]byte, error) {
	if c.mode == RandomDelta {
		if decrypt {
			return decryptRandomDelta(data, c.cipher, c.workers)
		}
		return encryptRandomDelta(data, c.cipher, iv, c.workers)
	}
	return c.operationState(iv, decrypt).transform(data)
}

func (c *CipherContext) Decrypt(data []byte) ([]byte, error) {
	if c == nil || c.cipher == nil {
		return nil, fmt.Errorf("cipher context is not initialized")
	}
	blockSize := c.cipher.BlockSize()
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be a multiple of block size")
	}
	iv := c.iv
	if c.prefixesIV() {
		if len(data) < blockSize {
			return nil, fmt.Errorf("ciphertext is missing its IV")
		}
		iv, data = data[:blockSize], data[blockSize:]
	}
	result, err := c.transformMode(data, iv, true)
	if err != nil {
		return nil, err
	}
	return c.padding.UnPad(result, blockSize)
}
