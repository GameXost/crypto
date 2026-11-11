package block

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrKeyNotSet         = errors.New("cipher key is not set")
	ErrInvalidBlockSize  = errors.New("invalid block size")
	ErrInvalidRoundBlock = errors.New("round function returned an invalid block")
)

type Feistel struct {
	blockSize     int
	keyExpander   KeyExpander
	roundFunction RoundFunction

	mu        sync.RWMutex
	roundKeys [][]byte
}

func NewFeistel(blockSize int, keyExpander KeyExpander, roundFunction RoundFunction) (*Feistel, error) {
	if blockSize <= 0 || blockSize%2 != 0 {
		return nil, fmt.Errorf("%w: Feistel block size must be positive and even", ErrInvalidBlockSize)
	}
	if keyExpander == nil {
		return nil, fmt.Errorf("key expander is required")
	}
	if roundFunction == nil {
		return nil, fmt.Errorf("round function is required")
	}

	return &Feistel{
		blockSize:     blockSize,
		keyExpander:   keyExpander,
		roundFunction: roundFunction,
	}, nil
}

func (f *Feistel) SetKey(key []byte) error {
	roundKeys, err := f.keyExpander.ExpandKey(bytes.Clone(key))
	if err != nil {
		return fmt.Errorf("expand key: %w", err)
	}
	if len(roundKeys) == 0 {
		return fmt.Errorf("key expander returned no round keys")
	}

	ownedKeys := make([][]byte, len(roundKeys))
	for i, roundKey := range roundKeys {
		ownedKeys[i] = bytes.Clone(roundKey)
	}

	f.mu.Lock()
	f.roundKeys = ownedKeys
	f.mu.Unlock()
	return nil
}

func (f *Feistel) BlockSize() int {
	return f.blockSize
}

func (f *Feistel) EncryptBlock(block []byte) ([]byte, error) {
	return f.transform(block, false)
}

func (f *Feistel) DecryptBlock(block []byte) ([]byte, error) {
	return f.transform(block, true)
}

func (f *Feistel) transform(block []byte, decrypt bool) ([]byte, error) {
	if len(block) != f.blockSize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidBlockSize, len(block), f.blockSize)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.roundKeys) == 0 {
		return nil, ErrKeyNotSet
	}

	halfSize := f.blockSize / 2
	left := bytes.Clone(block[:halfSize])
	right := bytes.Clone(block[halfSize:])

	for round := range f.roundKeys {
		keyIndex := round
		if decrypt {
			keyIndex = len(f.roundKeys) - 1 - round
		}

		transformed, err := f.roundFunction.Apply(right, f.roundKeys[keyIndex])
		if err != nil {
			return nil, fmt.Errorf("round %d: %w", round+1, err)
		}
		if len(transformed) != halfSize {
			return nil, fmt.Errorf("%w: round %d returned %d bytes, want %d", ErrInvalidRoundBlock, round+1, len(transformed), halfSize)
		}

		nextRight := make([]byte, halfSize)
		for i := range nextRight {
			nextRight[i] = left[i] ^ transformed[i]
		}
		left, right = right, nextRight
	}

	result := make([]byte, f.blockSize)
	copy(result, right)
	copy(result[halfSize:], left)
	return result, nil
}

var _ BlockCipher = (*Feistel)(nil)
