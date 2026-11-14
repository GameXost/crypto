package block

import (
	"encoding/binary"
	"errors"
	"fmt"

	"cryp/funcs"
)

var ErrInvalidKeySize = errors.New("invalid key size")

type DESKeyExpander struct{}

type DESRoundFunction struct{}

type DES struct {
	network *Feistel
}

func NewDES() (*DES, error) {
	network, err := NewFeistel(8, DESKeyExpander{}, DESRoundFunction{})
	if err != nil {
		return nil, fmt.Errorf("create DES Feistel network: %w", err)
	}
	return &DES{network: network}, nil
}

func (d *DES) SetKey(key []byte) error {
	if d == nil || d.network == nil {
		return ErrKeyNotSet
	}
	return d.network.SetKey(key)
}

func (d *DES) BlockSize() int {
	return 8
}

func (d *DES) EncryptBlock(block []byte) ([]byte, error) {
	return d.transform(block, false)
}

func (d *DES) DecryptBlock(block []byte) ([]byte, error) {
	return d.transform(block, true)
}

func (d *DES) transform(block []byte, decrypt bool) ([]byte, error) {
	if d == nil || d.network == nil {
		return nil, ErrKeyNotSet
	}
	if len(block) != d.BlockSize() {
		return nil, fmt.Errorf("DES: %w: got %d bytes, want %d", ErrInvalidBlockSize, len(block), d.BlockSize())
	}

	permuted, err := funcs.Permutate(block, desIP, funcs.MSBFirst, 1)
	if err != nil {
		return nil, fmt.Errorf("DES initial permutation: %w", err)
	}

	var preoutput []byte
	if decrypt {
		preoutput, err = d.network.DecryptBlock(permuted)
	} else {
		preoutput, err = d.network.EncryptBlock(permuted)
	}
	if err != nil {
		return nil, fmt.Errorf("DES Feistel network: %w", err)
	}

	result, err := funcs.Permutate(preoutput, desIPInverse, funcs.MSBFirst, 1)
	if err != nil {
		return nil, fmt.Errorf("DES final permutation: %w", err)
	}
	return result, nil
}

func (DESKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES: %w: got %d bytes, want 8", ErrInvalidKeySize, len(key))
	}

	permuted, err := funcs.Permutate(key, desPC1, funcs.MSBFirst, 1)
	if err != nil {
		return nil, fmt.Errorf("DES PC-1: %w", err)
	}

	var key56 uint64
	for _, value := range permuted {
		key56 = key56<<8 | uint64(value)
	}
	left := uint32(key56 >> 28)
	right := uint32(key56 & 0x0fffffff)

	roundKeys := make([][]byte, len(desKeyShifts))
	for round, shift := range desKeyShifts {
		left = rotate28(left, shift)
		right = rotate28(right, shift)

		var packed [8]byte
		binary.BigEndian.PutUint64(packed[:], uint64(left)<<28|uint64(right))
		roundKeys[round], err = funcs.Permutate(packed[1:], desPC2, funcs.MSBFirst, 1)
		if err != nil {
			return nil, fmt.Errorf("DES PC-2 round %d: %w", round+1, err)
		}
	}
	return roundKeys, nil
}

func rotate28(value uint32, shift uint) uint32 {
	return ((value << shift) | (value >> (28 - shift))) & 0x0fffffff
}

func (DESRoundFunction) Apply(right, roundKey []byte) ([]byte, error) {
	if len(right) != 4 {
		return nil, fmt.Errorf("DES F: %w: got %d data bytes, want 4", ErrInvalidBlockSize, len(right))
	}
	if len(roundKey) != 6 {
		return nil, fmt.Errorf("DES F: %w: got %d key bytes, want 6", ErrInvalidKeySize, len(roundKey))
	}

	expanded, err := funcs.Permutate(right, desExpansion, funcs.MSBFirst, 1)
	if err != nil {
		return nil, fmt.Errorf("DES expansion: %w", err)
	}
	for i := range expanded {
		expanded[i] ^= roundKey[i]
	}

	var mixed uint64
	for _, value := range expanded {
		mixed = mixed<<8 | uint64(value)
	}
	var substituted uint32
	for box := 0; box < 8; box++ {
		sixBits := byte(mixed>>uint(42-6*box)) & 0x3f
		row := ((sixBits & 0x20) >> 4) | (sixBits & 1)
		column := (sixBits >> 1) & 0x0f
		substituted = substituted<<4 | uint32(desSBoxes[box][row][column])
	}

	var packed [4]byte
	binary.BigEndian.PutUint32(packed[:], substituted)
	result, err := funcs.Permutate(packed[:], desPermutation, funcs.MSBFirst, 1)
	if err != nil {
		return nil, fmt.Errorf("DES P permutation: %w", err)
	}
	return result, nil
}
