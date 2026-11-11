package symmetric

import (
	"bytes"
	"fmt"
	"math/rand"
)

func (p Padding) Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("blockSize smust be in [1:255]")
	}
	lenPadding := blockSize - (len(data) % blockSize)

	result := make([]byte, len(data)+lenPadding)
	copy(result, data)
	switch p {
	case Zeros:
		if len(data)%blockSize == 0 {
			return data, nil
		}
	case ANSIX923:
		result[len(data)+lenPadding-1] = byte(lenPadding)
	case PKCS7:
		padding := bytes.Repeat([]byte{byte(lenPadding)}, lenPadding)
		copy(result[len(data):], padding)
	case ISO10126:
		padding := make([]byte, lenPadding)
		for i := range padding {
			result[len(data)+i] = byte(rand.Int())
		}
		result[len(result)-1] = byte(lenPadding)
	default:
		return nil, fmt.Errorf("unknown padding type")
	}
	return result, nil
}

func (p Padding) UnPad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("blockSize must be in [1:255]")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("padded data length must be a multiple of block size")
	}
	lenPadding := 0
	if p != Zeros {
		if len(data) == 0 {
			return nil, fmt.Errorf("padded data must not be empty")
		}
		lenPadding = int(data[len(data)-1])
		if lenPadding < 1 || lenPadding > blockSize {
			return nil, fmt.Errorf("invalid padding length: %d", lenPadding)
		}
	}
	end := len(data) - lenPadding
	switch p {
	case Zeros:
		for end > 0 && data[end-1] == 0 {
			end--
		}
	case ANSIX923:
		for _, value := range data[end : len(data)-1] {
			if value != 0 {
				return nil, fmt.Errorf("invalid padding bytes")
			}
		}
	case PKCS7:
		for _, value := range data[end:] {
			if value != byte(lenPadding) {
				return nil, fmt.Errorf("invalid padding bytes")
			}
		}
	case ISO10126:
	default:
		return nil, fmt.Errorf("unknown padding type")
	}
	return bytes.Clone(data[:end]), nil
}
