package symmetric

import (
	"fmt"

	"cryp/block"
)

func validateIV(mode Mode, iv []byte, blockSize int) error {
	if mode == ECB {
		if len(iv) != 0 {
			return fmt.Errorf("ECB does not use an IV")
		}
		return nil
	}
	if iv != nil && len(iv) != blockSize {
		return fmt.Errorf("IV must have %d bytes", blockSize)
	}
	if mode == RandomDelta {
		return validateRandomDeltaIV(iv, blockSize)
	}
	return nil
}

func encryptBlock(data []byte, cipher block.BlockCipher) ([]byte, error) {
	return transformBlock(data, cipher.EncryptBlock)
}

func decryptBlock(data []byte, cipher block.BlockCipher) ([]byte, error) {
	return transformBlock(data, cipher.DecryptBlock)
}

func transformBlock(data []byte, transform func([]byte) ([]byte, error)) ([]byte, error) {
	result, err := transform(data)
	if err != nil {
		return nil, fmt.Errorf("transform block: %w", err)
	}
	if len(result) != len(data) {
		return nil, fmt.Errorf("cipher returned %d bytes, want %d", len(result), len(data))
	}
	return result, nil
}

func xorBlock(dst, left, right []byte) {
	for i := range dst {
		dst[i] = left[i] ^ right[i]
	}
}

func addCounter(counter, step []byte) {
	ost := 0
	for i := len(counter) - 1; i >= 0; i-- {
		sum := int(counter[i]) + ost
		j := i - len(counter) + len(step)
		if j >= 0 {
			sum += int(step[j])
		}
		counter[i] = byte(sum)
		ost = sum >> 8
	}
}

func validateCounterPeriod(dataLen, blockSize int) error {
	if blockSize < 8 && uint64(dataLen/blockSize) > uint64(1)<<(8*blockSize) {
		return fmt.Errorf("message exceeds the counter period")
	}
	return nil
}
