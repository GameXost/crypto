package symmetric

import (
	"fmt"

	"cryp/block"
)

func validateRandomDeltaIV(iv []byte, blockSize int) error {
	if blockSize%2 != 0 {
		return fmt.Errorf("RandomDelta requires an even block size")
	}
	if iv != nil && iv[len(iv)-1]&1 == 0 {
		return fmt.Errorf("RandomDelta requires an odd delta")
	}
	return nil
}

func encryptRandomDelta(data []byte, cipher block.BlockCipher, iv []byte, workers int) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if err := validateCounterPeriod(len(data), blockSize); err != nil {
		return nil, err
	}
	header, err := encryptBlock(iv, cipher)
	if err != nil {
		return nil, err
	}
	result := make([]byte, blockSize+len(data))
	copy(result, header)
	state := newModeState(cipher, RandomDelta, iv, false)
	state.workers = workers
	payload, err := state.transform(data)
	if err != nil {
		return nil, err
	}
	copy(result[blockSize:], payload)
	return result, nil
}

func decryptRandomDelta(data []byte, cipher block.BlockCipher, workers int) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(data) < blockSize {
		return nil, fmt.Errorf("RandomDelta ciphertext is missing its IV")
	}
	if err := validateCounterPeriod(len(data)-blockSize, blockSize); err != nil {
		return nil, err
	}
	iv, err := decryptBlock(data[:blockSize], cipher)
	if err != nil {
		return nil, err
	}
	if err := validateRandomDeltaIV(iv, blockSize); err != nil {
		return nil, err
	}
	state := newModeState(cipher, RandomDelta, iv, true)
	state.workers = workers
	return state.transform(data[blockSize:])
}

func transformRandomDelta(data []byte, cipher block.BlockCipher, counter, delta []byte, decrypt bool) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	mixed := make([]byte, blockSize)
	transform := cipher.EncryptBlock
	if decrypt {
		transform = cipher.DecryptBlock
	}
	for offset := 0; offset < len(data); offset += blockSize {
		input := data[offset : offset+blockSize]
		if !decrypt {
			xorBlock(mixed, input, counter)
			input = mixed
		}
		transformed, err := transformBlock(input, transform)
		if err != nil {
			return nil, err
		}
		output := result[offset : offset+blockSize]
		if decrypt {
			xorBlock(output, transformed, counter)
		} else {
			copy(output, transformed)
		}
		addCounter(counter, delta)
	}
	return result, nil
}
