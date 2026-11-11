package symmetric

import (
	"fmt"

	"cryp/block"
)

func encryptECB(data []byte, cipher block.BlockCipher) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += blockSize {
		encrypted, err := cipher.EncryptBlock(data[offset : offset+blockSize])
		if err != nil {
			return nil, fmt.Errorf("encrypt block: %w", err)
		}
		if len(encrypted) != blockSize {
			return nil, fmt.Errorf("cipher returned %d bytes, want %d", len(encrypted), blockSize)
		}
		copy(result[offset:], encrypted)
	}
	return result, nil
}

func decryptECB(data []byte, cipher block.BlockCipher) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += blockSize {
		decrypted, err := cipher.DecryptBlock(data[offset : offset+blockSize])
		if err != nil {
			return nil, fmt.Errorf("decrypt block: %w", err)
		}
		if len(decrypted) != blockSize {
			return nil, fmt.Errorf("cipher returned %d bytes, want %d", len(decrypted), blockSize)
		}
		copy(result[offset:], decrypted)
	}
	return result, nil
}
