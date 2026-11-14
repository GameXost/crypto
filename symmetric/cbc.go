package symmetric

import "cryp/block"

func encryptChained(data []byte, cipher block.BlockCipher, iv []byte, propagate bool) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	feedback := iv
	mixed := make([]byte, blockSize)
	for offset := 0; offset < len(data); offset += blockSize {
		plain := data[offset : offset+blockSize]
		xorBlock(mixed, plain, feedback)
		encrypted, err := encryptBlock(mixed, cipher)
		if err != nil {
			return nil, err
		}
		copy(result[offset:], encrypted)
		if propagate {
			xorBlock(feedback, plain, encrypted)
		} else {
			copy(feedback, encrypted)
		}
	}
	return result, nil
}

func decryptChained(data []byte, cipher block.BlockCipher, iv []byte, propagate bool) ([]byte, error) {
	result, err := decryptECB(data, cipher)
	if err != nil {
		return nil, err
	}
	unchainBlocks(data, result, iv, propagate)
	return result, nil
}
