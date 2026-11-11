package symmetric

import "cryp/block"

func transformOFB(data []byte, cipher block.BlockCipher, feedback []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += blockSize {
		gamma, err := encryptBlock(feedback, cipher)
		if err != nil {
			return nil, err
		}
		xorBlock(result[offset:offset+blockSize], data[offset:offset+blockSize], gamma)
		copy(feedback, gamma)
	}
	return result, nil
}
