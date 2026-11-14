package symmetric

import "cryp/block"

func transformCTR(data []byte, cipher block.BlockCipher, counter []byte) ([]byte, error) {
	return transformCounter(data, cipher, counter, []byte{1})
}

func transformCounter(data []byte, cipher block.BlockCipher, counter, step []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += blockSize {
		gamma, err := encryptBlock(counter, cipher)
		if err != nil {
			return nil, err
		}
		xorBlock(result[offset:offset+blockSize], data[offset:offset+blockSize], gamma)
		addCounter(counter, step)
	}
	return result, nil
}
