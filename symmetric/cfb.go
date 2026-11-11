package symmetric

import "cryp/block"

func cryptCFB(data []byte, cipher block.BlockCipher, iv []byte, decrypt bool) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	feedback := iv
	for offset := 0; offset < len(data); offset += blockSize {
		gamma, err := encryptBlock(feedback, cipher)
		if err != nil {
			return nil, err
		}
		current := data[offset : offset+blockSize]
		output := result[offset : offset+blockSize]
		xorBlock(output, current, gamma)
		if decrypt {
			feedback = current
		} else {
			feedback = output
		}
	}
	copy(iv, feedback)
	return result, nil
}
