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

func transformRandomDelta(data []byte, cipher block.BlockCipher, counter, delta []byte) ([]byte, error) {
	return transformCounter(data, cipher, counter, delta)
}
