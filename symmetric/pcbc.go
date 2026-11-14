package symmetric

func unchainBlocks(data, result, feedback []byte, propagate bool) {
	blockSize := len(feedback)
	for offset := 0; offset < len(data); offset += blockSize {
		current := data[offset : offset+blockSize]
		plain := result[offset : offset+blockSize]
		xorBlock(plain, plain, feedback)
		if propagate {
			xorBlock(feedback, plain, current)
		} else {
			copy(feedback, current)
		}
	}
}
