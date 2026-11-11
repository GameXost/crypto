package funcs

import (
	"fmt"
)

type BitOrder int

const (
	MSBFirst = iota
	LSBFirst
)

func Permutate(data []byte, rule []int, order BitOrder, base int) ([]byte, error) {
	if order != MSBFirst && order != LSBFirst {
		return nil, fmt.Errorf("invalid bit order: %d", order)
	}
	if base != 0 && base != 1 {
		return nil, fmt.Errorf("invalid index base: %d (allowed only 0 or 1)", base)
	}

	result := make([]byte, (len(rule)+7)/8)
	for outputBit, sourceNumber := range rule {
		if sourceNumber < base || (sourceNumber-base)/8 >= len(data) {
			return nil, fmt.Errorf("rule[%d]: bit index %d is out of range for %d input bytes (base %d)", outputBit, sourceNumber, len(data), base)
		}
		sourceBit := sourceNumber - base
		sourceByte := sourceBit / 8
		sourceShift := 7 - sourceBit%8
		if order == LSBFirst {
			sourceByte = len(data) - 1 - sourceByte
			sourceShift = sourceBit % 8
		}
		bit := (data[sourceByte] >> sourceShift) & 1
		result[outputBit/8] |= bit << (7 - outputBit%8)
	}
	return result, nil
}
