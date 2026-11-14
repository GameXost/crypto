package symmetric

import (
	"bytes"
	"fmt"

	"cryp/block"
)

type modeState struct {
	cipher    block.BlockCipher
	mode      Mode
	feedback  []byte
	delta     []byte
	decrypt   bool
	processed uint64
	workers   int
}

func newModeState(cipher block.BlockCipher, mode Mode, iv []byte, decrypt bool) *modeState {
	s := &modeState{cipher: cipher, mode: mode, feedback: bytes.Clone(iv), decrypt: decrypt, workers: 1}
	if mode == RandomDelta {
		s.delta = bytes.Clone(iv[cipher.BlockSize()/2:])
	}
	return s
}

func (s *modeState) transform(data []byte) ([]byte, error) {
	count := uint64(len(data) / s.cipher.BlockSize())
	if err := s.checkBlocks(count); err != nil {
		return nil, err
	}
	var result []byte
	var err error
	if s.workers > 1 && count > 1 && s.canParallel() {
		result, err = s.transformParallel(data)
	} else {
		result, err = s.transformBlocks(data)
	}
	if err != nil {
		return nil, err
	}
	s.processed += count
	return result, nil
}

func (s *modeState) checkBlocks(count uint64) error {
	if count > ^uint64(0)-s.processed {
		return fmt.Errorf("message block count overflows uint64")
	}
	if s.mode == CTR || s.mode == RandomDelta {
		blockSize := s.cipher.BlockSize()
		if blockSize < 8 && count > uint64(1)<<(8*blockSize)-s.processed {
			return fmt.Errorf("message exceeds the counter period")
		}
	}
	return nil
}

func (s *modeState) transformBlocks(data []byte) ([]byte, error) {
	ecb := encryptECB
	chained := encryptChained
	if s.decrypt {
		ecb = decryptECB
		chained = decryptChained
	}
	switch s.mode {
	case ECB:
		return ecb(data, s.cipher)
	case CBC, PCBC:
		return chained(data, s.cipher, s.feedback, s.mode == PCBC)
	case CFB:
		return cryptCFB(data, s.cipher, s.feedback, s.decrypt)
	case OFB:
		return transformOFB(data, s.cipher, s.feedback)
	case CTR:
		return transformCTR(data, s.cipher, s.feedback)
	case RandomDelta:
		return transformRandomDelta(data, s.cipher, s.feedback, s.delta)
	default:
		return nil, fmt.Errorf("unknown mode %d", s.mode)
	}
}
