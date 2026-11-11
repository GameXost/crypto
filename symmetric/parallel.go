package symmetric

import (
	"bytes"
	"sync"
)

func (s *modeState) canParallel() bool {
	switch s.mode {
	case ECB, CTR, RandomDelta:
		return true
	case CBC, PCBC, CFB:
		return s.decrypt
	default:
		return false
	}
}

func (s *modeState) transformParallel(data []byte) ([]byte, error) {
	if s.mode != PCBC {
		return s.transformParallelRanges(data)
	}
	blocks := *s
	blocks.mode = ECB
	blocks.feedback = nil
	result, err := blocks.transformParallelRanges(data)
	if err != nil {
		return nil, err
	}
	unchainBlocks(data, result, s.feedback, true)
	return result, nil
}

func (s *modeState) transformParallelRanges(data []byte) ([]byte, error) {
	blockSize := s.cipher.BlockSize()
	blockCount := len(data) / blockSize
	workers := min(s.workers, blockCount)
	result := make([]byte, len(data))
	errors := make([]error, workers)
	var group sync.WaitGroup
	var lastState *modeState
	start := 0
	for worker := 0; worker < workers; worker++ {
		count := blockCount / workers
		if worker < blockCount%workers {
			count++
		}
		end := start + count*blockSize
		state := s.rangeState(data, start)
		lastState = state
		group.Add(1)
		go func(worker, start, end int, state *modeState) {
			defer group.Done()
			part, err := state.transformBlocks(data[start:end])
			errors[worker] = err
			if err == nil {
				copy(result[start:end], part)
			}
		}(worker, start, end, state)
		start = end
	}
	group.Wait()
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	copy(s.feedback, lastState.feedback)
	return result, nil
}

func (s *modeState) rangeState(data []byte, start int) *modeState {
	state := *s
	state.feedback = bytes.Clone(s.feedback)
	blockSize := s.cipher.BlockSize()
	switch s.mode {
	case CBC, CFB:
		if start > 0 {
			copy(state.feedback, data[start-blockSize:start])
		}
	case CTR:
		advanceCounter(state.feedback, []byte{1}, uint64(start/blockSize))
	case RandomDelta:
		advanceCounter(state.feedback, s.delta, uint64(start/blockSize))
	}
	return &state
}

func advanceCounter(counter, step []byte, count uint64) {
	increment := make([]byte, len(counter))
	copy(increment[len(increment)-len(step):], step)
	for count > 0 {
		if count&1 != 0 {
			addCounter(counter, increment)
		}
		addCounter(increment, increment)
		count >>= 1
	}
}
