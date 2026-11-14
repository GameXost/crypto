package block

import "fmt"

type DEALKeyExpander struct{}

type DESRoundAdapter struct{}

type DEAL struct {
	network *Feistel
}

func NewDEAL() (*DEAL, error) {
	network, err := NewFeistel(16, DEALKeyExpander{}, DESRoundAdapter{})
	if err != nil {
		return nil, fmt.Errorf("create DEAL Feistel network: %w", err)
	}
	return &DEAL{network: network}, nil
}

func (d *DEAL) SetKey(key []byte) error {
	if d == nil || d.network == nil {
		return ErrKeyNotSet
	}
	return d.network.SetKey(key)
}

func (d *DEAL) BlockSize() int { return 16 }

func (d *DEAL) EncryptBlock(data []byte) ([]byte, error) {
	return d.transform(data, false)
}

func (d *DEAL) DecryptBlock(data []byte) ([]byte, error) {
	return d.transform(data, true)
}

func (d *DEAL) transform(data []byte, decrypt bool) ([]byte, error) {
	if d == nil || d.network == nil {
		return nil, ErrKeyNotSet
	}
	if len(data) != d.BlockSize() {
		return nil, fmt.Errorf("DEAL: %w: got %d bytes, want %d", ErrInvalidBlockSize, len(data), d.BlockSize())
	}
	var result []byte
	var err error
	if decrypt {
		result, err = d.network.DecryptBlock(data)
	} else {

		result, err = d.network.EncryptBlock(swapDEALHalves(data))
	}
	if err != nil {
		return nil, fmt.Errorf("DEAL Feistel network: %w", err)
	}
	if decrypt {
		result = swapDEALHalves(result)
	}
	return result, nil
}

func swapDEALHalves(data []byte) []byte {
	half := len(data) / 2
	result := make([]byte, len(data))
	copy(result, data[half:])
	copy(result[half:], data[:half])
	return result
}

func (DEALKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	rounds, err := dealRounds(len(key))
	if err != nil {
		return nil, err
	}
	cipher, err := NewDES()
	if err != nil {
		return nil, fmt.Errorf("create DEAL key cipher: %w", err)
	}
	if err := cipher.SetKey([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}); err != nil {
		return nil, fmt.Errorf("set DEAL fixed key: %w", err)
	}
	parts := len(key) / 8
	roundKeys := make([][]byte, rounds)
	previous := make([]byte, 8)
	mixed := make([]byte, 8)
	for round := range roundKeys {
		part := key[(round%parts)*8 : (round%parts+1)*8]
		for i := range mixed {
			mixed[i] = part[i] ^ previous[i]
		}
		if round >= parts {

			mixed[0] ^= byte(0x80 >> (round - parts))
		}
		roundKeys[round], err = cipher.EncryptBlock(mixed)
		if err != nil {
			return nil, fmt.Errorf("expand DEAL round %d: %w", round+1, err)
		}
		previous = roundKeys[round]
	}
	return roundKeys, nil
}

func dealRounds(keySize int) (int, error) {
	switch keySize {
	case 16, 24:
		return 6, nil
	case 32:
		return 8, nil
	default:
		return 0, fmt.Errorf("DEAL: %w: got %d bytes, want 16, 24 or 32", ErrInvalidKeySize, keySize)
	}
}

func (DESRoundAdapter) Apply(data, roundKey []byte) ([]byte, error) {
	if len(data) != 8 {
		return nil, fmt.Errorf("DEAL round: %w: got %d bytes, want 8", ErrInvalidBlockSize, len(data))
	}
	if len(roundKey) != 8 {
		return nil, fmt.Errorf("DEAL round: %w: got %d bytes, want 8", ErrInvalidKeySize, len(roundKey))
	}

	cipher, err := NewDES()
	if err != nil {
		return nil, fmt.Errorf("create DEAL round cipher: %w", err)
	}
	if err := cipher.SetKey(roundKey); err != nil {
		return nil, fmt.Errorf("set DEAL round key: %w", err)
	}
	return cipher.EncryptBlock(data)
}
