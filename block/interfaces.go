package block

type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

type RoundFunction interface {
	Apply(block, roundKey []byte) ([]byte, error)
}

type BlockCipher interface {
	SetKey(key []byte) error

	BlockSize() int
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}
