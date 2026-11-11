package block

// Task 2.

type KeyExpander interface {
	ExpandKey(key []byte) ([][]byte, error)
}

type RoundFunction interface {
	Apply(block, roundKey []byte) ([]byte, error)
}

// BlockCipher при нескольких воркерах или одновременных операциях должен допускать
// параллельные вызовы EncryptBlock/DecryptBlock без перезаписи их результатов.
// SetKey во время обработки запрещён.
type BlockCipher interface {
	SetKey(key []byte) error
	// BlockSize return size in bytes
	BlockSize() int
	EncryptBlock(block []byte) ([]byte, error)
	DecryptBlock(block []byte) ([]byte, error)
}
