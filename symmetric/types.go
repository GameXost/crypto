package symmetric

// Mode identifies the block cipher mode.
type Mode uint8

const (
	ECB Mode = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

// Padding identifies the padding scheme.
type Padding uint8

const (
	Zeros Padding = iota
	ANSIX923
	PKCS7
	ISO10126
)
