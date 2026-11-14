package symmetric

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

type Padding uint8

const (
	Zeros Padding = iota
	ANSIX923
	PKCS7
	ISO10126
)
