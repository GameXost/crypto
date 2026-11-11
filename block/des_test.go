package block

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

func TestDESKnownAnswer(t *testing.T) {
	cipher, err := NewDES()
	if err != nil {
		t.Fatalf("NewDES: %v", err)
	}
	if err := cipher.SetKey(decodeHex(t, "133457799BBCDFF1")); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	plain := decodeHex(t, "0123456789ABCDEF")
	wantCipher := decodeHex(t, "85E813540F0AB405")
	gotCipher, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}
	if !bytes.Equal(gotCipher, wantCipher) {
		t.Fatalf("EncryptBlock = %X, want %X", gotCipher, wantCipher)
	}

	gotPlain, err := cipher.DecryptBlock(wantCipher)
	if err != nil {
		t.Fatalf("DecryptBlock: %v", err)
	}
	if !bytes.Equal(gotPlain, plain) {
		t.Fatalf("DecryptBlock = %X, want %X", gotPlain, plain)
	}
}

func TestDESKeyScheduleAndRoundFunction(t *testing.T) {
	key := decodeHex(t, "133457799BBCDFF1")
	roundKeys, err := (DESKeyExpander{}).ExpandKey(key)
	if err != nil {
		t.Fatalf("ExpandKey: %v", err)
	}
	if len(roundKeys) != 16 {
		t.Fatalf("ExpandKey returned %d keys, want 16", len(roundKeys))
	}
	if want := decodeHex(t, "1B02EFFC7072"); !bytes.Equal(roundKeys[0], want) {
		t.Fatalf("K1 = %X, want %X", roundKeys[0], want)
	}
	if want := decodeHex(t, "CB3D8B0E17F5"); !bytes.Equal(roundKeys[15], want) {
		t.Fatalf("K16 = %X, want %X", roundKeys[15], want)
	}

	got, err := (DESRoundFunction{}).Apply(decodeHex(t, "F0AAF0AA"), roundKeys[0])
	if err != nil {
		t.Fatalf("DES F: %v", err)
	}
	if want := decodeHex(t, "234AA9BB"); !bytes.Equal(got, want) {
		t.Fatalf("DES F = %X, want %X", got, want)
	}
}

func TestDESValidationAndOwnership(t *testing.T) {
	cipher, err := NewDES()
	if err != nil {
		t.Fatalf("NewDES: %v", err)
	}
	if _, err := cipher.EncryptBlock(make([]byte, 8)); !errors.Is(err, ErrKeyNotSet) {
		t.Fatalf("EncryptBlock without key error = %v, want ErrKeyNotSet", err)
	}
	if err := cipher.SetKey(make([]byte, 7)); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("SetKey error = %v, want ErrInvalidKeySize", err)
	}
	if err := cipher.SetKey(make([]byte, 8)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if _, err := cipher.EncryptBlock(make([]byte, 7)); !errors.Is(err, ErrInvalidBlockSize) {
		t.Fatalf("EncryptBlock error = %v, want ErrInvalidBlockSize", err)
	}

	plain := make([]byte, 8)
	before := bytes.Clone(plain)
	first, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}
	if !bytes.Equal(plain, before) {
		t.Fatalf("EncryptBlock modified input: %X", plain)
	}
	first[0] ^= 0xff
	second, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("second EncryptBlock: %v", err)
	}
	if first[0] == second[0] {
		t.Fatal("EncryptBlock results share mutable storage")
	}

	want := bytes.Clone(second)
	if err := cipher.SetKey(make([]byte, 7)); err == nil {
		t.Fatal("SetKey accepted an invalid key")
	}
	got, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock after failed SetKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("failed SetKey changed the previous valid key")
	}
}

func TestDESParityBitsDoNotAffectEncryption(t *testing.T) {
	key := decodeHex(t, "133457799BBCDFF1")
	parityChanged := bytes.Clone(key)
	for i := range parityChanged {
		parityChanged[i] ^= 1
	}

	plain := decodeHex(t, "0123456789ABCDEF")
	results := make([][]byte, 2)
	for i, currentKey := range [][]byte{key, parityChanged} {
		cipher, err := NewDES()
		if err != nil {
			t.Fatalf("NewDES: %v", err)
		}
		if err := cipher.SetKey(currentKey); err != nil {
			t.Fatalf("SetKey: %v", err)
		}
		results[i], err = cipher.EncryptBlock(plain)
		if err != nil {
			t.Fatalf("EncryptBlock: %v", err)
		}
	}
	if !bytes.Equal(results[0], results[1]) {
		t.Fatalf("parity bits changed DES result: %X != %X", results[0], results[1])
	}
}

func TestDESRoundFunctionValidation(t *testing.T) {
	function := DESRoundFunction{}
	if _, err := function.Apply(make([]byte, 3), make([]byte, 6)); !errors.Is(err, ErrInvalidBlockSize) {
		t.Fatalf("data size error = %v, want ErrInvalidBlockSize", err)
	}
	if _, err := function.Apply(make([]byte, 4), make([]byte, 5)); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("key size error = %v, want ErrInvalidKeySize", err)
	}
}
