package block

import (
	"bytes"
	"errors"
	"testing"
)

type fixedKeyExpander struct {
	keys [][]byte
	err  error
}

func (e *fixedKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.keys, nil
}

type xorRoundFunction struct{}

func (xorRoundFunction) Apply(block, roundKey []byte) ([]byte, error) {
	if len(block) != len(roundKey) {
		return nil, errors.New("different block and key sizes")
	}
	result := make([]byte, len(block))
	for i := range result {
		result[i] = block[i] ^ roundKey[i]
	}
	return result, nil
}

func TestFeistelEncryptDecrypt(t *testing.T) {
	expander := &fixedKeyExpander{keys: [][]byte{
		{0x0f, 0xf0},
		{0xaa, 0x55},
		{0x01, 0x02},
	}}
	cipher, err := NewFeistel(4, expander, xorRoundFunction{})
	if err != nil {
		t.Fatalf("NewFeistel: %v", err)
	}
	if err := cipher.SetKey([]byte("master key")); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	plain := []byte{0x12, 0x34, 0x56, 0x78}
	encrypted, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}
	wantEncrypted := []byte{0xfd, 0x2f, 0xb7, 0x91}
	if !bytes.Equal(encrypted, wantEncrypted) {
		t.Fatalf("EncryptBlock = %x, want %x", encrypted, wantEncrypted)
	}

	decrypted, err := cipher.DecryptBlock(encrypted)
	if err != nil {
		t.Fatalf("DecryptBlock: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("DecryptBlock = %x, want %x", decrypted, plain)
	}
}

func TestFeistelDoesNotModifyInputs(t *testing.T) {
	roundKeys := [][]byte{{1, 2}, {3, 4}}
	cipher, err := NewFeistel(4, &fixedKeyExpander{keys: roundKeys}, xorRoundFunction{})
	if err != nil {
		t.Fatalf("NewFeistel: %v", err)
	}
	key := []byte{5, 6}
	if err := cipher.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	key[0] = 99
	roundKeys[0][0] = 99
	plain := []byte{7, 8, 9, 10}
	before := bytes.Clone(plain)
	first, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}
	if !bytes.Equal(plain, before) {
		t.Fatalf("EncryptBlock modified its input: %x", plain)
	}

	first[0] ^= 0xff
	second, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("second EncryptBlock: %v", err)
	}
	if first[0] == second[0] {
		t.Fatal("EncryptBlock results share mutable storage")
	}
}

func TestFeistelValidation(t *testing.T) {
	expander := &fixedKeyExpander{keys: [][]byte{{1, 2}}}

	for _, blockSize := range []int{0, -2, 3} {
		if _, err := NewFeistel(blockSize, expander, xorRoundFunction{}); !errors.Is(err, ErrInvalidBlockSize) {
			t.Errorf("NewFeistel(%d) error = %v, want ErrInvalidBlockSize", blockSize, err)
		}
	}
	if _, err := NewFeistel(4, nil, xorRoundFunction{}); err == nil {
		t.Fatal("NewFeistel accepted nil key expander")
	}
	if _, err := NewFeistel(4, expander, nil); err == nil {
		t.Fatal("NewFeistel accepted nil round function")
	}

	cipher, err := NewFeistel(4, expander, xorRoundFunction{})
	if err != nil {
		t.Fatalf("NewFeistel: %v", err)
	}
	if _, err := cipher.EncryptBlock(make([]byte, 4)); !errors.Is(err, ErrKeyNotSet) {
		t.Fatalf("EncryptBlock without key error = %v, want ErrKeyNotSet", err)
	}
	if err := cipher.SetKey([]byte{1}); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if _, err := cipher.EncryptBlock(make([]byte, 3)); !errors.Is(err, ErrInvalidBlockSize) {
		t.Fatalf("EncryptBlock wrong size error = %v, want ErrInvalidBlockSize", err)
	}
}

func TestFeistelFailedRekeyKeepsOldKeys(t *testing.T) {
	expander := &fixedKeyExpander{keys: [][]byte{{1, 2}, {3, 4}}}
	cipher, err := NewFeistel(4, expander, xorRoundFunction{})
	if err != nil {
		t.Fatalf("NewFeistel: %v", err)
	}
	if err := cipher.SetKey([]byte{1}); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	plain := []byte{5, 6, 7, 8}
	want, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}

	expander.err = errors.New("bad key")
	if err := cipher.SetKey([]byte{2}); err == nil {
		t.Fatal("SetKey accepted a key after expansion failed")
	}
	got, err := cipher.EncryptBlock(plain)
	if err != nil {
		t.Fatalf("EncryptBlock after failed SetKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("failed SetKey changed cipher state: got %x, want %x", got, want)
	}
}

type shortRoundFunction struct{}

func (shortRoundFunction) Apply([]byte, []byte) ([]byte, error) {
	return []byte{1}, nil
}

func TestFeistelRejectsWrongRoundOutputSize(t *testing.T) {
	cipher, err := NewFeistel(4, &fixedKeyExpander{keys: [][]byte{{1}}}, shortRoundFunction{})
	if err != nil {
		t.Fatalf("NewFeistel: %v", err)
	}
	if err := cipher.SetKey([]byte{1}); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if _, err := cipher.EncryptBlock(make([]byte, 4)); !errors.Is(err, ErrInvalidRoundBlock) {
		t.Fatalf("EncryptBlock error = %v, want ErrInvalidRoundBlock", err)
	}
}
