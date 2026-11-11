package block

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestDEALPublishedKnownAnswers(t *testing.T) {
	// Cryptix 1998: ecb_vk.txt / ecb_vt.txt в архиве ftp.funet.fi/pub/crypt/cryptography/symmetric/deal/deal.zip.
	for _, tt := range []struct{ key, plain, cipher string }{
		{"0123456789ABCDEF1032547698BADCFE", "0123456789ABCDEF1032547698BADCFE", "419C64EC7C579C4CAC81A4ED78D9374B"},
		{"80000000000000000000000000000000", "00000000000000000000000000000000", "EEC0DF4759817D07B747D5AE8E2E99D8"},
		{"800000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "35359BC13966119241AA81F2637996FD"},
		{"8000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000", "FB9FE58485DB9AE8B50A426112DAAAEF"},
		{"00000000000000000000000000000000", "80000000000000000000000000000000", "B21C092B6AB07F6A227DD47C78828D50"},
		{"000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "02969B3E16E491214CC9F6EEFC1C6481"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "80000000000000000000000000000000", "FE5D09F534ECA6D15C4BF4E51EB32E75"},
	} {
		t.Run(tt.key+"/"+tt.plain, func(t *testing.T) {
			cipher, err := NewDEAL()
			if err != nil {
				t.Fatal(err)
			}
			if err := cipher.SetKey(decodeHex(t, tt.key)); err != nil {
				t.Fatal(err)
			}
			if cipher.BlockSize() != 16 {
				t.Fatalf("BlockSize() = %d", cipher.BlockSize())
			}
			plain, expected := decodeHex(t, tt.plain), decodeHex(t, tt.cipher)
			got, err := cipher.EncryptBlock(plain)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatalf("EncryptBlock() = %x, %v; want %x", got, err, expected)
			}
			got, err = cipher.DecryptBlock(expected)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("DecryptBlock() = %x, %v; want %x", got, err, plain)
			}
		})
	}
}

func TestDEALKeyScheduleKnownAnswers(t *testing.T) {
	// Все 64 бита ключей сверены с Cryptix Java и отдельным oracle на Go crypto/des.
	for _, tt := range []struct{ key, rounds string }{
		{"000102030405060708090a0b0c0d0e0f", "3260266c2cf202e2 79cf70cd1dac09a5 4d29ed01607e2a58 70dab168c2f349b8 6f02d327070a6578 91dcce2439827d3e"},
		{"000102030405060708090a0b0c0d0e0f1011121314151617", "3260266c2cf202e2 79cf70cd1dac09a5 b218e9ca8b9251f2 9dd80b7dd35d25ca 780f554a37cdc165 d594bad2c4216a8d"},
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "3260266c2cf202e2 79cf70cd1dac09a5 b218e9ca8b9251f2 4512cab9af4aae12 95c6ec297d5572c4 2653231022a9be71 d614571deedc34b1 b9a25b74a14f709d"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			key := decodeHex(t, tt.key)
			original := bytes.Clone(key)
			keys, err := (DEALKeyExpander{}).ExpandKey(key)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Fields(tt.rounds)
			if len(keys) != len(want) {
				t.Fatalf("round count = %d, want %d", len(keys), len(want))
			}
			for i := range want {
				if !bytes.Equal(keys[i], decodeHex(t, want[i])) {
					t.Fatalf("round %d = %x, want %s", i, keys[i], want[i])
				}
			}
			if !bytes.Equal(key, original) {
				t.Fatal("ExpandKey modified input")
			}
			key[0] ^= 0xff
			if !bytes.Equal(keys[0], decodeHex(t, want[0])) {
				t.Fatal("round keys alias caller key")
			}
			keys[0][0] ^= 0xff
			for i := 1; i < len(keys); i++ {
				if !bytes.Equal(keys[i], decodeHex(t, want[i])) {
					t.Fatal("round keys share storage")
				}
			}
			fresh, err := (DEALKeyExpander{}).ExpandKey(original)
			if err != nil || !bytes.Equal(fresh[0], decodeHex(t, want[0])) {
				t.Fatalf("subsequent ExpandKey changed: %x, %v", fresh, err)
			}
		})
	}
}

func TestDEALValidation(t *testing.T) {
	cipher, err := NewDEAL()
	if err != nil {
		t.Fatal(err)
	}
	for _, unkeyed := range []*DEAL{nil, {}, cipher} {
		for _, run := range []func(*DEAL, []byte) ([]byte, error){(*DEAL).EncryptBlock, (*DEAL).DecryptBlock} {
			if got, err := run(unkeyed, make([]byte, 16)); !errors.Is(err, ErrKeyNotSet) || got != nil {
				t.Fatalf("unkeyed result = %x, %v", got, err)
			}
		}
	}
	for _, uninitialized := range []*DEAL{nil, {}} {
		if err := uninitialized.SetKey(make([]byte, 16)); !errors.Is(err, ErrKeyNotSet) {
			t.Fatalf("uninitialized SetKey error = %v", err)
		}
	}
	for _, length := range []int{0, 1, 8, 15, 17, 23, 25, 31, 33} {
		t.Run(fmt.Sprintf("key_%d", length), func(t *testing.T) {
			if err := cipher.SetKey(make([]byte, length)); !errors.Is(err, ErrInvalidKeySize) {
				t.Fatalf("SetKey error = %v", err)
			}
			if got, err := (DEALKeyExpander{}).ExpandKey(make([]byte, length)); !errors.Is(err, ErrInvalidKeySize) || got != nil {
				t.Fatalf("ExpandKey = %x, %v", got, err)
			}
		})
	}
	if err := cipher.SetKey(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{0, 1, 8, 15, 17, 32} {
		for _, run := range []func(*DEAL, []byte) ([]byte, error){(*DEAL).EncryptBlock, (*DEAL).DecryptBlock} {
			if got, err := run(cipher, make([]byte, length)); !errors.Is(err, ErrInvalidBlockSize) || got != nil {
				t.Fatalf("block length %d = %x, %v", length, got, err)
			}
		}
	}
}

func TestDEALOwnershipAndRekey(t *testing.T) {
	cipher, err := NewDEAL()
	if err != nil {
		t.Fatal(err)
	}
	plain := decodeHex(t, "000102030405060708090a0b0c0d0e0f")
	original := bytes.Clone(plain)
	for _, tt := range []struct{ key, ciphertext string }{
		{"000102030405060708090a0b0c0d0e0f", "47070f29f814c92b1ad7556fe98262fb"},
		{"000102030405060708090a0b0c0d0e0f1011121314151617", "0f2df43b7b28105ff2b9f3bae0694924"},
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "5b9014b97fdc142a19b54e5107666fe9"},
	} {
		key := decodeHex(t, tt.key)
		if err := cipher.SetKey(key); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, decodeHex(t, tt.key)) {
			t.Fatal("SetKey modified input")
		}
		key[0] ^= 0xff
		want := decodeHex(t, tt.ciphertext)
		encoded, err := cipher.EncryptBlock(plain)
		if err != nil || !bytes.Equal(encoded, want) {
			t.Fatalf("encryption after caller key change = %x, %v", encoded, err)
		}
		decoded, err := cipher.DecryptBlock(encoded)
		if err != nil || !bytes.Equal(decoded, original) {
			t.Fatalf("decryption = %x, %v", decoded, err)
		}
		decoded[0] ^= 0xff
		if !bytes.Equal(encoded, want) || !bytes.Equal(plain, original) {
			t.Fatal("decryption aliases or changes its input")
		}
		encoded[0] ^= 0xff
		if !bytes.Equal(plain, original) {
			t.Fatal("encryption result aliases input")
		}
		if err := cipher.SetKey(make([]byte, 17)); !errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("failed rekey error = %v", err)
		}
		again, err := cipher.EncryptBlock(plain)
		if err != nil || !bytes.Equal(again, want) {
			t.Fatalf("failed rekey or result mutation changed key: %x, %v", again, err)
		}
	}
}

func TestDESRoundAdapter(t *testing.T) {
	adapter := DESRoundAdapter{}
	plain, key := decodeHex(t, "0123456789ABCDEF"), decodeHex(t, "133457799BBCDFF1")
	want := decodeHex(t, "85E813540F0AB405")
	got, err := adapter.Apply(plain, key)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Apply = %x, %v; want %x", got, err, want)
	}
	got[0] ^= 0xff
	if !bytes.Equal(plain, decodeHex(t, "0123456789ABCDEF")) || !bytes.Equal(key, decodeHex(t, "133457799BBCDFF1")) {
		t.Fatal("Apply changed input or returned an alias")
	}
	for _, length := range []int{0, 7, 9} {
		if got, err := adapter.Apply(make([]byte, length), key); !errors.Is(err, ErrInvalidBlockSize) || got != nil {
			t.Fatalf("bad block = %x, %v", got, err)
		}
		if got, err := adapter.Apply(plain, make([]byte, length)); !errors.Is(err, ErrInvalidKeySize) || got != nil {
			t.Fatalf("bad key = %x, %v", got, err)
		}
	}
}

func TestDEALConcurrentEncryptionAndDecryption(t *testing.T) {
	cipher, err := NewDEAL()
	if err != nil {
		t.Fatal(err)
	}
	plain := decodeHex(t, "000102030405060708090a0b0c0d0e0f")
	if err := cipher.SetKey(plain); err != nil {
		t.Fatal(err)
	}
	expected := decodeHex(t, "47070f29f814c92b1ad7556fe98262fb")
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for attempt := 0; attempt < 5; attempt++ {
				got, err := cipher.EncryptBlock(plain)
				if err != nil || !bytes.Equal(got, expected) {
					t.Errorf("concurrent encrypt = %x, %v", got, err)
					return
				}
				got, err = cipher.DecryptBlock(expected)
				if err != nil || !bytes.Equal(got, plain) {
					t.Errorf("concurrent decrypt = %x, %v", got, err)
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}
