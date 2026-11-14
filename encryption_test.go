package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cryp/block"
	"cryp/symmetric"
)

func newEncryptionContext(t *testing.T, algorithm string, mode symmetric.Mode) *symmetric.CipherContext {
	t.Helper()
	var cipher block.BlockCipher
	var key []byte
	var err error
	if algorithm == "DES" {
		cipher, err = block.NewDES()
		key = []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}
	} else {
		cipher, err = block.NewDEAL()
		key = []byte("0123456789abcdef")
	}
	if err != nil {
		t.Fatal(err)
	}
	c, err := symmetric.NewCipherContext(key, cipher, mode, symmetric.PKCS7, nil, symmetric.WithWorkers(4))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFileEncryption(t *testing.T) {
	inputs, err := collectDemoInputs(inputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, input := range inputs {
		switch strings.ToLower(filepath.Ext(input)) {
		case ".mp4", ".m4v", ".mov", ".avi", ".mkv", ".webm", ".mpeg", ".mpg":

			continue
		}
		info, err := os.Stat(input)
		if err != nil {
			t.Fatal(err)
		}
		if testing.Short() && info.Size() > 1024*1024 {
			t.Logf("пропускаем крупный файл в коротком прогоне: %s", input)
			continue
		}
		paths = append(paths, input)
	}
	if len(paths) == 0 {
		t.Skip("нет подходящих файлов для проверки")
	}
	for _, algorithm := range []string{"DES", "DEAL"} {
		for _, mode := range []struct {
			name  string
			value symmetric.Mode
		}{
			{"ECB", symmetric.ECB}, {"CBC", symmetric.CBC},
			{"PCBC", symmetric.PCBC}, {"CFB", symmetric.CFB},
			{"OFB", symmetric.OFB}, {"CTR", symmetric.CTR},
			{"RandomDelta", symmetric.RandomDelta},
		} {
			t.Run(algorithm+"/"+mode.name, func(t *testing.T) {
				c := newEncryptionContext(t, algorithm, mode.value)
				dir := t.TempDir()
				for i, input := range paths {
					name := fmt.Sprintf("%02d-%s", i+1, filepath.Base(input))
					encrypted := filepath.Join(dir, name+".enc")
					restored := filepath.Join(dir, "restored-"+name)
					if err := <-c.EncryptFileAsync(input, encrypted, false); err != nil {
						t.Fatalf("encrypt %s: %v", input, err)
					}
					if err := <-c.DecryptFileAsync(encrypted, restored, false); err != nil {
						t.Fatalf("decrypt %s: %v", input, err)
					}
					if err := compareFiles(input, restored); err != nil {
						t.Fatalf("%s: %v", input, err)
					}
				}
			})
		}
	}
}

func TestLargeByteEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("large arrays")
	}
	for _, tt := range []struct {
		algorithm string
		size      int
	}{
		{"DES", 8*1024*1024 + 17},
		{"DEAL", 65536 + 37},
	} {
		t.Run(tt.algorithm, func(t *testing.T) {
			text := []byte("Большой текст: внутренние нули\x00 и произвольные байты\xff.\n")
			plain := bytes.Repeat(text, tt.size/len(text)+1)[:tt.size]
			plain[len(plain)-1] = 0
			c := newEncryptionContext(t, tt.algorithm, symmetric.CTR)
			encrypted := <-c.EncryptAsync(plain)
			if encrypted.Err != nil {
				t.Fatal(encrypted.Err)
			}
			restored := <-c.DecryptAsync(encrypted.Data)
			if restored.Err != nil || !bytes.Equal(restored.Data, plain) {
				t.Fatalf("restored %d bytes, want %d; error=%v", len(restored.Data), len(plain), restored.Err)
			}
		})
	}
}
