package main

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"

	"cryp/block"
	"cryp/symmetric"
)

type namedMode struct {
	name string
	mode symmetric.Mode
}

var demoModes = []namedMode{
	{"ECB", symmetric.ECB},
	{"CBC", symmetric.CBC},
	{"PCBC", symmetric.PCBC},
	{"CFB", symmetric.CFB},
	{"OFB", symmetric.OFB},
	{"CTR", symmetric.CTR},
	{"RandomDelta", symmetric.RandomDelta},
}

func newDemoCipher(name string) (block.BlockCipher, []byte, error) {
	switch name {
	case "DES":
		cipher, err := block.NewDES()
		return cipher, []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1}, err
	case "DEAL":
		cipher, err := block.NewDEAL()
		return cipher, []byte("0123456789abcdef"), err
	default:
		return nil, nil, fmt.Errorf("unknown cipher %q: use DES or DEAL", name)
	}
}

func demonstrate(cipher block.BlockCipher, key []byte, inputs []string, output string, workers int, stdout io.Writer) error {
	random := rand.New(rand.NewSource(1))
	data := make([]byte, 4099)
	for i := range data {
		data[i] = byte(random.Intn(256))
	}
	for _, mode := range demoModes {
		c, err := symmetric.NewCipherContext(key, cipher, mode.mode, symmetric.PKCS7, nil, symmetric.WithWorkers(workers))
		if err != nil {
			return err
		}
		if err := demonstrateMode(c, mode, inputs, data, output, stdout); err != nil {
			return fmt.Errorf("%s: %w", mode.name, err)
		}
	}
	return writeReport(stdout, "Проверено: %d массивов байтов, %d файлов. Все восстановлены без изменений.\n", len(demoModes), len(demoModes)*len(inputs))
}

func demonstrateMode(c *symmetric.CipherContext, mode namedMode, inputs []string, data []byte, output string, stdout io.Writer) error {
	if err := demoBytes(c, data); err != nil {
		return err
	}
	if err := writeReport(stdout, "%s | массив | %d байт | OK\n", mode.name, len(data)); err != nil {
		return err
	}
	directory := filepath.Join(output, mode.name)
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	return demonstrateFiles(c, mode.name, inputs, directory, stdout)
}

func demonstrateFiles(c *symmetric.CipherContext, mode string, inputs []string, directory string, stdout io.Writer) error {
	for i, input := range inputs {
		name := fmt.Sprintf("%02d-%s", i+1, filepath.Base(input))
		encrypted := filepath.Join(directory, name+".enc")
		restored := filepath.Join(directory, "restored-"+name)
		if err := demoFile(c, input, encrypted, restored); err != nil {
			return fmt.Errorf("file %q: %w", input, err)
		}
		info, err := os.Stat(input)
		if err != nil {
			return err
		}
		if err := writeReport(stdout, "%s | %s | %d байт | OK\n", mode, input, info.Size()); err != nil {
			return err
		}
	}
	return nil
}

func demoBytes(c *symmetric.CipherContext, data []byte) error {
	encrypted := <-c.EncryptAsync(data)
	if encrypted.Err != nil {
		return fmt.Errorf("encrypt bytes: %w", encrypted.Err)
	}
	decrypted := <-c.DecryptAsync(encrypted.Data)
	if decrypted.Err != nil {
		return fmt.Errorf("decrypt bytes: %w", decrypted.Err)
	}
	if !bytes.Equal(data, decrypted.Data) {
		return fmt.Errorf("restored bytes differ from input")
	}
	return nil
}

func demoFile(c *symmetric.CipherContext, input, encrypted, restored string) error {
	if err := <-c.EncryptFileAsync(input, encrypted, false); err != nil {
		return fmt.Errorf("encrypt file: %w", err)
	}
	if err := <-c.DecryptFileAsync(encrypted, restored, false); err != nil {
		return fmt.Errorf("decrypt file: %w", err)
	}
	return compareFiles(input, restored)
}
