package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"cryp/funcs"
	"cryp/symmetric"
)

const (
	inputDirectory  = "testdata/des-demo"
	outputDirectory = "des_demo"
)

func main() {
	// showByteExamples()
	//

	workers := 8
	inputs, err := collectDemoInputs(inputDirectory)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// if err := demonstratePermutation(os.Stdout); err != nil {
	// fmt.Fprintln(os.Stderr, err)
	// os.Exit(1)
	// }
	//
	if err := runDemo("DES", inputs, workers, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)

	}
}

func showByteExamples() error {
	cipher, key, err := newDemoCipher("DES")
	if err != nil {
		return err
	}

	ctx, err := symmetric.NewCipherContext(
		key, cipher,
		symmetric.ECB, symmetric.PKCS7,
		nil,
	)
	if err != nil {
		return err
	}

	blockSize := cipher.BlockSize()

	examples := []struct {
		name string
		data []byte
	}{
		{"Пустой массив", []byte{}},
		{"Один нулевой байт", []byte{0}},
		{"Только нули", make([]byte, blockSize)},
		{"Заданные биты", []byte{0b10110010, 0b01101100}},
		{"Меньше блока", bytes.Repeat([]byte{0xAB}, blockSize-1)},
		{"Ровно блок", bytes.Repeat([]byte{0xAB}, blockSize)},
		{"Больше блока", bytes.Repeat([]byte{0xAB}, blockSize+1)},
	}

	for _, example := range examples {
		encrypted := <-ctx.EncryptAsync(example.data)
		if encrypted.Err != nil {
			return encrypted.Err
		}

		restored := <-ctx.DecryptAsync(encrypted.Data)
		if restored.Err != nil {
			return restored.Err
		}

		if !bytes.Equal(example.data, restored.Data) {
			return fmt.Errorf("%s: данные не восстановились", example.name)
		}

		fmt.Printf(
			"%s\n  Вход:  %08b (%d байт)\n  Шифр: %x (%d байт)\n  Выход: %08b (%d байт)\n  OK\n\n",
			example.name,
			example.data, len(example.data),
			encrypted.Data, len(encrypted.Data),
			restored.Data, len(restored.Data),
		)
	}

	return nil
}

func collectDemoInputs(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read input directory %q: %w", directory, err)
	}
	var inputs []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", filepath.Join(directory, entry.Name()), err)
		}
		if info.Mode().IsRegular() {
			inputs = append(inputs, filepath.Join(directory, entry.Name()))
		}
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("input directory %q contains no regular files", directory)
	}
	return inputs, nil
}

func demonstratePermutation(stdout io.Writer) error {
	data := []byte{0b10110010, 0b01101100}
	rule := []int{0, 8, 1, 9, 2, 10, 3, 11}
	if err := writeReport(stdout, "Перестановка битов\nInput: %08b\nRule (base 0): %v\n", data, rule); err != nil {
		return err
	}
	for _, example := range []struct {
		name  string
		order funcs.BitOrder
	}{
		{"MSBFirst", funcs.MSBFirst},
		{"LSBFirst", funcs.LSBFirst},
	} {
		result, err := funcs.Permutate(data, rule, example.order, 0)
		if err != nil {
			return err
		}
		if err := writeReport(stdout, "%s: %08b\n", example.name, result); err != nil {
			return err
		}
	}
	return nil
}
