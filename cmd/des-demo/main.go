package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("des-demo", flag.ContinueOnError)
	var diagnostics bytes.Buffer
	flags.SetOutput(&diagnostics)
	requestedCipher := flags.String("cipher", "DES", "DES или DEAL (128-битный ключ)")
	workers := flags.Int("workers", 4, "число воркеров")
	requestedOutput := flags.String("out", "", "новый каталог результатов; по умолчанию временный")
	if err := flags.Parse(args); err != nil {
		if writeErr := writeReport(stdout, "%s", diagnostics.String()); writeErr != nil {
			return writeErr
		}
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *workers < 1 {
		return fmt.Errorf("workers must be positive")
	}
	name := strings.ToUpper(*requestedCipher)
	cipher, key, err := newDemoCipher(name)
	if err != nil {
		return err
	}
	inputs, err := validateInputs(flags.Args())
	if err != nil {
		return err
	}
	output, err := createOutputDirectory(*requestedOutput)
	if err != nil {
		return err
	}
	if err := writeReport(stdout, "%s | PKCS7 | workers=%d\nРезультаты: %s\n", name, *workers, output); err != nil {
		return err
	}
	return demonstrate(cipher, key, inputs, output, *workers, stdout)
}

func validateInputs(paths []string) ([]string, error) {
	if len(paths) == 0 {
		paths = []string{
			"testdata/des-demo/message.txt",
			"testdata/des-demo/source.go",
			"testdata/des-demo/image.png",
			"testdata/des-demo/tone.wav",
			"testdata/des-demo/clip.avi",
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("input %q must be a regular file", path)
		}
	}
	return paths, nil
}

func createOutputDirectory(path string) (string, error) {
	var err error
	if path == "" {
		path, err = os.MkdirTemp("", "cryp-des-demo-")
	} else {
		err = os.Mkdir(path, 0700)
	}
	if err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	return filepath.Abs(path)
}

func writeReport(output io.Writer, format string, args ...any) error {
	text := fmt.Sprintf(format, args...)
	n, err := io.WriteString(output, text)
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if n != len(text) {
		return io.ErrShortWrite
	}
	return nil
}
