package symmetric

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (c *CipherContext) EncryptFile(inputPath, outputPath string, overwrite bool) error {
	return c.transformFile(inputPath, outputPath, overwrite, false)
}

func (c *CipherContext) DecryptFile(inputPath, outputPath string, overwrite bool) error {
	return c.transformFile(inputPath, outputPath, overwrite, true)
}

func (c *CipherContext) transformFile(inputPath, outputPath string, overwrite, decrypt bool) (err error) {
	if c == nil || c.cipher == nil {
		return fmt.Errorf("cipher context is not initialized")
	}
	input, info, err := openRegularInput(inputPath)
	if err != nil {
		return err
	}
	if err := checkFileOutput(outputPath, info, overwrite); err != nil {
		return errors.Join(err, input.Close())
	}
	output, err := os.CreateTemp(filepath.Dir(outputPath), ".cryp-*")
	if err != nil {
		return errors.Join(err, input.Close())
	}
	defer func() {
		err = errors.Join(err, removeTempFile(output.Name()))
	}()
	if err := c.writeFileContent(input, output, decrypt); err != nil {
		return err
	}
	if err := checkFileOutput(outputPath, info, overwrite); err != nil {
		return err
	}
	return publishFile(output.Name(), outputPath, overwrite)
}

func openRegularInput(path string) (*os.File, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("input must be a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err = file.Stat()
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.Join(fmt.Errorf("input must be a regular file: %s", path), file.Close())
	}
	return file, info, nil
}

func checkFileOutput(path string, inputInfo os.FileInfo, overwrite bool) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("output must be a regular file: %s", path)
	}
	if os.SameFile(inputInfo, info) {
		return fmt.Errorf("input and output refer to the same file")
	}
	if !overwrite {
		return fmt.Errorf("output %s: %w", path, os.ErrExist)
	}
	return nil
}

func (c *CipherContext) writeFileContent(input, output *os.File, decrypt bool) (err error) {
	defer func() {
		err = errors.Join(err, input.Close(), output.Close())
	}()
	if err := c.transformStream(input, output, decrypt); err != nil {
		return err
	}
	return output.Sync()
}

func publishFile(temporary, destination string, overwrite bool) error {
	if overwrite {
		return os.Rename(temporary, destination)
	}
	return os.Link(temporary, destination)
}

func removeTempFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
