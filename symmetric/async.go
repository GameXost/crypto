package symmetric

import "bytes"

type Result struct {
	Data []byte
	Err  error
}

func (c *CipherContext) EncryptAsync(data []byte) <-chan Result {
	return asyncBytes(data, c.Encrypt)
}

func (c *CipherContext) DecryptAsync(data []byte) <-chan Result {
	return asyncBytes(data, c.Decrypt)
}

func (c *CipherContext) EncryptFileAsync(inputPath, outputPath string, overwrite bool) <-chan error {
	return runAsync(func() error { return c.EncryptFile(inputPath, outputPath, overwrite) })
}

func (c *CipherContext) DecryptFileAsync(inputPath, outputPath string, overwrite bool) <-chan error {
	return runAsync(func() error { return c.DecryptFile(inputPath, outputPath, overwrite) })
}

func asyncBytes(data []byte, transform func([]byte) ([]byte, error)) <-chan Result {
	snapshot := bytes.Clone(data)
	return runAsync(func() Result {
		data, err := transform(snapshot)
		return Result{Data: data, Err: err}
	})
}

func runAsync[T any](operation func() T) <-chan T {
	result := make(chan T, 1)
	go func() {
		defer close(result)
		result <- operation()
	}()
	return result
}
