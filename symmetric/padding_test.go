package symmetric

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPaddingPad(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		blockSize    int
		zerosCount   int
		countedCount int
	}{
		{"empty", nil, 8, 0, 8},
		{"one_byte", []byte{0x41}, 8, 7, 7},
		{"aligned", []byte{1, 2, 3, 4, 5, 6, 0, 0}, 8, 0, 8},
		{"49_bytes", bytes.Repeat([]byte{0x41}, 49), 8, 7, 7},
		{"block_one_empty", nil, 1, 0, 1},
		{"block_one_aligned", []byte{0x41}, 1, 0, 1},
		{"block_255_partial", []byte{0x41}, 255, 254, 254},
		{"block_255_aligned", bytes.Repeat([]byte{0x41}, 255), 255, 0, 255},
	}
	for _, tt := range tests {
		for _, padding := range []Padding{Zeros, ANSIX923, PKCS7, ISO10126} {
			t.Run(fmt.Sprintf("%s/padding_%d", tt.name, padding), func(t *testing.T) {
				original := bytes.Clone(tt.data)
				got, err := padding.Pad(tt.data, tt.blockSize)
				if err != nil {
					t.Fatal(err)
				}
				count := tt.countedCount
				if padding == Zeros {
					count = tt.zerosCount
				}
				if len(got) != len(tt.data)+count {
					t.Fatalf("length = %d, want %d", len(got), len(tt.data)+count)
				}
				if !bytes.Equal(got[:len(tt.data)], original) || !bytes.Equal(tt.data, original) {
					t.Fatal("input bytes changed")
				}
				tail := got[len(tt.data):]
				switch padding {
				case Zeros:
					if !bytes.Equal(tail, make([]byte, count)) {
						t.Fatalf("zero padding = %X", tail)
					}
				case ANSIX923:
					if tail[count-1] != byte(count) || !bytes.Equal(tail[:count-1], make([]byte, count-1)) {
						t.Fatalf("ANSI X9.23 padding = %X", tail)
					}
				case PKCS7:
					if !bytes.Equal(tail, bytes.Repeat([]byte{byte(count)}, count)) {
						t.Fatalf("PKCS7 padding = %X", tail)
					}
				case ISO10126:
					if tail[count-1] != byte(count) {
						t.Fatalf("ISO10126 length byte = %d, want %d", tail[count-1], count)
					}
				}
			})
		}
	}
}

func TestPaddingUnPad(t *testing.T) {
	ansi255 := make([]byte, 255)
	ansi255[254] = 255
	iso255 := bytes.Repeat([]byte{0xA5}, 255)
	iso255[254] = 255
	tests := []struct {
		name      string
		padding   Padding
		data      []byte
		blockSize int
		want      []byte
	}{
		{"zeros_empty", Zeros, nil, 8, nil},
		{"zeros_partial", Zeros, []byte{0x41, 0, 0, 0, 0, 0, 0, 0}, 8, []byte{0x41}},
		{"zeros_aligned", Zeros, []byte{1, 2, 3, 4, 5, 6, 0, 0}, 8, []byte{1, 2, 3, 4, 5, 6}},
		{"zeros_all_zero_block", Zeros, make([]byte, 8), 8, nil},
		{"zeros_all_zero_blocks", Zeros, make([]byte, 16), 8, nil},
		{"zeros_no_trailing_zero", Zeros, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"zeros_internal_zero", Zeros, []byte{0x41, 0, 0x42, 0, 0, 0, 0, 0}, 8, []byte{0x41, 0, 0x42}},
		{"zeros_tail_spans_blocks", Zeros, append([]byte{0x41}, make([]byte, 15)...), 8, []byte{0x41}},
		{"ansi_partial", ANSIX923, []byte{0x41, 0, 0, 0, 0, 0, 0, 7}, 8, []byte{0x41}},
		{"pkcs_partial", PKCS7, []byte{0x41, 7, 7, 7, 7, 7, 7, 7}, 8, []byte{0x41}},
		{"iso_partial", ISO10126, []byte{0x41, 0, 255, 3, 9, 0, 6, 7}, 8, []byte{0x41}},
		{"ansi_empty", ANSIX923, []byte{0, 0, 0, 0, 0, 0, 0, 8}, 8, nil},
		{"pkcs_empty", PKCS7, bytes.Repeat([]byte{8}, 8), 8, nil},
		{"iso_empty", ISO10126, []byte{1, 2, 3, 4, 5, 6, 7, 8}, 8, nil},
		{"ansi_aligned", ANSIX923, []byte{1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}, 8, []byte{1, 2, 3, 4, 5, 6, 0, 0}},
		{"pkcs_aligned", PKCS7, []byte{1, 2, 3, 4, 5, 6, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8}, 8, []byte{1, 2, 3, 4, 5, 6, 0, 0}},
		{"iso_aligned", ISO10126, []byte{1, 2, 3, 4, 5, 6, 0, 0, 9, 0, 255, 4, 3, 7, 1, 8}, 8, []byte{1, 2, 3, 4, 5, 6, 0, 0}},
		{"zeros_block_one", Zeros, []byte{0x41}, 1, []byte{0x41}},
		{"ansi_block_one", ANSIX923, []byte{0x41, 1}, 1, []byte{0x41}},
		{"pkcs_block_one", PKCS7, []byte{1}, 1, nil},
		{"iso_block_one", ISO10126, []byte{0x41, 1}, 1, []byte{0x41}},
		{"zeros_block_255", Zeros, append([]byte{0x41}, make([]byte, 254)...), 255, []byte{0x41}},
		{"ansi_block_255", ANSIX923, ansi255, 255, nil},
		{"pkcs_block_255", PKCS7, bytes.Repeat([]byte{255}, 255), 255, nil},
		{"iso_block_255", ISO10126, iso255, 255, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := bytes.Clone(tt.data)
			got, err := tt.padding.UnPad(tt.data, tt.blockSize)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("UnPad() = %X, want %X", got, tt.want)
			}
			if !bytes.Equal(tt.data, original) {
				t.Fatal("UnPad changed input")
			}
			if len(got) > 0 {
				got[0] ^= 0xFF
				if !bytes.Equal(tt.data, original) {
					t.Fatal("result shares memory with input")
				}
			}
		})
	}
}

func TestPaddingRejectsInvalidConfiguration(t *testing.T) {
	for _, padding := range []Padding{Zeros, ANSIX923, PKCS7, ISO10126, Padding(4), Padding(255)} {
		for _, blockSize := range []int{-1, 0, 256, 8} {
			if blockSize == 8 && padding <= ISO10126 {
				continue
			}
			t.Run(fmt.Sprintf("padding_%d/block_%d", padding, blockSize), func(t *testing.T) {
				data := []byte{0x41}
				if got, err := padding.Pad(data, blockSize); err == nil || got != nil {
					t.Fatalf("Pad() = %X, %v; want nil, error", got, err)
				}
				padded := []byte{0x41, 0, 0, 0, 0, 0, 0, 1}
				originalPadded := bytes.Clone(padded)
				if got, err := padding.UnPad(padded, blockSize); err == nil || got != nil {
					t.Fatalf("UnPad() = %X, %v; want nil, error", got, err)
				}
				if !bytes.Equal(data, []byte{0x41}) || !bytes.Equal(padded, originalPadded) {
					t.Fatal("invalid operation changed input")
				}
			})
		}
	}
}

func TestPaddingUnPadRejectsMalformedData(t *testing.T) {
	tests := []struct {
		name    string
		padding Padding
		data    []byte
	}{
		{"zeros_unaligned", Zeros, []byte{0}},
		{"ansi_unaligned", ANSIX923, []byte{1}},
		{"pkcs_unaligned", PKCS7, []byte{1}},
		{"iso_unaligned", ISO10126, []byte{1}},
		{"ansi_empty", ANSIX923, nil},
		{"pkcs_empty", PKCS7, nil},
		{"iso_empty", ISO10126, nil},
		{"ansi_zero_count", ANSIX923, make([]byte, 8)},
		{"pkcs_zero_count", PKCS7, make([]byte, 8)},
		{"iso_zero_count", ISO10126, make([]byte, 8)},
		{"ansi_large_count", ANSIX923, []byte{0, 0, 0, 0, 0, 0, 0, 9}},
		{"pkcs_large_count", PKCS7, bytes.Repeat([]byte{9}, 8)},
		{"iso_large_count", ISO10126, []byte{0, 0, 0, 0, 0, 0, 0, 9}},
		{"ansi_nonzero_tail", ANSIX923, []byte{1, 2, 3, 4, 5, 6, 1, 2}},
		{"pkcs_inconsistent_tail", PKCS7, []byte{1, 2, 3, 4, 5, 6, 0, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := bytes.Clone(tt.data)
			got, err := tt.padding.UnPad(tt.data, 8)
			if err == nil || got != nil {
				t.Fatalf("UnPad() = %X, %v; want nil, error", got, err)
			}
			if !bytes.Equal(tt.data, original) {
				t.Fatal("failed UnPad changed input")
			}
		})
	}
}
