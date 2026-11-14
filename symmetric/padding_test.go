package symmetric

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPaddingFormatAndRoundTrip(t *testing.T) {
	for _, padding := range testPaddings {
		for _, tt := range []struct{ size, length int }{
			{8, 0}, {8, 1}, {8, 7}, {8, 8}, {8, 9},
			{16, 0}, {16, 15}, {16, 16}, {16, 17},
			{1, 0}, {1, 1}, {255, 1}, {255, 255},
		} {
			t.Run(fmt.Sprintf("padding_%d/block_%d/length_%d", padding, tt.size, tt.length), func(t *testing.T) {
				plain := bytes.Repeat([]byte{0x41}, tt.length)
				got, err := padding.Pad(plain, tt.size)
				if err != nil {
					t.Fatal(err)
				}
				count := tt.size - tt.length%tt.size
				if padding == Zeros && count == tt.size {
					count = 0
				}
				if len(got) != tt.length+count || !bytes.Equal(got[:tt.length], plain) {
					t.Fatal("wrong length or plaintext prefix")
				}
				tail := got[tt.length:]
				switch padding {
				case Zeros:
					if !bytes.Equal(tail, make([]byte, count)) {
						t.Fatalf("Zeros = %x", tail)
					}
				case ANSIX923:
					if tail[count-1] != byte(count) || !bytes.Equal(tail[:count-1], make([]byte, count-1)) {
						t.Fatalf("ANSI X9.23 = %x", tail)
					}
				case PKCS7:
					if !bytes.Equal(tail, bytes.Repeat([]byte{byte(count)}, count)) {
						t.Fatalf("PKCS7 = %x", tail)
					}
				case ISO10126:
					if tail[count-1] != byte(count) {
						t.Fatalf("ISO10126 length = %d", tail[count-1])
					}
				}
				decoded, err := padding.UnPad(got, tt.size)
				if err != nil || !bytes.Equal(decoded, plain) {
					t.Fatalf("UnPad = %x, %v; want %x", decoded, err, plain)
				}
			})
		}
	}

	for _, tt := range []struct{ data, want []byte }{
		{make([]byte, 16), nil},
		{append([]byte{'A', 0, 'B'}, make([]byte, 21)...), []byte{'A', 0, 'B'}},
	} {
		got, err := Zeros.UnPad(tt.data, 8)
		if err != nil || !bytes.Equal(got, tt.want) {
			t.Fatalf("zero tail = %x, %v; want %x", got, err, tt.want)
		}
	}
	if got, err := ISO10126.UnPad([]byte{'A', 0, 255, 3, 9, 0, 6, 7}, 8); err != nil || !bytes.Equal(got, []byte{'A'}) {
		t.Fatalf("ISO10126 arbitrary fill = %x, %v", got, err)
	}
}

func TestPaddingRejectsMalformedData(t *testing.T) {
	for _, padding := range testPaddings {
		t.Run(fmt.Sprint(padding), func(t *testing.T) {
			invalid := [][]byte{{1}}
			if padding != Zeros {
				invalid = append(invalid, nil, make([]byte, 8), []byte{0, 0, 0, 0, 0, 0, 0, 9})
			}
			switch padding {
			case ANSIX923:
				invalid = append(invalid, []byte{1, 2, 3, 4, 5, 6, 1, 2})
			case PKCS7:
				invalid = append(invalid, []byte{1, 2, 3, 4, 5, 6, 0, 2})
			}
			for _, data := range invalid {
				if _, err := padding.UnPad(data, 8); err == nil {
					t.Fatalf("UnPad(%x) accepted", data)
				}
			}
		})
	}
}
