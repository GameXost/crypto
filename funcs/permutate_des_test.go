package funcs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Tables are taken from FIPS PUB 46-3: IP, inverse IP, E, P, PC-1, PC-2.
// Expected values were calculated independently by selecting characters from
// a binary string using those tables, without calling Permutate or a DES library.
func TestPermutateDESTables(t *testing.T) {
	tests := []struct {
		name     string
		inputHex string
		wantHex  string
		rule     []int
	}{
		{
			name:     "IP", // FIPS PDF page 15.
			inputHex: "0123456789ABCDEF",
			wantHex:  "CC00CCFFF0AAF0AA",
			rule: []int{
				58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7,
			},
		},
		{
			name:     "IP inverse", // FIPS PDF page 15.
			inputHex: "CC00CCFFF0AAF0AA",
			wantHex:  "0123456789ABCDEF",
			rule: []int{
				40, 8, 48, 16, 56, 24, 64, 32,
				39, 7, 47, 15, 55, 23, 63, 31,
				38, 6, 46, 14, 54, 22, 62, 30,
				37, 5, 45, 13, 53, 21, 61, 29,
				36, 4, 44, 12, 52, 20, 60, 28,
				35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26,
				33, 1, 41, 9, 49, 17, 57, 25,
			},
		},
		{
			name:     "E", // FIPS PDF page 18.
			inputHex: "F0AAF0AA",
			wantHex:  "7A15557A1555",
			rule: []int{
				32, 1, 2, 3, 4, 5, 4, 5,
				6, 7, 8, 9, 8, 9, 10, 11,
				12, 13, 12, 13, 14, 15, 16, 17,
				16, 17, 18, 19, 20, 21, 20, 21,
				22, 23, 24, 25, 24, 25, 26, 27,
				28, 29, 28, 29, 30, 31, 32, 1,
			},
		},
		{
			name:     "P", // FIPS PDF page 20.
			inputHex: "5C82B597",
			wantHex:  "234AA9BB",
			rule: []int{
				16, 7, 20, 21, 29, 12, 28, 17,
				1, 15, 23, 26, 5, 18, 31, 10,
				2, 8, 24, 14, 32, 27, 3, 9,
				19, 13, 30, 6, 22, 11, 4, 25,
			},
		},
		{
			name:     "PC-1", // FIPS PDF page 24.
			inputHex: "133457799BBCDFF1",
			wantHex:  "F0CCAAF556678F",
			rule: []int{
				57, 49, 41, 33, 25, 17, 9, 1,
				58, 50, 42, 34, 26, 18, 10, 2,
				59, 51, 43, 35, 27, 19, 11, 3,
				60, 52, 44, 36, 63, 55, 47, 39,
				31, 23, 15, 7, 62, 54, 46, 38,
				30, 22, 14, 6, 61, 53, 45, 37,
				29, 21, 13, 5, 28, 20, 12, 4,
			},
		},
		{
			name:     "PC-2", // FIPS PDF page 26.
			inputHex: "E19955FAACCF1E",
			wantHex:  "1B02EFFC7072",
			rule: []int{
				14, 17, 11, 24, 1, 5, 3, 28,
				15, 6, 21, 10, 23, 19, 12, 4,
				26, 8, 16, 7, 27, 20, 13, 2,
				41, 52, 31, 37, 47, 55, 30, 40,
				51, 45, 33, 48, 44, 49, 39, 56,
				34, 53, 46, 42, 50, 36, 29, 32,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.inputHex)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tt.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			for _, numbering := range []struct {
				name  string
				order BitOrder
				base  int
			}{
				{"MSB_base_1_original_FIPS_table", MSBFirst, 1},
				{"MSB_base_0", MSBFirst, 0},
				{"LSB_base_1", LSBFirst, 1},
				{"LSB_base_0", LSBFirst, 0},
			} {
				t.Run(numbering.name, func(t *testing.T) {
					// Convert the standard's bit labels to the requested
					// numbering without changing which physical bits are selected.
					rule := make([]int, len(tt.rule))
					for i, position := range tt.rule {
						if numbering.order == MSBFirst {
							rule[i] = position - 1 + numbering.base
						} else {
							rule[i] = len(input)*8 - position + numbering.base
						}
					}
					got, err := Permutate(input, rule, numbering.order, numbering.base)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("got %X, want %X", got, want)
					}
				})
			}
		})
	}
}
