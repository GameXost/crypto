package funcs

import (
	"bytes"
	"slices"
	"testing"
)

func TestPermutate(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		rule  []int
		order BitOrder
		base  int
		want  []byte
	}{
		{
			name:  "MSB first, base zero",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			order: MSBFirst, base: 0,
			want: []byte{0b10110010, 0b01101100},
		},
		{
			name:  "MSB first, base one",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			order: MSBFirst, base: 1,
			want: []byte{0b10110010, 0b01101100},
		},
		{
			name:  "LSB first counts from the last byte, base zero",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			order: LSBFirst, base: 0,
			want: []byte{0b00110110, 0b01001101},
		},
		{
			name:  "LSB first counts from the last byte, base one",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			order: LSBFirst, base: 1,
			want: []byte{0b00110110, 0b01001101},
		},
		{
			name:  "reorder bits within one byte",
			data:  []byte{0b10110010},
			rule:  []int{2, 0, 1, 3, 4, 5, 6, 7},
			order: MSBFirst, base: 0,
			want: []byte{0b11010010},
		},
		{
			name:  "swap two bytes using bit positions",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7},
			order: MSBFirst, base: 0,
			want: []byte{0b01101100, 0b10110010},
		},
		{
			name:  "compress and interleave bits from different bytes",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{0, 8, 1, 9, 2, 10, 3, 11},
			order: MSBFirst, base: 0,
			want: []byte{0b10011110},
		},
		{
			name:  "nine bits need two bytes with zero unused bits",
			data:  []byte{0b10110010, 0b11111111},
			rule:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8},
			order: MSBFirst, base: 0,
			want: []byte{0b10110010, 0b10000000},
		},
		{
			name:  "expand by repeating source positions",
			data:  []byte{0b10100101},
			rule:  []int{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7},
			order: MSBFirst, base: 0,
			want: []byte{0b10100101, 0b10100101},
		},
		{
			name:  "LSB first also packs partial output from the MSB",
			data:  []byte{0b10110010, 0b01101100},
			rule:  []int{2, 8, 15},
			order: LSBFirst, base: 0,
			want: []byte{0b10100000},
		},
		{
			name:  "empty rule with nonempty input",
			data:  []byte{0xFF},
			rule:  nil,
			order: MSBFirst, base: 0,
			want: []byte{},
		},
		{
			name:  "nil input and rule",
			data:  nil,
			rule:  nil,
			order: MSBFirst, base: 0,
			want: []byte{},
		},
		{
			name:  "empty input and rule, LSB first, base one",
			data:  []byte{},
			rule:  []int{},
			order: LSBFirst, base: 1,
			want: []byte{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Permutate(tt.data, tt.rule, tt.order, tt.base)
			if err != nil {
				t.Fatalf("Permutate() returned an unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Permutate() = %08b, want %08b", got, tt.want)
			}
		})
	}
}

func TestPermutateInvalidInput(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	tests := []struct {
		name  string
		data  []byte
		rule  []int
		order BitOrder
		base  int
	}{
		{name: "negative order", data: []byte{0xFF}, rule: []int{0}, order: -1},
		{name: "unknown order", data: []byte{0xFF}, rule: []int{0}, order: 2},
		{name: "negative base", data: []byte{0xFF}, rule: []int{0}, base: -1},
		{name: "unsupported base", data: []byte{0xFF}, rule: []int{2}, base: 2},
		{name: "negative bit position", data: []byte{0xFF}, rule: []int{-1}},
		{name: "zero position with base one", data: []byte{0xFF}, rule: []int{0}, base: 1},
		{name: "position past input", data: []byte{0xFF}, rule: []int{8}},
		{name: "position past input with base one", data: []byte{0xFF}, rule: []int{9}, base: 1},
		{name: "LSB position past input", data: []byte{0xFF, 0xFF}, rule: []int{16}, order: LSBFirst},
		{name: "LSB negative position", data: []byte{0xFF, 0xFF}, rule: []int{-1}, order: LSBFirst},
		{name: "invalid position after valid ones", data: []byte{0xFF}, rule: []int{0, 1, 8}},
		{name: "nonempty rule with nil input", rule: []int{0}},
		{name: "nonempty rule with empty input and base one", data: []byte{}, rule: []int{1}, base: 1},
		{name: "invalid order with empty rule", order: -1},
		{name: "invalid base with empty rule", base: 2},
		{name: "maximum int position", data: []byte{0xFF}, rule: []int{maxInt}},
		{name: "minimum int position", data: []byte{0xFF}, rule: []int{minInt}},
		{name: "minimum int position with base one", data: []byte{0xFF}, rule: []int{minInt}, base: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Permutate(tt.data, tt.rule, tt.order, tt.base)
			if err == nil {
				t.Error("Permutate() returned no error for invalid input")
			}
			if got != nil {
				t.Errorf("Permutate() returned %08b for invalid input, want nil", got)
			}
		})
	}
}

func TestPermutateKeepsInputsAndReturnsIndependentResult(t *testing.T) {
	data := []byte{0b10110010, 0b01101100}
	rule := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	originalData := bytes.Clone(data)
	originalRule := slices.Clone(rule)

	got, err := Permutate(data, rule, MSBFirst, 1)
	if err != nil {
		t.Fatalf("Permutate() returned an unexpected error: %v", err)
	}
	if !bytes.Equal(data, originalData) {
		t.Fatal("Permutate() changed the input data")
	}
	if !slices.Equal(rule, originalRule) {
		t.Fatal("Permutate() changed the rule")
	}
	if !bytes.Equal(got, originalData) {
		t.Fatalf("Permutate() = %08b, want %08b", got, originalData)
	}

	// Changing the result must not change the caller's input slice.
	got[0] ^= 0xFF
	if !bytes.Equal(data, originalData) {
		t.Error("result shares memory with the input data")
	}
}
