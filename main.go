package main

import (
	"fmt"
	"log"

	"cryp/funcs"
)

func main() {
	data := []byte{0b10110010, 0b01101100}
	rule := []int{0, 8, 1, 9, 2, 10, 3, 11}

	fmt.Printf("Input: %08b\nRule (base 0): %v\n", data, rule)
	for _, example := range []struct {
		name  string
		order funcs.BitOrder
	}{
		{"MSBFirst", funcs.MSBFirst},
		{"LSBFirst", funcs.LSBFirst},
	} {
		result, err := funcs.Permutate(data, rule, example.order, 0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %08b\n", example.name, result)
	}
}
