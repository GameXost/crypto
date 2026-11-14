package main

import "fmt"

func main() {
	values := []int{2, 3, 5}
	total := 0
	for _, value := range values {
		total += value
	}
	fmt.Println("Сумма:", total)
}
