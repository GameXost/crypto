package main

import "fmt"

// Исходник для проверки шифрования файлов.
func main() {
	values := []int{2, 3, 5}
	total := 0
	for _, value := range values {
		total += value
	}
	fmt.Println("Сумма:", total)
}
