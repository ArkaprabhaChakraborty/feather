package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	// Create a simple C program
	cCode := `
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main() {
    int x = 5;
    int y = 10;
    int sum = add(x, y);
    int product = multiply(x, y);
    printf("Sum: %d, Product: %d\n", sum, product);
    return 0;
}
`

	// Write C code to file
	if err := os.WriteFile("test_program.c", []byte(cCode), 0644); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Created test_program.c")

	// Compile it
	cmd := exec.Command("gcc", "-o", "test_program", "test_program.c")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to compile: %v\nMake sure gcc is installed", err)
	}

	fmt.Println("Compiled test_program")
	fmt.Println("\nNow you can disassemble it:")
	fmt.Println("  go run disasm_file.go -file test_program")
	fmt.Println("  go run disasm_file.go -file test_program -section __text")
	fmt.Println("  go run disasm_file.go -file test_program -count 50")
	fmt.Println("\nOr use system tools:")
	fmt.Println("  objdump -d test_program")
	fmt.Println("  otool -tV test_program  (macOS)")
}
