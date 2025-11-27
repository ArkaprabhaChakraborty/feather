package main

import (
	"fmt"
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

	// Write C code
	if err := os.WriteFile("test_program.c", []byte(cCode), 0644); err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Println("✓ Created test_program.c")

	// Compile for x86-64
	cmd := exec.Command("gcc", "-arch", "x86_64", "-o", "test_program_x86", "test_program.c")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error compiling: %v\n", err)
		fmt.Println("Note: x86_64 compilation may not be available on ARM Macs")
		return
	}

	fmt.Println("✓ Compiled test_program_x86")
	fmt.Println("\nNow you can disassemble it:")
	fmt.Println("  cd disasm && go run main.go -file ../test_program_x86 -section __text")
	fmt.Println("  cd disasm && go run main.go -file ../test_program_x86 -section __text -detail")
	fmt.Println("  cd disasm && go run main.go -file ../test_program_x86 -section __text -syntax att")
}
