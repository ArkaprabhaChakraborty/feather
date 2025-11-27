package main

import (
	"fmt"
	"log"

	capstone "github.com/yourusername/capstone-go"
)

func main() {
	// Print Capstone version
	major, minor := capstone.Version()
	fmt.Printf("Capstone version: %d.%d\n\n", major, minor)

	// Example 1: 64-bit disassembly
	fmt.Println("=== x86-64 Disassembly (Intel Syntax) ===")
	disasm64()

	// Example 2: 32-bit disassembly
	fmt.Println("\n=== x86-32 Disassembly (Intel Syntax) ===")
	disasm32()

	// Example 3: AT&T syntax
	fmt.Println("\n=== x86-64 Disassembly (AT&T Syntax) ===")
	disasmATT()

	// Example 4: Complex code
	fmt.Println("\n=== Complex x86-64 Code ===")
	disasmComplex()
}

func disasm64() {
	engine, err := capstone.New(capstone.ArchX86, capstone.Mode64)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxIntel)

	// Function prologue and epilogue
	code := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x5d,             // pop rbp
		0xc3,             // ret
	}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		log.Fatal(err)
	}

	for _, insn := range instructions {
		fmt.Printf("0x%x:\t%-8s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func disasm32() {
	engine, err := capstone.New(capstone.ArchX86, capstone.Mode32)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxIntel)

	// 32-bit function prologue and epilogue
	code := []byte{
		0x55,       // push ebp
		0x89, 0xe5, // mov ebp, esp
		0x5d,       // pop ebp
		0xc3,       // ret
	}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		log.Fatal(err)
	}

	for _, insn := range instructions {
		fmt.Printf("0x%x:\t%-8s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func disasmATT() {
	engine, err := capstone.New(capstone.ArchX86, capstone.Mode64)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxATT)

	code := []byte{
		0x55,             // push %rbp
		0x48, 0x89, 0xe5, // mov %rsp, %rbp
		0x5d,             // pop %rbp
		0xc3,             // ret
	}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		log.Fatal(err)
	}

	for _, insn := range instructions {
		fmt.Printf("0x%x:\t%-8s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func disasmComplex() {
	engine, err := capstone.New(capstone.ArchX86, capstone.Mode64)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxIntel)

	// More complex code with various instruction types
	code := []byte{
		0x55,                         // push rbp
		0x48, 0x89, 0xe5,             // mov rbp, rsp
		0x48, 0x83, 0xec, 0x10,       // sub rsp, 0x10
		0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00, // mov rax, [rip+0x13b8]
		0x48, 0x89, 0x45, 0xf8,       // mov [rbp-8], rax
		0x48, 0x8b, 0x45, 0xf8,       // mov rax, [rbp-8]
		0x48, 0x83, 0xc4, 0x10,       // add rsp, 0x10
		0x5d,                         // pop rbp
		0xc3,                         // ret
	}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		log.Fatal(err)
	}

	for _, insn := range instructions {
		fmt.Printf("0x%x:\t%-8s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}
