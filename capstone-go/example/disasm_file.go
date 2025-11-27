package main

import (
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	capstone "github.com/yourusername/capstone-go"
)

func main() {
	// Command line flags
	filePtr := flag.String("file", "", "Binary file to disassemble")
	addrPtr := flag.Uint64("addr", 0, "Start address (hex)")
	countPtr := flag.Int("count", 20, "Number of instructions (0 = all)")
	syntaxPtr := flag.String("syntax", "intel", "Syntax: intel or att")
	modePtr := flag.String("mode", "auto", "Mode: auto, 32, or 64")
	sectionPtr := flag.String("section", "", "Section name to disassemble (e.g., .text, __text)")
	
	flag.Parse()

	if *filePtr == "" {
		fmt.Println("Usage: disasm_file -file <binary> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  # Disassemble first 20 instructions from a binary")
		fmt.Println("  disasm_file -file /bin/ls")
		fmt.Println()
		fmt.Println("  # Disassemble .text section")
		fmt.Println("  disasm_file -file /bin/ls -section .text")
		fmt.Println()
		fmt.Println("  # Disassemble from specific address")
		fmt.Println("  disasm_file -file /bin/ls -addr 0x1000 -count 10")
		fmt.Println()
		fmt.Println("  # Use AT&T syntax")
		fmt.Println("  disasm_file -file /bin/ls -syntax att")
		os.Exit(1)
	}

	// Detect file format and extract code
	code, baseAddr, mode, err := extractCode(*filePtr, *sectionPtr, *addrPtr)
	if err != nil {
		log.Fatalf("Failed to extract code: %v", err)
	}

	// Override mode if specified
	if *modePtr == "32" {
		mode = capstone.Mode32
	} else if *modePtr == "64" {
		mode = capstone.Mode64
	}

	// Create disassembler
	engine, err := capstone.New(capstone.ArchX86, mode)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Set syntax
	if *syntaxPtr == "att" {
		engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxATT)
	} else {
		engine.SetOption(capstone.OptSyntax, capstone.OptSyntaxIntel)
	}

	// Disassemble
	fmt.Printf("Disassembling: %s\n", *filePtr)
	fmt.Printf("Mode: %d-bit, Syntax: %s\n", getModeSize(mode), *syntaxPtr)
	fmt.Printf("Base Address: 0x%x\n", baseAddr)
	fmt.Printf("Code Size: %d bytes\n\n", len(code))

	instructions, err := engine.Disasm(code, baseAddr, *countPtr)
	if err != nil {
		log.Fatalf("Failed to disassemble: %v", err)
	}

	// Print results
	fmt.Printf("%-16s %-12s %-8s %s\n", "Address", "Bytes", "Mnemonic", "Operands")
	fmt.Println(string(make([]byte, 70, 70)))
	for i := 0; i < 70; i++ {
		fmt.Print("-")
	}
	fmt.Println()

	for _, insn := range instructions {
		bytesStr := hex.EncodeToString(insn.Bytes)
		if len(bytesStr) > 20 {
			bytesStr = bytesStr[:20] + "..."
		}
		fmt.Printf("0x%-14x %-12s %-8s %s\n", 
			insn.Address, bytesStr, insn.Mnemonic, insn.OpStr)
	}

	fmt.Printf("\nTotal instructions: %d\n", len(instructions))
}

func extractCode(filename, sectionName string, startAddr uint64) ([]byte, uint64, capstone.Mode, error) {
	// Try ELF first
	if code, addr, mode, err := extractELF(filename, sectionName, startAddr); err == nil {
		return code, addr, mode, nil
	}

	// Try Mach-O
	if code, addr, mode, err := extractMachO(filename, sectionName, startAddr); err == nil {
		return code, addr, mode, nil
	}

	// Fallback: read as raw binary
	return extractRaw(filename, startAddr)
}

func extractELF(filename, sectionName string, startAddr uint64) ([]byte, uint64, capstone.Mode, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()

	// Determine mode
	mode := capstone.Mode32
	if f.Class == elf.ELFCLASS64 {
		mode = capstone.Mode64
	}

	// Find section
	var section *elf.Section
	if sectionName != "" {
		section = f.Section(sectionName)
	} else {
		// Default to .text
		section = f.Section(".text")
	}

	if section == nil {
		return nil, 0, 0, fmt.Errorf("section not found")
	}

	code, err := section.Data()
	if err != nil {
		return nil, 0, 0, err
	}

	addr := section.Addr
	if startAddr > 0 {
		addr = startAddr
	}

	return code, addr, mode, nil
}

func extractMachO(filename, sectionName string, startAddr uint64) ([]byte, uint64, capstone.Mode, error) {
	f, err := macho.Open(filename)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()

	// Determine mode
	mode := capstone.Mode32
	if f.Cpu == macho.CpuAmd64 || f.Cpu == macho.CpuArm64 {
		mode = capstone.Mode64
	}

	// Find section
	var section *macho.Section
	if sectionName != "" {
		section = f.Section(sectionName)
	} else {
		// Default to __text in __TEXT segment
		section = f.Section("__text")
	}

	if section == nil {
		return nil, 0, 0, fmt.Errorf("section not found")
	}

	code, err := section.Data()
	if err != nil {
		return nil, 0, 0, err
	}

	addr := section.Addr
	if startAddr > 0 {
		addr = startAddr
	}

	return code, addr, mode, nil
}

func extractRaw(filename string, startAddr uint64) ([]byte, uint64, capstone.Mode, error) {
	code, err := os.ReadFile(filename)
	if err != nil {
		return nil, 0, 0, err
	}

	addr := startAddr
	if addr == 0 {
		addr = 0x1000 // Default base address
	}

	// Assume 64-bit for raw files
	return code, addr, capstone.Mode64, nil
}

func getModeSize(mode capstone.Mode) int {
	switch mode {
	case capstone.Mode16:
		return 16
	case capstone.Mode32:
		return 32
	case capstone.Mode64:
		return 64
	default:
		return 0
	}
}
