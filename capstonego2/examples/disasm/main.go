package main

import (
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	cs "github.com/yourusername/capstonego2"
)

func main() {
	// Parse command line flags
	filePtr := flag.String("file", "", "Binary file to disassemble")
	addrPtr := flag.Uint64("addr", 0, "Start address (hex)")
	countPtr := flag.Uint("count", 20, "Number of instructions (0 = all)")
	syntaxPtr := flag.String("syntax", "intel", "Syntax: intel or att")
	modePtr := flag.String("mode", "auto", "Mode: auto, 32, or 64")
	sectionPtr := flag.String("section", "", "Section name (e.g., .text, __text)")
	detailPtr := flag.Bool("detail", false, "Show detailed instruction information")
	
	flag.Parse()

	if *filePtr == "" {
		fmt.Println("capstonego2 disassembler")
		fmt.Println("\nUsage: disasm -file <binary> [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  disasm -file /bin/ls")
		fmt.Println("  disasm -file /bin/ls -section __text -count 30")
		fmt.Println("  disasm -file test.bin -syntax att -detail")
		os.Exit(1)
	}

	// Extract code from binary
	code, baseAddr, mode, err := extractCode(*filePtr, *sectionPtr, *addrPtr)
	if err != nil {
		log.Fatalf("Failed to extract code: %v", err)
	}

	// Override mode if specified
	if *modePtr == "32" {
		mode = cs.Mode32
	} else if *modePtr == "64" {
		mode = cs.Mode64
	}

	// Create engine
	engine, err := cs.New(cs.ArchX86, mode)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Set syntax
	if *syntaxPtr == "att" {
		engine.SetOption(cs.OptSyntax, cs.OptSyntaxATT)
	} else {
		engine.SetOption(cs.OptSyntax, cs.OptSyntaxIntel)
	}

	// Enable detail mode if requested
	if *detailPtr {
		engine.SetOption(cs.OptDetail, cs.OptOn)
	}

	// Print header
	fmt.Printf("Disassembling: %s\n", *filePtr)
	fmt.Printf("Mode: %d-bit, Syntax: %s\n", getModeSize(mode), *syntaxPtr)
	fmt.Printf("Base Address: 0x%x\n", baseAddr)
	fmt.Printf("Code Size: %d bytes\n\n", len(code))

	// Disassemble
	instructions, err := engine.Disasm(code, baseAddr, *countPtr)
	if err != nil {
		log.Fatalf("Failed to disassemble: %v", err)
	}

	// Print results
	printInstructions(instructions, *detailPtr)
	
	fmt.Printf("\nTotal instructions: %d\n", len(instructions))
}

func printInstructions(insns []cs.Instruction, detail bool) {
	fmt.Printf("%-16s %-20s %-10s %s\n", "Address", "Bytes", "Mnemonic", "Operands")
	for i := 0; i < 80; i++ {
		fmt.Print("-")
	}
	fmt.Println()

	for _, insn := range insns {
		// Format bytes
		bytesStr := hex.EncodeToString(insn.Bytes)
		if len(bytesStr) > 20 {
			bytesStr = bytesStr[:20] + "..."
		}

		fmt.Printf("0x%-14x %-20s %-10s %s\n",
			insn.Address, bytesStr, insn.Mnemonic, insn.OpStr)

		// Print detailed information if requested
		if detail && insn.X86 != nil {
			printX86Details(insn.X86)
		}
	}
}

func printX86Details(x86 *cs.X86Instruction) {
	fmt.Printf("  Prefix: %02x %02x %02x %02x\n",
		x86.Prefix[0], x86.Prefix[1], x86.Prefix[2], x86.Prefix[3])
	fmt.Printf("  Opcode: %02x %02x %02x %02x\n",
		x86.Opcode[0], x86.Opcode[1], x86.Opcode[2], x86.Opcode[3])
	
	if len(x86.Operands) > 0 {
		fmt.Printf("  Operands (%d):\n", len(x86.Operands))
		for i, op := range x86.Operands {
			fmt.Printf("    [%d] Type: %d, Size: %d\n", i, op.Type, op.Size)
			switch op.Type {
			case cs.X86_OP_REG:
				fmt.Printf("        Register: %d\n", op.Reg)
			case cs.X86_OP_IMM:
				fmt.Printf("        Immediate: 0x%x\n", op.Imm)
			case cs.X86_OP_MEM:
				fmt.Printf("        Memory: [base=%d, index=%d, scale=%d, disp=0x%x]\n",
					op.Mem.Base, op.Mem.Index, op.Mem.Scale, op.Mem.Disp)
			}
		}
	}
	fmt.Println()
}

func extractCode(filename, sectionName string, startAddr uint64) ([]byte, uint64, cs.Mode, error) {
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

func extractELF(filename, sectionName string, startAddr uint64) ([]byte, uint64, cs.Mode, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()

	// Determine mode
	mode := cs.Mode32
	if f.Class == elf.ELFCLASS64 {
		mode = cs.Mode64
	}

	// Find section
	var section *elf.Section
	if sectionName != "" {
		section = f.Section(sectionName)
	} else {
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

func extractMachO(filename, sectionName string, startAddr uint64) ([]byte, uint64, cs.Mode, error) {
	f, err := macho.Open(filename)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()

	// Determine mode
	mode := cs.Mode32
	if f.Cpu == macho.CpuAmd64 {
		mode = cs.Mode64
	}

	// Find section
	var section *macho.Section
	if sectionName != "" {
		section = f.Section(sectionName)
	} else {
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

func extractRaw(filename string, startAddr uint64) ([]byte, uint64, cs.Mode, error) {
	code, err := os.ReadFile(filename)
	if err != nil {
		return nil, 0, 0, err
	}

	addr := startAddr
	if addr == 0 {
		addr = 0x1000
	}

	return code, addr, cs.Mode64, nil
}

func getModeSize(mode cs.Mode) int {
	switch mode {
	case cs.Mode16:
		return 16
	case cs.Mode32:
		return 32
	case cs.Mode64:
		return 64
	default:
		return 0
	}
}
