package capstone

import (
	"testing"
)

func TestVersion(t *testing.T) {
	major, minor := Version()
	if major == 0 && minor == 0 {
		t.Error("Version returned 0.0")
	}
	t.Logf("Capstone version: %d.%d", major, minor)
}

func TestNewEngine(t *testing.T) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()
}

func TestDisasm64(t *testing.T) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	err = engine.SetOption(OptSyntax, OptSyntaxIntel)
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	// push rbp; mov rbp, rsp; pop rbp; ret
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}

	if len(instructions) != 4 {
		t.Errorf("Expected 4 instructions, got %d", len(instructions))
	}

	expected := []string{"push", "mov", "pop", "ret"}
	for i, insn := range instructions {
		if insn.Mnemonic != expected[i] {
			t.Errorf("Instruction %d: expected %s, got %s", i, expected[i], insn.Mnemonic)
		}
		t.Logf("0x%x: %s %s", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func TestDisasm32(t *testing.T) {
	engine, err := New(ArchX86, Mode32)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	err = engine.SetOption(OptSyntax, OptSyntaxIntel)
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	// push ebp; mov ebp, esp; pop ebp; ret
	code := []byte{0x55, 0x89, 0xe5, 0x5d, 0xc3}

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}

	if len(instructions) != 4 {
		t.Errorf("Expected 4 instructions, got %d", len(instructions))
	}

	for _, insn := range instructions {
		t.Logf("0x%x: %s %s", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func TestATTSyntax(t *testing.T) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	err = engine.SetOption(OptSyntax, OptSyntaxATT)
	if err != nil {
		t.Fatalf("Failed to set option: %v", err)
	}

	code := []byte{0x48, 0x89, 0xe5} // mov rbp, rsp

	instructions, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}

	if len(instructions) == 0 {
		t.Error("No instructions disassembled")
	}

	for _, insn := range instructions {
		t.Logf("0x%x: %s %s", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func BenchmarkDisasm(b *testing.B) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Disasm(code, 0x1000, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}
