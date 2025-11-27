package capstonego2

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
	
	if engine.arch != ArchX86 {
		t.Errorf("Expected arch %v, got %v", ArchX86, engine.arch)
	}
	if engine.mode != Mode64 {
		t.Errorf("Expected mode %v, got %v", Mode64, engine.mode)
	}
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
	
	insns, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}
	
	if len(insns) != 4 {
		t.Errorf("Expected 4 instructions, got %d", len(insns))
	}
	
	expected := []string{"push", "mov", "pop", "ret"}
	for i, insn := range insns {
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
	
	insns, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}
	
	if len(insns) != 4 {
		t.Errorf("Expected 4 instructions, got %d", len(insns))
	}
	
	for _, insn := range insns {
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
	
	insns, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}
	
	if len(insns) == 0 {
		t.Error("No instructions disassembled")
	}
	
	for _, insn := range insns {
		t.Logf("0x%x: %s %s", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}

func TestDetailMode(t *testing.T) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()
	
	// Enable detail mode
	err = engine.SetOption(OptDetail, OptOn)
	if err != nil {
		t.Fatalf("Failed to enable detail mode: %v", err)
	}
	
	code := []byte{0x55, 0x48, 0x89, 0xe5}
	
	insns, err := engine.Disasm(code, 0x1000, 0)
	if err != nil {
		t.Fatalf("Failed to disassemble: %v", err)
	}
	
	for _, insn := range insns {
		t.Logf("0x%x: %s %s", insn.Address, insn.Mnemonic, insn.OpStr)
		if insn.X86 != nil {
			t.Logf("  Operands: %d", len(insn.X86.Operands))
			for j, op := range insn.X86.Operands {
				t.Logf("    Op %d: type=%d", j, op.Type)
			}
		}
	}
}

func TestSupport(t *testing.T) {
	if !Support(ArchX86) {
		t.Error("x86 should be supported")
	}
	
	t.Logf("x86 supported: %v", Support(ArchX86))
	t.Logf("ARM supported: %v", Support(ArchARM))
}

func TestEmptyCode(t *testing.T) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()
	
	_, err = engine.Disasm([]byte{}, 0x1000, 0)
	if err == nil {
		t.Error("Expected error for empty code")
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

func BenchmarkDisasmWithDetail(b *testing.B) {
	engine, err := New(ArchX86, Mode64)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()
	
	engine.SetOption(OptDetail, OptOn)
	
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Disasm(code, 0x1000, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}
