// Package capstonego2 provides optimized Go bindings for the Capstone disassembly library.
//
// This is an improved version based on gapstone with:
// - Modular architecture
// - Better performance
// - Cleaner API
// - Comprehensive error handling
package capstonego2

// #cgo LDFLAGS: -L/usr/local/lib -lcapstone -Wl,-rpath,/usr/local/lib
// #cgo CFLAGS: -I/usr/local/include
// #include <capstone/capstone.h>
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"unsafe"
)

// Engine represents a Capstone disassembly engine instance.
// After creation, it must be closed with Close() to free resources.
type Engine struct {
	handle C.csh
	arch   Architecture
	mode   Mode
}

// New creates a new disassembly engine for the specified architecture and mode.
// The engine must be closed with Close() when done to free resources.
//
// Example:
//
//	engine, err := capstonego2.New(ArchX86, Mode64)
//	if err != nil {
//	    return err
//	}
//	defer engine.Close()
func New(arch Architecture, mode Mode) (*Engine, error) {
	var handle C.csh
	
	err := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if err != C.CS_ERR_OK {
		return nil, Error(err)
	}
	
	return &Engine{
		handle: handle,
		arch:   arch,
		mode:   mode,
	}, nil
}

// Close closes the engine and frees all associated resources.
// After calling Close(), the engine should not be used.
func (e *Engine) Close() error {
	if e.handle == 0 {
		return nil // Already closed
	}
	
	err := C.cs_close(&e.handle)
	if err != C.CS_ERR_OK {
		return Error(err)
	}
	
	e.handle = 0
	return nil
}

// SetOption sets an option for the engine.
//
// Common options:
//   - OptDetail: Enable detailed instruction information
//   - OptSyntax: Set assembly syntax (Intel, AT&T, etc.)
//   - OptSkipData: Skip data when disassembling
func (e *Engine) SetOption(opt OptionType, value OptionValue) error {
	err := C.cs_option(e.handle, C.cs_opt_type(opt), C.size_t(value))
	if err != C.CS_ERR_OK {
		return Error(err)
	}
	return nil
}

// Disasm disassembles binary code and returns a slice of instructions.
//
// Parameters:
//   - code: Binary code to disassemble
//   - address: Starting address for the first instruction
//   - count: Number of instructions to disassemble (0 = all)
//
// Example:
//
//	code := []byte{0x55, 0x48, 0x89, 0xe5}
//	insns, err := engine.Disasm(code, 0x1000, 0)
func (e *Engine) Disasm(code []byte, address uint64, count uint) ([]Instruction, error) {
	if len(code) == 0 {
		return nil, fmt.Errorf("empty code buffer")
	}
	
	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	cSize := C.size_t(len(code))
	
	numInsns := C.cs_disasm(
		e.handle,
		cCode,
		cSize,
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)
	
	if numInsns == 0 {
		return nil, fmt.Errorf("failed to disassemble code")
	}
	defer C.cs_free(insn, numInsns)
	
	// Convert C instructions to Go
	return e.convertInstructions(insn, int(numInsns))
}

// convertInstructions converts C cs_insn array to Go Instruction slice
func (e *Engine) convertInstructions(cInsns *C.cs_insn, count int) ([]Instruction, error) {
	// Create slice header pointing to C array
	insns := (*[1 << 30]C.cs_insn)(unsafe.Pointer(cInsns))[:count:count]
	
	result := make([]Instruction, count)
	for i := 0; i < count; i++ {
		result[i] = e.convertInstruction(&insns[i])
	}
	
	return result, nil
}

// convertInstruction converts a single C instruction to Go
func (e *Engine) convertInstruction(cInsn *C.cs_insn) Instruction {
	insn := Instruction{
		ID:       uint(cInsn.id),
		Address:  uint64(cInsn.address),
		Size:     uint16(cInsn.size),
		Bytes:    C.GoBytes(unsafe.Pointer(&cInsn.bytes[0]), C.int(cInsn.size)),
		Mnemonic: C.GoString(&cInsn.mnemonic[0]),
		OpStr:    C.GoString(&cInsn.op_str[0]),
	}
	
	// Add architecture-specific details if available
	if cInsn.detail != nil {
		e.fillDetails(&insn, cInsn)
	}
	
	return insn
}

// fillDetails fills architecture-specific instruction details
func (e *Engine) fillDetails(insn *Instruction, cInsn *C.cs_insn) {
	if cInsn.detail == nil {
		return
	}
	
	detail := cInsn.detail
	
	// Fill generic details (registers read/written, groups)
	insn.RegsRead = convertRegArray(detail.regs_read[:], int(detail.regs_read_count))
	insn.RegsWrite = convertRegArray(detail.regs_write[:], int(detail.regs_write_count))
	insn.Groups = convertGroupArray(detail.groups[:], int(detail.groups_count))
	
	// Fill architecture-specific details
	switch e.arch {
	case ArchX86:
		insn.X86 = fillX86Details(cInsn)
	// Add other architectures as needed
	}
}

// Version returns the Capstone library version
func Version() (major, minor int) {
	cMajor := C.int(0)
	cMinor := C.int(0)
	C.cs_version(&cMajor, &cMinor)
	return int(cMajor), int(cMinor)
}

// Support checks if an architecture is supported
func Support(arch Architecture) bool {
	return bool(C.cs_support(C.int(arch)))
}

// Helper functions

func convertRegArray(regs []C.uint16_t, count int) []uint {
	if count == 0 {
		return nil
	}
	result := make([]uint, count)
	for i := 0; i < count; i++ {
		result[i] = uint(regs[i])
	}
	return result
}

func convertGroupArray(groups []C.uint8_t, count int) []uint {
	if count == 0 {
		return nil
	}
	result := make([]uint, count)
	for i := 0; i < count; i++ {
		result[i] = uint(groups[i])
	}
	return result
}
