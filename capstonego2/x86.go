package capstonego2

// #include <capstone/capstone.h>
// #include <capstone/x86.h>
import "C"

import (
	"unsafe"
)

// X86Instruction contains x86/x86-64 specific instruction details
type X86Instruction struct {
	Prefix   [4]byte       // Instruction prefix bytes
	Opcode   [4]byte       // Instruction opcode bytes
	Rex      byte          // REX prefix
	AddrSize byte          // Address size
	ModRM    byte          // ModR/M byte
	Sib      byte          // SIB byte
	Disp     int64         // Displacement value
	SibIndex uint          // SIB index register
	SibScale int8          // SIB scale
	SibBase  uint          // SIB base register
	XopCC    uint          // XOP condition code
	SseCC    uint          // SSE condition code
	AvxCC    uint          // AVX condition code
	AvxSAE   bool          // AVX SAE flag
	AvxRM    uint          // AVX rounding mode
	EFlags   uint64        // EFLAGS updated by this instruction
	FPUFlags uint64        // FPU flags updated by this instruction
	Operands []X86Operand  // Instruction operands
	Encoding X86Encoding   // Encoding information
}

// X86Encoding contains instruction encoding details
type X86Encoding struct {
	ModRMOffset byte // ModR/M offset
	DispOffset  byte // Displacement offset
	DispSize    byte // Displacement size
	ImmOffset   byte // Immediate offset
	ImmSize     byte // Immediate size
}

// X86Operand represents an x86 instruction operand
type X86Operand struct {
	Type          X86OpType        // Operand type
	Reg           uint             // Register value (for X86_OP_REG)
	Imm           int64            // Immediate value (for X86_OP_IMM)
	Mem           X86MemoryOperand // Memory operand (for X86_OP_MEM)
	Size          uint8            // Operand size in bytes
	Access        uint8            // Access type (read/write)
	AvxBcast      uint             // AVX broadcast type
	AvxZeroOpmask bool             // AVX zero opmask flag
}

// X86MemoryOperand represents a memory operand
type X86MemoryOperand struct {
	Segment uint  // Segment register
	Base    uint  // Base register
	Index   uint  // Index register
	Scale   int   // Scale factor
	Disp    int64 // Displacement
}

// X86OpType represents operand types
type X86OpType uint

const (
	X86_OP_INVALID X86OpType = C.X86_OP_INVALID
	X86_OP_REG     X86OpType = C.X86_OP_REG
	X86_OP_IMM     X86OpType = C.X86_OP_IMM
	X86_OP_MEM     X86OpType = C.X86_OP_MEM
)

// OpCount returns the number of operands of a given type
func (insn *X86Instruction) OpCount(optype X86OpType) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

// fillX86Details fills x86-specific instruction details
func fillX86Details(cInsn *C.cs_insn) *X86Instruction {
	if cInsn.detail == nil {
		return nil
	}
	
	// Cast to x86 detail structure
	csX86 := (*C.cs_x86)(unsafe.Pointer(&cInsn.detail.anon0[0]))
	
	x86 := &X86Instruction{
		Rex:      byte(csX86.rex),
		AddrSize: byte(csX86.addr_size),
		ModRM:    byte(csX86.modrm),
		Sib:      byte(csX86.sib),
		Disp:     int64(csX86.disp),
		SibIndex: uint(csX86.sib_index),
		SibScale: int8(csX86.sib_scale),
		SibBase:  uint(csX86.sib_base),
		XopCC:    uint(csX86.xop_cc),
		SseCC:    uint(csX86.sse_cc),
		AvxCC:    uint(csX86.avx_cc),
		AvxSAE:   bool(csX86.avx_sae),
		AvxRM:    uint(csX86.avx_rm),
		Encoding: X86Encoding{
			ModRMOffset: byte(csX86.encoding.modrm_offset),
			DispOffset:  byte(csX86.encoding.disp_offset),
			DispSize:    byte(csX86.encoding.disp_size),
			ImmOffset:   byte(csX86.encoding.imm_offset),
			ImmSize:     byte(csX86.encoding.imm_size),
		},
	}
	
	// Copy prefix and opcode arrays
	for i := 0; i < 4; i++ {
		x86.Prefix[i] = byte(csX86.prefix[i])
		x86.Opcode[i] = byte(csX86.opcode[i])
	}
	
	// Handle eflags/fpu_flags union
	x86.EFlags = uint64(*(*C.uint64_t)(unsafe.Pointer(&csX86.anon0[0])))
	
	// Parse operands
	x86.Operands = make([]X86Operand, int(csX86.op_count))
	for i := 0; i < int(csX86.op_count); i++ {
		cop := &csX86.operands[i]
		
		gop := X86Operand{
			Type:          X86OpType(cop._type),
			Size:          uint8(cop.size),
			Access:        uint8(cop.access),
			AvxBcast:      uint(cop.avx_bcast),
			AvxZeroOpmask: bool(cop.avx_zero_opmask),
		}
		
		switch X86OpType(cop._type) {
		case X86_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_MEM:
			cmem := (*C.x86_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = X86MemoryOperand{
				Segment: uint(cmem.segment),
				Base:    uint(cmem.base),
				Index:   uint(cmem.index),
				Scale:   int(cmem.scale),
				Disp:    int64(cmem.disp),
			}
		}
		
		x86.Operands[i] = gop
	}
	
	return x86
}
