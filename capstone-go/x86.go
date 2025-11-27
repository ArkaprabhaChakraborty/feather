package capstone

// #include <capstone/capstone.h>
// #include <capstone/x86.h>
import "C"

// X86 operand types
type X86OpType uint

const (
	X86_OP_INVALID X86OpType = C.X86_OP_INVALID
	X86_OP_REG     X86OpType = C.X86_OP_REG
	X86_OP_IMM     X86OpType = C.X86_OP_IMM
	X86_OP_MEM     X86OpType = C.X86_OP_MEM
)

// X86OpMem represents memory operand structure
type X86OpMem struct {
	Segment X86Reg // Segment register (or X86_REG_INVALID if irrelevant)
	Base    X86Reg // Base register (or X86_REG_INVALID if irrelevant)
	Index   X86Reg // Index register (or X86_REG_INVALID if irrelevant)
	Scale   int    // Scale for index register (1, 2, 4, or 8)
	Disp    int64  // Displacement value
}

// X86Operand represents an x86 operand
type X86Operand struct {
	Type          X86OpType // Operand type
	Reg           X86Reg    // Register value (for X86_OP_REG)
	Imm           int64     // Immediate value (for X86_OP_IMM)
	Mem           X86OpMem  // Memory value (for X86_OP_MEM)
	Size          uint8     // Size of operand in bytes
	Access        uint8     // Access type (READ, WRITE, or READ|WRITE)
	AvxBcast      uint      // AVX broadcast type
	AvxZeroOpmask bool      // AVX zero opmask
}

// X86Encoding represents instruction encoding details
type X86Encoding struct {
	ModRMOffset uint8 // ModR/M offset, or 0 when irrelevant
	DispOffset  uint8 // Displacement offset, or 0 when irrelevant
	DispSize    uint8 // Displacement size, or 0 when irrelevant
	ImmOffset   uint8 // Immediate offset, or 0 when irrelevant
	ImmSize     uint8 // Immediate size, or 0 when irrelevant
}

// X86Detail represents x86-specific instruction details
type X86Detail struct {
	Prefix   [4]uint8    // Instruction prefix bytes
	Opcode   [4]uint8    // Instruction opcode bytes
	Rex      uint8       // REX prefix byte
	AddrSize uint8       // Address size
	ModRM    uint8       // ModR/M byte
	Sib      uint8       // SIB byte
	Disp     int64       // Displacement value
	SibIndex X86Reg      // SIB index register
	SibScale int8        // SIB scale
	SibBase  X86Reg      // SIB base register
	XopCC    uint        // XOP condition code
	SseCC    uint        // SSE condition code
	AvxCC    uint        // AVX condition code
	AvxSae   bool        // AVX SAE (Suppress All Exceptions)
	AvxRM    uint        // AVX rounding mode
	Eflags   uint64      // EFLAGS updated by this instruction
	FpuFlags uint64      // FPU flags updated by this instruction
	Operands []X86Operand // Operand list
	Encoding X86Encoding // Encoding information
}
