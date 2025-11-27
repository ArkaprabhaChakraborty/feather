package capstonego2

// Instruction represents a disassembled instruction with all its details.
type Instruction struct {
	// Basic instruction information
	ID       uint     // Instruction ID (architecture-specific)
	Address  uint64   // Instruction address
	Size     uint16   // Instruction size in bytes
	Bytes    []byte   // Raw instruction bytes
	Mnemonic string   // Instruction mnemonic (e.g., "mov", "add")
	OpStr    string   // Operand string (e.g., "rax, rbx")
	
	// Detailed information (requires CS_OPT_DETAIL)
	RegsRead  []uint // Registers read by this instruction
	RegsWrite []uint // Registers written by this instruction
	Groups    []uint // Instruction groups this belongs to
	
	// Architecture-specific details
	X86    *X86Instruction    // x86/x86-64 specific details
	ARM    *ARMInstruction    // ARM specific details
	ARM64  *ARM64Instruction  // ARM64 specific details
	MIPS   *MIPSInstruction   // MIPS specific details
	PPC    *PPCInstruction    // PowerPC specific details
	SPARC  *SPARCInstruction  // SPARC specific details
	SYSZ   *SYSZInstruction   // SystemZ specific details
	XCORE  *XCOREInstruction  // XCore specific details
}

// Architecture represents a CPU architecture
type Architecture int

// Mode represents disassembly mode
type Mode int

// OptionType represents an engine option type
type OptionType int

// OptionValue represents an engine option value
type OptionValue int

// Error represents a Capstone error
type Error int

func (e Error) Error() string {
	return errorStrings[e]
}

var errorStrings = map[Error]string{
	ErrOK:       "No error",
	ErrMem:      "Out of memory",
	ErrArch:     "Unsupported architecture",
	ErrHandle:   "Invalid handle",
	ErrCSH:      "Invalid csh argument",
	ErrMode:     "Invalid/unsupported mode",
	ErrOption:   "Invalid/unsupported option",
	ErrDetail:   "Detail information unavailable",
	ErrMemSetup: "Dynamic memory management uninitialized",
	ErrVersion:  "Unsupported version",
	ErrDiet:     "Access irrelevant data in diet engine",
	ErrSkipData: "Access irrelevant data for data instruction",
	ErrX86ATT:   "X86 AT&T syntax unsupported",
	ErrX86Intel: "X86 Intel syntax unsupported",
}

// Placeholder types for other architectures
type ARMInstruction struct{}
type ARM64Instruction struct{}
type MIPSInstruction struct{}
type PPCInstruction struct{}
type SPARCInstruction struct{}
type SYSZInstruction struct{}
type XCOREInstruction struct{}
