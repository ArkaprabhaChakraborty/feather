// Package x86 provides x86/x86-64 specific constants and types
package x86

// #include <capstone/x86.h>
import "C"

// Register constants
type Reg uint

const (
	REG_INVALID Reg = C.X86_REG_INVALID
	REG_AH      Reg = C.X86_REG_AH
	REG_AL      Reg = C.X86_REG_AL
	REG_AX      Reg = C.X86_REG_AX
	REG_BH      Reg = C.X86_REG_BH
	REG_BL      Reg = C.X86_REG_BL
	REG_BP      Reg = C.X86_REG_BP
	REG_BPL     Reg = C.X86_REG_BPL
	REG_BX      Reg = C.X86_REG_BX
	REG_CH      Reg = C.X86_REG_CH
	REG_CL      Reg = C.X86_REG_CL
	REG_CS      Reg = C.X86_REG_CS
	REG_CX      Reg = C.X86_REG_CX
	REG_DH      Reg = C.X86_REG_DH
	REG_DI      Reg = C.X86_REG_DI
	REG_DIL     Reg = C.X86_REG_DIL
	REG_DL      Reg = C.X86_REG_DL
	REG_DS      Reg = C.X86_REG_DS
	REG_DX      Reg = C.X86_REG_DX
	REG_EAX     Reg = C.X86_REG_EAX
	REG_EBP     Reg = C.X86_REG_EBP
	REG_EBX     Reg = C.X86_REG_EBX
	REG_ECX     Reg = C.X86_REG_ECX
	REG_EDI     Reg = C.X86_REG_EDI
	REG_EDX     Reg = C.X86_REG_EDX
	REG_EFLAGS  Reg = C.X86_REG_EFLAGS
	REG_EIP     Reg = C.X86_REG_EIP
	REG_ES      Reg = C.X86_REG_ES
	REG_ESI     Reg = C.X86_REG_ESI
	REG_ESP     Reg = C.X86_REG_ESP
	REG_FS      Reg = C.X86_REG_FS
	REG_GS      Reg = C.X86_REG_GS
	REG_IP      Reg = C.X86_REG_IP
	REG_RAX     Reg = C.X86_REG_RAX
	REG_RBP     Reg = C.X86_REG_RBP
	REG_RBX     Reg = C.X86_REG_RBX
	REG_RCX     Reg = C.X86_REG_RCX
	REG_RDI     Reg = C.X86_REG_RDI
	REG_RDX     Reg = C.X86_REG_RDX
	REG_RIP     Reg = C.X86_REG_RIP
	REG_RSI     Reg = C.X86_REG_RSI
	REG_RSP     Reg = C.X86_REG_RSP
	REG_SI      Reg = C.X86_REG_SI
	REG_SIL     Reg = C.X86_REG_SIL
	REG_SP      Reg = C.X86_REG_SP
	REG_SPL     Reg = C.X86_REG_SPL
	REG_SS      Reg = C.X86_REG_SS
	// Add more as needed...
)

// EFLAGS constants
const (
	EFLAGS_MODIFY_AF = 1 << 0
	EFLAGS_MODIFY_CF = 1 << 1
	EFLAGS_MODIFY_SF = 1 << 2
	EFLAGS_MODIFY_ZF = 1 << 3
	EFLAGS_MODIFY_PF = 1 << 4
	EFLAGS_MODIFY_OF = 1 << 5
	// Add more as needed...
)

// Instruction group constants
type Group uint

const (
	GRP_INVALID Group = C.X86_GRP_INVALID
	GRP_JUMP    Group = C.X86_GRP_JUMP
	GRP_CALL    Group = C.X86_GRP_CALL
	GRP_RET     Group = C.X86_GRP_RET
	GRP_INT     Group = C.X86_GRP_INT
	GRP_IRET    Group = C.X86_GRP_IRET
	// Add more as needed...
)
