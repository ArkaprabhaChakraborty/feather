package capstone

// #cgo LDFLAGS: -L/usr/local/lib -lcapstone -Wl,-rpath,/usr/local/lib
// #include <capstone/capstone.h>
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// Architecture type
type Arch int

const (
	ArchARM     Arch = C.CS_ARCH_ARM
	ArchARM64   Arch = C.CS_ARCH_AARCH64
	ArchMIPS    Arch = C.CS_ARCH_MIPS
	ArchX86     Arch = C.CS_ARCH_X86
	ArchPPC     Arch = C.CS_ARCH_PPC
	ArchSPARC   Arch = C.CS_ARCH_SPARC
	ArchSYSTEMZ Arch = C.CS_ARCH_SYSTEMZ
	ArchXCORE   Arch = C.CS_ARCH_XCORE
)

// Mode type
type Mode int

const (
	ModeLittleEndian Mode = C.CS_MODE_LITTLE_ENDIAN
	Mode16           Mode = C.CS_MODE_16
	Mode32           Mode = C.CS_MODE_32
	Mode64           Mode = C.CS_MODE_64
	ModeArm          Mode = C.CS_MODE_ARM
	ModeThumb        Mode = C.CS_MODE_THUMB
)

// Option type
type OptionType int

const (
	OptSyntax   OptionType = C.CS_OPT_SYNTAX
	OptDetail   OptionType = C.CS_OPT_DETAIL
	OptMode     OptionType = C.CS_OPT_MODE
	OptSkipData OptionType = C.CS_OPT_SKIPDATA
)

// Option value
type OptionValue int

const (
	OptOff         OptionValue = C.CS_OPT_OFF
	OptOn          OptionValue = C.CS_OPT_ON
	OptSyntaxIntel OptionValue = C.CS_OPT_SYNTAX_INTEL
	OptSyntaxATT   OptionValue = C.CS_OPT_SYNTAX_ATT
)

// Error codes
type ErrCode int

const (
	ErrOK       ErrCode = C.CS_ERR_OK
	ErrMem      ErrCode = C.CS_ERR_MEM
	ErrArch     ErrCode = C.CS_ERR_ARCH
	ErrHandle   ErrCode = C.CS_ERR_HANDLE
	ErrCSH      ErrCode = C.CS_ERR_CSH
	ErrMode     ErrCode = C.CS_ERR_MODE
	ErrOption   ErrCode = C.CS_ERR_OPTION
	ErrDetail   ErrCode = C.CS_ERR_DETAIL
	ErrMemSetup ErrCode = C.CS_ERR_MEMSETUP
	ErrVersion  ErrCode = C.CS_ERR_VERSION
	ErrDiet     ErrCode = C.CS_ERR_DIET
	ErrSkipData ErrCode = C.CS_ERR_SKIPDATA
	ErrX86ATT   ErrCode = C.CS_ERR_X86_ATT
	ErrX86Intel ErrCode = C.CS_ERR_X86_INTEL
)

func (e ErrCode) Error() string {
	return C.GoString(C.cs_strerror(C.cs_err(e)))
}

// Engine represents a Capstone disassembly engine
type Engine struct {
	handle C.csh
	arch   Arch
	mode   Mode
}

// Instruction represents a disassembled instruction
type Instruction struct {
	ID       uint
	Address  uint64
	Size     uint16
	Bytes    []byte
	Mnemonic string
	OpStr    string
}

// New creates a new Capstone engine
func New(arch Arch, mode Mode) (*Engine, error) {
	var handle C.csh
	err := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if err != C.CS_ERR_OK {
		return nil, ErrCode(err)
	}
	return &Engine{handle: handle, arch: arch, mode: mode}, nil
}

// Close closes the Capstone engine
func (e *Engine) Close() error {
	err := C.cs_close(&e.handle)
	if err != C.CS_ERR_OK {
		return ErrCode(err)
	}
	return nil
}

// SetOption sets an option for the engine
func (e *Engine) SetOption(opt OptionType, value OptionValue) error {
	err := C.cs_option(e.handle, C.cs_opt_type(opt), C.size_t(value))
	if err != C.CS_ERR_OK {
		return ErrCode(err)
	}
	return nil
}

// Disasm disassembles binary code
func (e *Engine) Disasm(code []byte, address uint64, count int) ([]Instruction, error) {
	var insn *C.cs_insn
	cCode := (*C.uint8_t)(unsafe.Pointer(&code[0]))
	cSize := C.size_t(len(code))

	numInsns := C.cs_disasm(e.handle, cCode, cSize, C.uint64_t(address), C.size_t(count), &insn)
	if numInsns == 0 {
		return nil, fmt.Errorf("failed to disassemble")
	}
	defer C.cs_free(insn, numInsns)

	instructions := make([]Instruction, numInsns)
	insns := (*[1 << 30]C.cs_insn)(unsafe.Pointer(insn))[:numInsns:numInsns]

	for i := 0; i < int(numInsns); i++ {
		instructions[i] = Instruction{
			ID:       uint(insns[i].id),
			Address:  uint64(insns[i].address),
			Size:     uint16(insns[i].size),
			Bytes:    C.GoBytes(unsafe.Pointer(&insns[i].bytes[0]), C.int(insns[i].size)),
			Mnemonic: C.GoString(&insns[i].mnemonic[0]),
			OpStr:    C.GoString(&insns[i].op_str[0]),
		}
	}

	return instructions, nil
}

// Version returns Capstone version
func Version() (int, int) {
	major := C.int(0)
	minor := C.int(0)
	C.cs_version(&major, &minor)
	return int(major), int(minor)
}
