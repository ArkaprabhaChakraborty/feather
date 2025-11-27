package capstonego2

// #include <capstone/capstone.h>
import "C"

// Architecture constants
const (
	ArchARM     Architecture = C.CS_ARCH_ARM
	ArchARM64   Architecture = C.CS_ARCH_AARCH64
	ArchMIPS    Architecture = C.CS_ARCH_MIPS
	ArchX86     Architecture = C.CS_ARCH_X86
	ArchPPC     Architecture = C.CS_ARCH_PPC
	ArchSPARC   Architecture = C.CS_ARCH_SPARC
	ArchSYSZ    Architecture = C.CS_ARCH_SYSTEMZ
	ArchXCORE   Architecture = C.CS_ARCH_XCORE
	ArchM68K    Architecture = C.CS_ARCH_M68K
	ArchTMS320C64X Architecture = C.CS_ARCH_TMS320C64X
	ArchM680X   Architecture = C.CS_ARCH_M680X
	ArchEVM     Architecture = C.CS_ARCH_EVM
	ArchMax     Architecture = C.CS_ARCH_MAX
	ArchAll     Architecture = C.CS_ARCH_ALL
)

// Mode constants
const (
	ModeLittleEndian Mode = C.CS_MODE_LITTLE_ENDIAN
	ModeARM          Mode = C.CS_MODE_ARM
	Mode16           Mode = C.CS_MODE_16
	Mode32           Mode = C.CS_MODE_32
	Mode64           Mode = C.CS_MODE_64
	ModeThumb        Mode = C.CS_MODE_THUMB
	ModeMClass       Mode = C.CS_MODE_MCLASS
	ModeV8           Mode = C.CS_MODE_V8
	ModeMicro        Mode = C.CS_MODE_MICRO
	ModeMIPS3        Mode = C.CS_MODE_MIPS3
	ModeMIPS32R6     Mode = C.CS_MODE_MIPS32R6
	ModeMIPS2        Mode = C.CS_MODE_MIPS2
	ModeV9           Mode = C.CS_MODE_V9
	ModeQPX          Mode = C.CS_MODE_QPX
	ModeM68K000      Mode = C.CS_MODE_M68K_000
	ModeM68K010      Mode = C.CS_MODE_M68K_010
	ModeM68K020      Mode = C.CS_MODE_M68K_020
	ModeM68K030      Mode = C.CS_MODE_M68K_030
	ModeM68K040      Mode = C.CS_MODE_M68K_040
	ModeM68K060      Mode = C.CS_MODE_M68K_060
	ModeBigEndian    Mode = C.CS_MODE_BIG_ENDIAN
	ModeMIPS32       Mode = C.CS_MODE_MIPS32
	ModeMIPS64       Mode = C.CS_MODE_MIPS64
)

// Option type constants
const (
	OptInvalid      OptionType = C.CS_OPT_INVALID
	OptSyntax       OptionType = C.CS_OPT_SYNTAX
	OptDetail       OptionType = C.CS_OPT_DETAIL
	OptMode         OptionType = C.CS_OPT_MODE
	OptMem          OptionType = C.CS_OPT_MEM
	OptSkipData     OptionType = C.CS_OPT_SKIPDATA
	OptSkipDataSetup OptionType = C.CS_OPT_SKIPDATA_SETUP
	OptMnemonic     OptionType = C.CS_OPT_MNEMONIC
	OptUnsigned     OptionType = C.CS_OPT_UNSIGNED
)

// Option value constants
const (
	OptOff            OptionValue = C.CS_OPT_OFF
	OptOn             OptionValue = C.CS_OPT_ON
	OptSyntaxDefault  OptionValue = C.CS_OPT_SYNTAX_DEFAULT
	OptSyntaxIntel    OptionValue = C.CS_OPT_SYNTAX_INTEL
	OptSyntaxATT      OptionValue = C.CS_OPT_SYNTAX_ATT
	OptSyntaxNoRegName OptionValue = C.CS_OPT_SYNTAX_NOREGNAME
	OptSyntaxMASM     OptionValue = C.CS_OPT_SYNTAX_MASM
)

// Error constants
const (
	ErrOK       Error = C.CS_ERR_OK
	ErrMem      Error = C.CS_ERR_MEM
	ErrArch     Error = C.CS_ERR_ARCH
	ErrHandle   Error = C.CS_ERR_HANDLE
	ErrCSH      Error = C.CS_ERR_CSH
	ErrMode     Error = C.CS_ERR_MODE
	ErrOption   Error = C.CS_ERR_OPTION
	ErrDetail   Error = C.CS_ERR_DETAIL
	ErrMemSetup Error = C.CS_ERR_MEMSETUP
	ErrVersion  Error = C.CS_ERR_VERSION
	ErrDiet     Error = C.CS_ERR_DIET
	ErrSkipData Error = C.CS_ERR_SKIPDATA
	ErrX86ATT   Error = C.CS_ERR_X86_ATT
	ErrX86Intel Error = C.CS_ERR_X86_INTEL
)

// Support constants
const (
	SupportDiet      = C.CS_SUPPORT_DIET
	SupportX86Reduce = C.CS_SUPPORT_X86_REDUCE
)
