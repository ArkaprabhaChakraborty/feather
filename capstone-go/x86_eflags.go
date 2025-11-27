package capstone

// EFLAGS bit definitions
const (
	X86_EFLAGS_MODIFY_AF     uint64 = 1 << 0
	X86_EFLAGS_MODIFY_CF     uint64 = 1 << 1
	X86_EFLAGS_MODIFY_SF     uint64 = 1 << 2
	X86_EFLAGS_MODIFY_ZF     uint64 = 1 << 3
	X86_EFLAGS_MODIFY_PF     uint64 = 1 << 4
	X86_EFLAGS_MODIFY_OF     uint64 = 1 << 5
	X86_EFLAGS_MODIFY_TF     uint64 = 1 << 6
	X86_EFLAGS_MODIFY_IF     uint64 = 1 << 7
	X86_EFLAGS_MODIFY_DF     uint64 = 1 << 8
	X86_EFLAGS_MODIFY_NT     uint64 = 1 << 9
	X86_EFLAGS_MODIFY_RF     uint64 = 1 << 10
	X86_EFLAGS_PRIOR_OF      uint64 = 1 << 11
	X86_EFLAGS_PRIOR_SF      uint64 = 1 << 12
	X86_EFLAGS_PRIOR_ZF      uint64 = 1 << 13
	X86_EFLAGS_PRIOR_AF      uint64 = 1 << 14
	X86_EFLAGS_PRIOR_PF      uint64 = 1 << 15
	X86_EFLAGS_PRIOR_CF      uint64 = 1 << 16
	X86_EFLAGS_PRIOR_TF      uint64 = 1 << 17
	X86_EFLAGS_PRIOR_IF      uint64 = 1 << 18
	X86_EFLAGS_PRIOR_DF      uint64 = 1 << 19
	X86_EFLAGS_PRIOR_NT      uint64 = 1 << 20
	X86_EFLAGS_RESET_OF      uint64 = 1 << 21
	X86_EFLAGS_RESET_CF      uint64 = 1 << 22
	X86_EFLAGS_RESET_DF      uint64 = 1 << 23
	X86_EFLAGS_RESET_IF      uint64 = 1 << 24
	X86_EFLAGS_RESET_SF      uint64 = 1 << 25
	X86_EFLAGS_RESET_AF      uint64 = 1 << 26
	X86_EFLAGS_RESET_TF      uint64 = 1 << 27
	X86_EFLAGS_RESET_NT      uint64 = 1 << 28
	X86_EFLAGS_RESET_PF      uint64 = 1 << 29
	X86_EFLAGS_SET_CF        uint64 = 1 << 30
	X86_EFLAGS_SET_DF        uint64 = 1 << 31
	X86_EFLAGS_SET_IF        uint64 = 1 << 32
	X86_EFLAGS_TEST_OF       uint64 = 1 << 33
	X86_EFLAGS_TEST_SF       uint64 = 1 << 34
	X86_EFLAGS_TEST_ZF       uint64 = 1 << 35
	X86_EFLAGS_TEST_PF       uint64 = 1 << 36
	X86_EFLAGS_TEST_CF       uint64 = 1 << 37
	X86_EFLAGS_TEST_NT       uint64 = 1 << 38
	X86_EFLAGS_TEST_DF       uint64 = 1 << 39
	X86_EFLAGS_UNDEFINED_OF  uint64 = 1 << 40
	X86_EFLAGS_UNDEFINED_SF  uint64 = 1 << 41
	X86_EFLAGS_UNDEFINED_ZF  uint64 = 1 << 42
	X86_EFLAGS_UNDEFINED_PF  uint64 = 1 << 43
	X86_EFLAGS_UNDEFINED_AF  uint64 = 1 << 44
	X86_EFLAGS_UNDEFINED_CF  uint64 = 1 << 45
	X86_EFLAGS_RESET_RF      uint64 = 1 << 46
	X86_EFLAGS_TEST_RF       uint64 = 1 << 47
	X86_EFLAGS_TEST_IF       uint64 = 1 << 48
	X86_EFLAGS_TEST_TF       uint64 = 1 << 49
)

// FPU FLAGS bit definitions
const (
	X86_FPU_FLAGS_MODIFY_C0    uint64 = 1 << 0
	X86_FPU_FLAGS_MODIFY_C1    uint64 = 1 << 1
	X86_FPU_FLAGS_MODIFY_C2    uint64 = 1 << 2
	X86_FPU_FLAGS_MODIFY_C3    uint64 = 1 << 3
	X86_FPU_FLAGS_RESET_C0     uint64 = 1 << 4
	X86_FPU_FLAGS_RESET_C1     uint64 = 1 << 5
	X86_FPU_FLAGS_RESET_C2     uint64 = 1 << 6
	X86_FPU_FLAGS_RESET_C3     uint64 = 1 << 7
	X86_FPU_FLAGS_SET_C0       uint64 = 1 << 8
	X86_FPU_FLAGS_SET_C1       uint64 = 1 << 9
	X86_FPU_FLAGS_SET_C2       uint64 = 1 << 10
	X86_FPU_FLAGS_SET_C3       uint64 = 1 << 11
	X86_FPU_FLAGS_UNDEFINED_C0 uint64 = 1 << 12
	X86_FPU_FLAGS_UNDEFINED_C1 uint64 = 1 << 13
	X86_FPU_FLAGS_UNDEFINED_C2 uint64 = 1 << 14
	X86_FPU_FLAGS_UNDEFINED_C3 uint64 = 1 << 15
	X86_FPU_FLAGS_TEST_C0      uint64 = 1 << 16
	X86_FPU_FLAGS_TEST_C1      uint64 = 1 << 17
	X86_FPU_FLAGS_TEST_C2      uint64 = 1 << 18
	X86_FPU_FLAGS_TEST_C3      uint64 = 1 << 19
)
