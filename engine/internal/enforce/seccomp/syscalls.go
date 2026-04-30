package seccomp

// AUDIT_ARCH_* values from <linux/audit.h>. Exposed as exported consts so
// callers (the gateway, tests) can pass them to Compile.
const (
	ArchAMD64 uint32 = 0xC000003E // AUDIT_ARCH_X86_64
	ArchARM64 uint32 = 0xC00000B7 // AUDIT_ARCH_AARCH64
)

// SyscallTable maps human-readable syscall names to their numbers, per arch.
//
// This is intentionally not exhaustive — we list the syscalls a choke
// policy is plausibly going to want to deny. Add more as needed; an
// unknown name is reported as a non-fatal warning by the compiler so
// missing entries are visible at install time, not at runtime.
var SyscallTable = map[uint32]map[string]uint32{
	ArchAMD64: {
		// "ransomware-shape" / persistence
		"ptrace":           101,
		"process_vm_writev": 311,
		"process_vm_readv":  310,
		// kernel surface
		"mount":         165,
		"umount2":       166,
		"init_module":   175,
		"finit_module":  313,
		"delete_module": 176,
		"bpf":           321,
		"perf_event_open": 298,
		"unshare":       272,
		"setns":         308,
		// time tampering (token replay)
		"clock_settime": 227,
		"settimeofday":  164,
		"adjtimex":      159,
		"clock_adjtime": 305,
		// privilege bumps
		"setuid":  105,
		"setreuid": 113,
		"setresuid": 117,
		"capset":  126,
		// network surface
		"socket":      41,
		"connect":     42,
		"bind":        49,
		"listen":      50,
		"accept":      43,
		"sendto":      44,
		"recvfrom":    45,
		// fs surface
		"execve":   59,
		"execveat": 322,
		"chmod":    90,
		"fchmod":   91,
		"fchmodat": 268,
		"chown":    92,
		"fchown":   93,
		"fchownat": 260,
	},
	ArchARM64: {
		"ptrace":            117,
		"process_vm_writev": 271,
		"process_vm_readv":  270,
		"mount":             40,
		"umount2":           39,
		"init_module":       105,
		"finit_module":      273,
		"delete_module":     106,
		"bpf":               280,
		"perf_event_open":   241,
		"unshare":           97,
		"setns":             268,
		"clock_settime":     112,
		"settimeofday":      170,
		"adjtimex":          171,
		"clock_adjtime":     266,
		"setuid":            146,
		"setreuid":          145,
		"setresuid":         147,
		"capset":            91,
		"socket":            198,
		"connect":           203,
		"bind":              200,
		"listen":            201,
		"accept":            202,
		"sendto":            206,
		"recvfrom":          207,
		"execve":            221,
		"execveat":          281,
		"chmod":             52, // fchmodat (chmod absent on aarch64)
		"fchmod":            52,
		"fchmodat":          53,
		"chown":             54, // fchownat (chown absent on aarch64)
		"fchown":            55,
		"fchownat":          54,
	},
}
