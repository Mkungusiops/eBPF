//go:build linux

package seccomp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ApplyToSelf installs the compiled filter on the calling thread via
// prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER). Once installed it cannot be
// removed (kernel guarantees no escape from a stricter filter), and it is
// inherited across fork/exec.
//
// The filter applies only to the current thread group — typical use is to
// fork+exec a sandboxed child and have the child call ApplyToSelf right
// after it sets up the filter and before exec()'ing the workload.
//
// To filter a different running process we'd need ptrace; that's outside
// the scope of phase 2. The companion BPF-LSM backend is the better
// choice for hot-applying restrictions to running processes.
func (f *Filter) ApplyToSelf() error {
	if f == nil || len(f.Insns) == 0 {
		return fmt.Errorf("seccomp: refusing to apply empty filter")
	}

	// PR_SET_NO_NEW_PRIVS is required for unprivileged seccomp install.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}

	// struct sock_fprog { unsigned short len; struct sock_filter *filter; }
	type sockFprog struct {
		Len    uint16
		_pad   [6]byte // padding so Filter aligns at offset 8 on amd64
		Filter *SockFilter
	}
	prog := sockFprog{
		Len:    uint16(len(f.Insns)),
		Filter: &f.Insns[0],
	}
	const PR_SET_SECCOMP = 22
	const SECCOMP_MODE_FILTER = 2
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_SECCOMP): %v", errno)
	}
	return nil
}

// HostArch returns the AUDIT_ARCH_* constant for the running kernel.
func HostArch() uint32 {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		// machine[:] is null-terminated; "x86_64" or "aarch64"
		m := nullTerm(uts.Machine[:])
		switch m {
		case "x86_64":
			return ArchAMD64
		case "aarch64":
			return ArchARM64
		}
	}
	return ArchAMD64 // sensible default for the deployment target
}

func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
