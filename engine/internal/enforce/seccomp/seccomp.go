// Package seccomp compiles policy.Policy DenySyscalls into a cBPF filter
// suitable for prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...).
//
// The compiler is pure Go and builds on any platform; only the Apply step
// (in apply_linux.go) actually installs the filter via syscall. On other
// platforms Apply returns ErrUnsupportedPlatform — useful for unit tests
// and dev environments.
//
// Filter shape (architecturally):
//
//	1. load arch from offset 4   (seccomp_data.arch)
//	2. cmp against expected arch; on mismatch -> allow (we don't try to
//	   handle multi-arch; misbehaved arch reaches the next layer)
//	3. load nr   from offset 0   (seccomp_data.nr)
//	4. for each denied syscall: cmp; on equal -> return EPERM
//	5. fallthrough -> return ALLOW
//
// EPERM rather than KILL_PROCESS is deliberate: we want the syscall to
// return -1, not the whole process to disappear. The choke gateway can
// always escalate to a kill via the Severer.
package seccomp

import (
	"encoding/binary"
	"fmt"

	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
)

// Linux cBPF / seccomp constants. Defined here so the compiler builds on
// non-Linux dev hosts.
const (
	bpfLD     = 0x00
	bpfJMP    = 0x05
	bpfRET    = 0x06
	bpfW      = 0x00 // 32-bit word
	bpfABS    = 0x20
	bpfK      = 0x00
	bpfJEQ    = 0x10

	// seccomp data layout (struct seccomp_data): nr@0, arch@4, ip@8, args@16
	seccompNR   = 0
	seccompArch = 4

	// seccomp return values
	secRetAllow = 0x7fff0000
	secRetErrno = 0x00050000 // SECCOMP_RET_ERRNO
	epermErrno  = 0x00000001
)

// SockFilter mirrors the kernel's struct sock_filter so the slice can be
// handed to prctl unchanged. Stable layout: code(2) jt(1) jf(1) k(4).
type SockFilter struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// Filter is a compiled program plus the policy metadata it came from.
type Filter struct {
	PolicyName string
	Insns      []SockFilter
	// Denied is a sorted list of syscall numbers the filter rejects.
	Denied []uint32
}

// Compile turns the deny lists from one or more policies into a single
// merged filter targeting the given arch (use ArchAMD64 / ArchARM64 from
// the constants below). Unknown syscall names are skipped with an entry
// in the returned warnings slice — non-fatal because syscall tables drift
// between kernel versions and the operator should know which names didn't
// resolve, but we should still install the rest.
func Compile(arch uint32, policies []policy.Policy) (*Filter, []string, error) {
	denied := map[uint32]struct{}{}
	var warnings []string
	for _, p := range policies {
		for _, name := range p.DenySyscalls {
			nr, ok := SyscallTable[arch][name]
			if !ok {
				warnings = append(warnings,
					fmt.Sprintf("policy %s: syscall %q unknown for arch 0x%x", p.Metadata.Name, name, arch))
				continue
			}
			denied[nr] = struct{}{}
		}
	}
	if len(denied) == 0 {
		return nil, warnings, fmt.Errorf("no denied syscalls (after resolving names) — refusing to install empty filter")
	}

	// Sort for determinism (helps tests + audit).
	sorted := make([]uint32, 0, len(denied))
	for nr := range denied {
		sorted = append(sorted, nr)
	}
	sortU32(sorted)

	insns := make([]SockFilter, 0, 6+2*len(sorted))

	// 1. load arch from offset 4
	insns = append(insns, SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompArch})
	// 2. if arch != expected -> allow (jt=skip-to-allow, jf=fall-through)
	//    We compute jt as the offset to the final ALLOW return; updated below.
	insns = append(insns, SockFilter{Code: bpfJMP | bpfJEQ | bpfK, K: arch, JT: 1, JF: 0})
	insns = append(insns, SockFilter{Code: bpfRET | bpfK, K: secRetAllow})
	// 3. load nr from offset 0
	insns = append(insns, SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompNR})

	// 4. for each denied syscall, JEQ -> ret EPERM
	for _, nr := range sorted {
		// JEQ jt=1 (skip the fall-through), jf=0 (continue checking next nr)
		insns = append(insns, SockFilter{Code: bpfJMP | bpfJEQ | bpfK, K: nr, JT: 0, JF: 1})
		insns = append(insns, SockFilter{Code: bpfRET | bpfK, K: secRetErrno | epermErrno})
	}

	// 5. fallthrough -> allow
	insns = append(insns, SockFilter{Code: bpfRET | bpfK, K: secRetAllow})

	return &Filter{Insns: insns, Denied: sorted}, warnings, nil
}

// Bytes serialises the compiled program in the on-the-wire format the
// kernel expects (little-endian, packed). Use this when exporting to a
// file for offline review or for handing to the apply step.
func (f *Filter) Bytes() []byte {
	out := make([]byte, 0, len(f.Insns)*8)
	for _, in := range f.Insns {
		var buf [8]byte
		binary.LittleEndian.PutUint16(buf[0:2], in.Code)
		buf[2] = in.JT
		buf[3] = in.JF
		binary.LittleEndian.PutUint32(buf[4:8], in.K)
		out = append(out, buf[:]...)
	}
	return out
}

func sortU32(s []uint32) {
	// in-place insertion sort; n is tiny (the number of denied syscalls)
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
