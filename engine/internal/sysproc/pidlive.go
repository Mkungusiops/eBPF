package sysproc

import (
	"errors"
	"syscall"
)

// PIDLive reports whether a PID is a live process on this host.
//
// signal 0 does no work but still runs the kernel's permission check, so EPERM
// means the process exists and belongs to someone else; only ESRCH means "not
// here". Reading /proc/<pid> would answer the same question with a syscall per
// component and a race against the directory disappearing mid-read.
//
// Shared rather than duplicated: the agent has always had this as the evidence
// behind Gateway.Owns, and the engine now needs the identical answer to reap
// choke-map rows for dead processes. Two implementations of "is this process
// alive" would eventually disagree, and the direction that disagreement fails
// is deleting the enforcement state of a process that is still running.
func PIDLive(pid uint32) bool {
	if pid == 0 {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
