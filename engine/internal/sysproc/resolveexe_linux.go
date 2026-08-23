//go:build linux

package sysproc

import (
	"os"
	"path/filepath"
	"strconv"
)

// ResolveExe returns the real executable path behind a PID, from
// /proc/<pid>/exe.
//
// Callers use it when the path the KERNEL reported is not an identity — see
// the doc on the non-Linux stub. Returns "" when the process is already gone
// or the link is unreadable, which the caller must treat as "unknown" rather
// than substituting anything.
func ResolveExe(pid uint32) string {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe"))
	if err != nil {
		return ""
	}
	// A deleted or memfd-backed binary reads back with a suffix or a
	// non-filesystem prefix. Neither is a path a rule can reason about, and
	// both are worth NOT silently normalising away: returning "" leaves the
	// caller on the kernel-reported path, which is the honest fallback.
	if filepath.IsAbs(exe) && exe[0] == '/' && exe != "/" {
		return exe
	}
	return ""
}
