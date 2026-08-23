//go:build !linux

package sysproc

// ResolveExe is Linux-only; every other build reports "unknown" and the caller
// falls back to the path the kernel reported.
//
// This exists because Tetragon reports the executable as the kernel sees it,
// and for a process that re-exec'd through a file descriptor that is
// "/proc/self/fd/9" — not a path, and not an identity. Measured on the live
// engine 2026-08-21: systemd's own re-exec (`--deserialize 43`, parent PID 1)
// read /etc/passwd and /etc/shadow eleven times and scored 109, CRITICAL,
// attributed on the console to "/proc/self/fd/9". No path-based rule can
// recognise that as systemd, and no analyst can act on that process name.
func ResolveExe(pid uint32) string { return "" }
