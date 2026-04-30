//go:build !linux

package seccomp

import "errors"

// ErrUnsupportedPlatform is returned when seccomp install is attempted on
// a non-Linux host. The compiled filter is still useful: callers can
// inspect Insns/Bytes for tests, export, or hand off to a Linux subagent.
var ErrUnsupportedPlatform = errors.New("seccomp: only supported on Linux")

// ApplyToSelf is a no-op stub on non-Linux platforms.
func (f *Filter) ApplyToSelf() error { return ErrUnsupportedPlatform }

// HostArch returns the canonical default (x86_64) on non-Linux platforms
// so the compiler can still produce useful filters during development.
func HostArch() uint32 { return ArchAMD64 }
