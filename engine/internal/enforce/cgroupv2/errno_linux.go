//go:build linux

package cgroupv2

import (
	"errors"
	"syscall"
)

func isESRCH(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ESRCH
	}
	return false
}
