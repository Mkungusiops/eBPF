//go:build !linux

package sysproc

// ReadDetail is a no-op on non-Linux platforms. The dev build (macOS) does
// not have /proc, so the inspect drawer simply renders without live state.
func ReadDetail(pid uint32) (Detail, error) {
	return Detail{PID: pid}, nil
}
