//go:build !linux

package bpfmap

import "errors"

// CiliumEBPFBackend stub for non-Linux dev hosts. Construction is fine;
// Open returns ErrUnsupported so main.go can fall back to the noop
// backend and keep the engine running on macOS for UI/scoring iteration.
type CiliumEBPFBackend struct{}

// ErrUnsupported is returned when Open() is called on a non-Linux build.
var ErrUnsupported = errors.New("bpfmap: cilium backend requires linux")

func NewCiliumEBPFBackend(objPath, cgroupDir string) *CiliumEBPFBackend {
	return &CiliumEBPFBackend{}
}

func (c *CiliumEBPFBackend) Open() error                    { return ErrUnsupported }
func (c *CiliumEBPFBackend) Close() error                   { return nil }
func (c *CiliumEBPFBackend) Update(uint32, PIDBucket) error { return ErrUnsupported }
func (c *CiliumEBPFBackend) Delete(uint32) error            { return ErrUnsupported }
func (c *CiliumEBPFBackend) Snapshot() (map[uint32]PIDBucket, error) {
	return nil, ErrUnsupported
}
func (c *CiliumEBPFBackend) AttachedLinks() int { return 0 }
