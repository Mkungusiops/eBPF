//go:build !linux

package devbpf

import "errors"

// CiliumTCBackend stub for non-Linux dev hosts. Construction is fine; Open
// returns ErrUnsupported so main.go can fall back to the noop device
// backend and keep the engine running on macOS for UI/scoring iteration.
type CiliumTCBackend struct{}

// ErrUnsupported is returned when Open() is called on a non-Linux build.
var ErrUnsupported = errors.New("devbpf: tc backend requires linux")

func NewCiliumTCBackend(objPath string, ifaces []string) *CiliumTCBackend {
	return &CiliumTCBackend{}
}

func (c *CiliumTCBackend) Open() error                    { return ErrUnsupported }
func (c *CiliumTCBackend) Close() error                   { return nil }
func (c *CiliumTCBackend) Update(MAC, DeviceBucket) error { return ErrUnsupported }
func (c *CiliumTCBackend) Delete(MAC) error               { return ErrUnsupported }
func (c *CiliumTCBackend) Snapshot() (map[MAC]DeviceBucket, error) {
	return nil, ErrUnsupported
}
func (c *CiliumTCBackend) SeenSnapshot() (map[MAC]Seen, error)          { return nil, nil }
func (c *CiliumTCBackend) FlowsSnapshot() (map[FlowKey]FlowStat, error) { return nil, nil }
func (c *CiliumTCBackend) AttachedLinks() int                           { return 0 }
func (c *CiliumTCBackend) DataPlaneTier() string                        { return "tc" }
