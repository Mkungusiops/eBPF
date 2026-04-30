//go:build !linux

package cgroupv2

import (
	"context"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
)

// Backend on non-Linux is a stub that always reports the action as
// unsupported. Lets the engine compile on macOS for development without
// pulling in /sys/fs/cgroup file paths it can't satisfy.
type Backend struct {
	Mgr *Manager
}

func NewBackend(root string) *Backend { return &Backend{Mgr: NewManager(root)} }

func (b *Backend) Name() string { return "cgroupv2-stub" }

func (b *Backend) Apply(_ context.Context, _ enforce.Target, _ circuit.Action, _ string) error {
	return enforce.ErrUnsupported
}

func (b *Backend) Available() bool { return false }
