//go:build linux

package cgroupv2

import (
	"context"
	"errors"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
)

// Backend is the enforce.Enforcer that turns Decisions into cgroup v2
// operations. ActSever is rejected with enforce.ErrUnsupported so a
// Multi() chain dispatches it to the Severer (which sends SIGKILL).
type Backend struct {
	Mgr *Manager
}

// NewBackend builds a Linux cgroup v2 backend at the given root. Pass
// "" for the default /sys/fs/cgroup. Setup is NOT called automatically —
// run b.Mgr.Setup() once after construction (typically right after main()
// parses flags) so the cgroups exist before the first Decision lands.
func NewBackend(root string) *Backend {
	return &Backend{Mgr: NewManager(root)}
}

func (b *Backend) Name() string { return "cgroupv2" }

func (b *Backend) Apply(_ context.Context, t enforce.Target, a circuit.Action, _ string) error {
	if a == circuit.ActSever || a == circuit.ActNone {
		return enforce.ErrUnsupported
	}
	if err := b.Mgr.MoveTo(t.PID, a); err != nil {
		if errors.Is(err, ErrUnsupported) {
			return enforce.ErrUnsupported
		}
		return err
	}
	return nil
}

// Available reports whether a real cgroup v2 hierarchy is mounted at the
// configured root. Use to decide whether to skip Setup() and fall back
// to detect-only.
func (b *Backend) Available() bool { return IsCgroupV2(b.Mgr.root) }
