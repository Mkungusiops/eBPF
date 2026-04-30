package enforce

import (
	"context"
	"fmt"
	"syscall"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// Severer terminates processes. It handles only the ActSever action; every
// other action returns ErrUnsupported so a Multi backend can dispatch
// throttle/tarpit/quarantine elsewhere.
//
// Cross-platform: syscall.Kill exists on darwin, linux, freebsd, etc. On
// non-Linux dev machines kill against arbitrary PIDs typically fails with
// EPERM — that's acceptable; the production deploy is Linux.
type Severer struct {
	// Signal is the signal sent for ActSever. Defaults to SIGKILL when zero.
	Signal syscall.Signal
}

func (s *Severer) Name() string { return "severer" }

func (s *Severer) Apply(_ context.Context, t Target, action circuit.Action, reason string) error {
	if action != circuit.ActSever {
		return ErrUnsupported
	}
	if t.PID == 0 {
		return fmt.Errorf("severer: refusing to kill PID 0 (exec_id=%s)", t.ExecID)
	}
	sig := s.Signal
	if sig == 0 {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(int(t.PID), sig); err != nil {
		// ESRCH means the process is already gone — that's success for our
		// purposes (the goal is "this process is no longer running").
		if err == syscall.ESRCH {
			return nil
		}
		return fmt.Errorf("severer: kill(%d, %v): %w", t.PID, sig, err)
	}
	return nil
}
