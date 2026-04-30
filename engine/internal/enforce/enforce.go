// Package enforce contains the actuators that turn circuit decisions into
// concrete effects on a running system: throttle, tarpit, quarantine, sever.
//
// The package is split into a small interface (Enforcer) plus several
// backends. Backends are composable via Multi — typically you stack a
// userspace severer (kill(2)) with a kernel-level BPF/seccomp backend so
// that a single Decision triggers both an immediate process termination
// and an updated kernel choke map.
package enforce

import (
	"context"
	"errors"
	"log"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

// Target identifies the process to act on. ExecID is the canonical key
// (stable across PID reuse); PID is what the OS understands; Binary is for
// logging.
type Target struct {
	ExecID string
	PID    uint32
	Binary string
}

// Enforcer applies a circuit Action to a Target. Implementations must be
// idempotent — the circuit may re-emit the same decision after a daemon
// restart.
type Enforcer interface {
	Apply(ctx context.Context, t Target, action circuit.Action, reason string) error
	Name() string
}

// ErrUnsupported is returned when a backend cannot perform the requested
// action (e.g. asking the userspace severer to throttle bandwidth, which
// is the BPF backend's job). It is non-fatal: Multi treats it as "next
// backend please".
var ErrUnsupported = errors.New("enforcement action not supported by this backend")

// Multi fans out an action to several backends in order. The first backend
// that can handle the action runs; ErrUnsupported is treated as a skip.
// Any other error halts the chain and is returned.
type Multi struct {
	Backends []Enforcer
}

func (m *Multi) Name() string { return "multi" }

func (m *Multi) Apply(ctx context.Context, t Target, action circuit.Action, reason string) error {
	handled := false
	for _, b := range m.Backends {
		err := b.Apply(ctx, t, action, reason)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		handled = true
		if err != nil {
			return err
		}
	}
	if !handled {
		return ErrUnsupported
	}
	return nil
}

// Logger is a backend that does nothing but record decisions. Useful for
// dry-run mode and for the macOS dev environment where the real kernel
// backends aren't available.
type Logger struct {
	Prefix string
}

func (l *Logger) Name() string { return "logger" }

func (l *Logger) Apply(_ context.Context, t Target, action circuit.Action, reason string) error {
	prefix := l.Prefix
	if prefix == "" {
		prefix = "[enforce-dry-run]"
	}
	log.Printf("%s action=%s exec_id=%s pid=%d binary=%s reason=%q",
		prefix, action, t.ExecID, t.PID, t.Binary, reason)
	return nil
}

// DryRun wraps an Enforcer so that Apply is a no-op (but still logged).
// This is the audit-safe way to roll a new policy out: decisions are
// recorded in the store, but no syscall fires. Flip dryRun=false after an
// observation window.
type DryRun struct {
	Wrapped Enforcer
}

func (d *DryRun) Name() string {
	if d.Wrapped == nil {
		return "dry-run"
	}
	return "dry-run(" + d.Wrapped.Name() + ")"
}

func (d *DryRun) Apply(_ context.Context, t Target, action circuit.Action, reason string) error {
	log.Printf("[enforce-dry-run] would invoke %s on exec_id=%s pid=%d binary=%s action=%s reason=%q",
		d.wrappedName(), t.ExecID, t.PID, t.Binary, action, reason)
	return nil
}

func (d *DryRun) wrappedName() string {
	if d.Wrapped == nil {
		return "<nil>"
	}
	return d.Wrapped.Name()
}
