package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
)

type stubBackend struct {
	name    string
	handles map[circuit.Action]bool
	err     error
	calls   int
}

func (s *stubBackend) Name() string { return s.name }
func (s *stubBackend) Apply(_ context.Context, _ Target, a circuit.Action, _ string) error {
	if !s.handles[a] {
		return ErrUnsupported
	}
	s.calls++
	return s.err
}

func TestMultiSkipsUnsupportedAndStopsOnHandle(t *testing.T) {
	a := &stubBackend{name: "a", handles: map[circuit.Action]bool{circuit.ActSever: true}}
	b := &stubBackend{name: "b", handles: map[circuit.Action]bool{circuit.ActThrottle: true}}
	m := &Multi{Backends: []Enforcer{a, b}}

	if err := m.Apply(context.Background(), Target{PID: 1}, circuit.ActThrottle, ""); err != nil {
		t.Fatalf("apply throttle: %v", err)
	}
	if a.calls != 0 {
		t.Errorf("backend a should not have been called for throttle (returned ErrUnsupported)")
	}
	if b.calls != 1 {
		t.Errorf("backend b should have been called once, got %d", b.calls)
	}

	if err := m.Apply(context.Background(), Target{PID: 1}, circuit.ActSever, ""); err != nil {
		t.Fatalf("apply sever: %v", err)
	}
	if a.calls != 1 {
		t.Errorf("backend a should have been called for sever, got %d", a.calls)
	}
}

func TestMultiPropagatesError(t *testing.T) {
	boom := errors.New("boom")
	a := &stubBackend{name: "a", handles: map[circuit.Action]bool{circuit.ActSever: true}, err: boom}
	m := &Multi{Backends: []Enforcer{a}}
	if err := m.Apply(context.Background(), Target{PID: 1}, circuit.ActSever, ""); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestMultiAllUnsupportedReturnsUnsupported(t *testing.T) {
	a := &stubBackend{name: "a", handles: map[circuit.Action]bool{}}
	m := &Multi{Backends: []Enforcer{a}}
	err := m.Apply(context.Background(), Target{PID: 1}, circuit.ActSever, "")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported, got %v", err)
	}
}

func TestSevererRejectsNonSever(t *testing.T) {
	s := &Severer{}
	err := s.Apply(context.Background(), Target{PID: 1234}, circuit.ActThrottle, "")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("severer must refuse non-sever actions, got %v", err)
	}
}

func TestSevererRefusesPID0(t *testing.T) {
	s := &Severer{}
	err := s.Apply(context.Background(), Target{PID: 0, ExecID: "X"}, circuit.ActSever, "")
	if err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("severer must refuse PID 0, got %v", err)
	}
}

func TestLoggerAlwaysSucceeds(t *testing.T) {
	l := &Logger{}
	for _, a := range []circuit.Action{circuit.ActThrottle, circuit.ActTarpit, circuit.ActQuarantine, circuit.ActSever} {
		if err := l.Apply(context.Background(), Target{PID: 1, ExecID: "X"}, a, ""); err != nil {
			t.Errorf("logger action=%s err=%v", a, err)
		}
	}
}

func TestDryRunDoesNotCallWrapped(t *testing.T) {
	wrapped := &stubBackend{name: "real", handles: map[circuit.Action]bool{circuit.ActSever: true}}
	d := &DryRun{Wrapped: wrapped}
	if err := d.Apply(context.Background(), Target{PID: 1, ExecID: "X"}, circuit.ActSever, "test"); err != nil {
		t.Fatalf("dry-run apply: %v", err)
	}
	if wrapped.calls != 0 {
		t.Fatalf("dry-run must not invoke wrapped backend, got %d calls", wrapped.calls)
	}
}
