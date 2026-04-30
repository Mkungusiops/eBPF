package enforce

import (
	"context"
	"errors"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
)

func TestThrottlerWritesPIDBucketsPerAction(t *testing.T) {
	be := bpfmap.NewNoopBackend()
	if err := be.Open(); err != nil {
		t.Fatal(err)
	}
	tr := &Throttler{Backend: be}
	cases := []struct {
		action   circuit.Action
		wantFlag uint32
	}{
		{circuit.ActThrottle, bpfmap.FlagThrottle},
		{circuit.ActTarpit, bpfmap.FlagTarpit},
		{circuit.ActQuarantine, bpfmap.FlagQuarantine},
	}
	for i, c := range cases {
		pid := uint32(100 + i)
		if err := tr.Apply(context.Background(), Target{PID: pid}, c.action, ""); err != nil {
			t.Errorf("apply %s: %v", c.action, err)
			continue
		}
		snap, _ := be.Snapshot()
		got, ok := snap[pid]
		if !ok {
			t.Errorf("action %s did not write pid %d", c.action, pid)
			continue
		}
		if got.Flags&c.wantFlag == 0 {
			t.Errorf("action %s wrote flags %#x, want bit %#x set", c.action, got.Flags, c.wantFlag)
		}
		if got.RatePerSec == 0 || got.Burst == 0 {
			t.Errorf("action %s: rate/burst should be non-zero, got %+v", c.action, got)
		}
	}
}

func TestThrottlerRejectsSever(t *testing.T) {
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	tr := &Throttler{Backend: be}
	err := tr.Apply(context.Background(), Target{PID: 1}, circuit.ActSever, "")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("throttler must refuse sever, got %v", err)
	}
}

func TestThrottlerRejectsPID0(t *testing.T) {
	be := bpfmap.NewNoopBackend()
	_ = be.Open()
	tr := &Throttler{Backend: be}
	err := tr.Apply(context.Background(), Target{PID: 0}, circuit.ActThrottle, "")
	if err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("throttler must refuse pid 0, got %v", err)
	}
}

func TestThrottlerWithoutBackendReportsUnsupported(t *testing.T) {
	tr := &Throttler{}
	err := tr.Apply(context.Background(), Target{PID: 1}, circuit.ActThrottle, "")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected ErrUnsupported with nil backend, got %v", err)
	}
}
