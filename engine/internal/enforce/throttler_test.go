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

// Release must clear the kernel token bucket. Moving the pid into the pristine
// cgroup lifts the cgroup limits, but the BPF bucket is a separate data plane:
// if it survives, a "released" process is still silently rate-limited.
func TestThrottlerReleaseClearsBucket(t *testing.T) {
	be := bpfmap.NewNoopBackend()
	if err := be.Open(); err != nil {
		t.Fatal(err)
	}
	tr := &Throttler{Backend: be}
	const pid = uint32(4242)

	if err := tr.Apply(context.Background(), Target{PID: pid}, circuit.ActThrottle, ""); err != nil {
		t.Fatalf("throttle: %v", err)
	}
	if snap, _ := be.Snapshot(); snap[pid].Flags == 0 {
		t.Fatalf("precondition: throttle should have written a bucket for pid %d", pid)
	}

	if err := tr.Apply(context.Background(), Target{PID: pid}, circuit.ActNone, ""); err != nil {
		t.Fatalf("release: %v", err)
	}
	snap, _ := be.Snapshot()
	if _, still := snap[pid]; still {
		t.Errorf("release left a bucket for pid %d — the process is still throttled in the data plane", pid)
	}
}
