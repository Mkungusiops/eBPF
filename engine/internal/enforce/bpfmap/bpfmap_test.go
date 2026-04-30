package bpfmap

import (
	"errors"
	"testing"
)

func TestNoopBackendLifecycle(t *testing.T) {
	b := NewNoopBackend()
	// Operations before Open must fail with ErrClosed.
	if err := b.Update(1, PIDBucket{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("update before open: %v want ErrClosed", err)
	}
	if err := b.Open(); err != nil {
		t.Fatalf("open: %v", err)
	}
	bk := PIDBucket{RatePerSec: 100, Burst: 200, Flags: FlagThrottle}
	if err := b.Update(42, bk); err != nil {
		t.Fatalf("update: %v", err)
	}
	snap, err := b.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got, ok := snap[42]; !ok || got.RatePerSec != 100 || got.Flags&FlagThrottle == 0 {
		t.Fatalf("snapshot mismatch: %+v", got)
	}
	if err := b.Delete(42); err != nil {
		t.Fatalf("delete: %v", err)
	}
	snap2, _ := b.Snapshot()
	if _, ok := snap2[42]; ok {
		t.Fatalf("delete didn't remove pid 42")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := b.Update(1, PIDBucket{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("update after close: %v want ErrClosed", err)
	}
}

func TestActionFlagsAreDistinct(t *testing.T) {
	flags := []uint32{FlagThrottle, FlagTarpit, FlagQuarantine, FlagSever}
	seen := map[uint32]bool{}
	for _, f := range flags {
		if seen[f] {
			t.Errorf("duplicate flag value %#x", f)
		}
		seen[f] = true
	}
}
