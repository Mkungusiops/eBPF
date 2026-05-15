package origin

import (
	"testing"
	"time"
)

func TestTrackerRecordAndLookup(t *testing.T) {
	tr := NewTracker(time.Hour)
	tr.Record(123, Origin{Kind: KindSSH, RemoteIP: "1.2.3.4", RemotePort: 51000, User: "alice"})

	got, ok := tr.Lookup(123, nil)
	if !ok {
		t.Fatalf("Lookup(123): want hit")
	}
	if got.RemoteIP != "1.2.3.4" || got.User != "alice" || got.Kind != KindSSH {
		t.Errorf("Lookup(123) = %+v", got)
	}
	if got.FirstSeen.IsZero() {
		t.Errorf("FirstSeen should be backfilled by Record")
	}
}

func TestTrackerMergeOnSecondWrite(t *testing.T) {
	tr := NewTracker(time.Hour)
	// First write: accept event delivers IP+port.
	tr.Record(456, Origin{Kind: KindSSH, RemoteIP: "5.6.7.8", RemotePort: 22222})
	// Second write: sshd journald tailer arrives ~ms later with key fp.
	tr.Record(456, Origin{Fingerprint: "ED25519 SHA256:abc", User: "bob"})

	got, _ := tr.Lookup(456, nil)
	if got.RemoteIP != "5.6.7.8" {
		t.Errorf("merge wiped RemoteIP: %+v", got)
	}
	if got.Fingerprint != "ED25519 SHA256:abc" {
		t.Errorf("merge dropped Fingerprint: %+v", got)
	}
	if got.User != "bob" {
		t.Errorf("merge dropped User: %+v", got)
	}
}

func TestTrackerLookupWalksAncestors(t *testing.T) {
	tr := NewTracker(time.Hour)
	tr.Record(1000, Origin{Kind: KindSSH, RemoteIP: "9.9.9.9"}) // per-session sshd
	// 1000 → 1001 (bash) → 1002 (curl). Looking up 1002 should hit 1000.
	ancestors := func(pid uint32) []uint32 {
		switch pid {
		case 1002:
			return []uint32{1001, 1000}
		case 1001:
			return []uint32{1000}
		}
		return nil
	}
	got, ok := tr.Lookup(1002, ancestors)
	if !ok || got.RemoteIP != "9.9.9.9" {
		t.Errorf("ancestor walk failed: got=%+v ok=%v", got, ok)
	}
}

func TestTrackerLookupMissReturnsFalse(t *testing.T) {
	tr := NewTracker(time.Hour)
	_, ok := tr.Lookup(7, func(uint32) []uint32 { return []uint32{8, 9} })
	if ok {
		t.Errorf("expected miss on empty tracker")
	}
}

func TestTrackerSweepEvictsStale(t *testing.T) {
	tr := NewTracker(10 * time.Second)
	base := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return base }
	tr.Record(1, Origin{RemoteIP: "1.1.1.1"})

	tr.now = func() time.Time { return base.Add(20 * time.Second) }
	tr.Record(2, Origin{RemoteIP: "2.2.2.2"})

	tr.now = func() time.Time { return base.Add(25 * time.Second) }
	n := tr.Sweep()
	if n != 1 {
		t.Errorf("expected to evict 1 stale entry, got %d", n)
	}
	if _, ok := tr.Lookup(1, nil); ok {
		t.Errorf("pid 1 should have been swept")
	}
	if _, ok := tr.Lookup(2, nil); !ok {
		t.Errorf("pid 2 should still be present")
	}
}

func TestTrackerForget(t *testing.T) {
	tr := NewTracker(time.Hour)
	tr.Record(42, Origin{RemoteIP: "4.2.4.2"})
	tr.Forget(42)
	if _, ok := tr.Lookup(42, nil); ok {
		t.Errorf("Forget(42) should drop the entry")
	}
}

func TestOriginHasAttribution(t *testing.T) {
	if (Origin{}).HasAttribution() {
		t.Errorf("empty Origin should not report attribution")
	}
	if !(Origin{RemoteIP: "1.1.1.1"}).HasAttribution() {
		t.Errorf("Origin with RemoteIP should report attribution")
	}
	if !(Origin{Fingerprint: "x"}).HasAttribution() {
		t.Errorf("Origin with Fingerprint should report attribution")
	}
}
