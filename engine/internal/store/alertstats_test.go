package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The console cannot compute these itself for any window longer than its record
// buffer spans, and it cannot compute the "vs prior" delta at all — the
// preceding window is never in the buffer. These pin both.
func TestAlertStatsCountsWindowAndPriorWindow(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	from := now.Add(-30 * time.Minute)

	// 3 critical + 1 high inside the window; 2 medium in the PRIOR window; and
	// one alert older than both, which must be counted in neither.
	insert := func(at time.Time, sev string) {
		t.Helper()
		if _, err := s.InsertAlert(&Alert{Timestamp: at, Severity: sev, Title: sev}); err != nil {
			t.Fatal(err)
		}
	}
	insert(now.Add(-1*time.Minute), "critical")
	insert(now.Add(-10*time.Minute), "critical")
	insert(now.Add(-29*time.Minute), "critical")
	insert(now.Add(-5*time.Minute), "high")
	insert(now.Add(-35*time.Minute), "medium")
	insert(now.Add(-50*time.Minute), "medium")
	insert(now.Add(-3*time.Hour), "critical") // outside both windows

	stats, err := s.AlertStats(from, now, 30)
	if err != nil {
		t.Fatal(err)
	}

	if stats.Counts["critical"] != 3 {
		t.Errorf("counts.critical = %d, want 3", stats.Counts["critical"])
	}
	if stats.Counts["high"] != 1 {
		t.Errorf("counts.high = %d, want 1", stats.Counts["high"])
	}
	if stats.Counts["medium"] != 0 {
		t.Errorf("counts.medium = %d, want 0 (those are in the prior window)", stats.Counts["medium"])
	}
	if stats.Total != 4 {
		t.Errorf("total = %d, want 4", stats.Total)
	}
	// The delta's whole purpose: a real comparison against the preceding window.
	if stats.Previous["medium"] != 2 {
		t.Errorf("previous.medium = %d, want 2", stats.Previous["medium"])
	}
	if stats.Previous["critical"] != 0 {
		t.Errorf("previous.critical = %d, want 0 (the 3h-old alert is outside both)", stats.Previous["critical"])
	}
}

// Every severity key is always present, so the console never has to tell "zero"
// apart from "absent".
func TestAlertStatsAlwaysPopulatesEverySeverity(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now().UTC()
	stats, err := s.AlertStats(now.Add(-time.Hour), now, 12)
	if err != nil {
		t.Fatal(err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := stats.Counts[sev]; !ok {
			t.Errorf("counts missing key %q", sev)
		}
		if _, ok := stats.Previous[sev]; !ok {
			t.Errorf("previous missing key %q", sev)
		}
	}
	if len(stats.Buckets) != 12 {
		t.Fatalf("got %d buckets, want 12", len(stats.Buckets))
	}
}

// Buckets must tile the window and account for every alert in it — the timeline
// is read as a distribution, so a misplaced bucket misreads as a quiet period.
func TestAlertStatsBucketsTileTheWindow(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	now := time.Now().UTC().Truncate(time.Second)
	from := now.Add(-60 * time.Minute)
	for i := 0; i < 6; i++ {
		at := from.Add(time.Duration(i)*10*time.Minute + time.Minute)
		if _, err := s.InsertAlert(&Alert{Timestamp: at, Severity: "high", Title: "x"}); err != nil {
			t.Fatal(err)
		}
	}

	stats, err := s.AlertStats(from, now, 6) // 10-minute buckets
	if err != nil {
		t.Fatal(err)
	}
	summed := 0
	for i, b := range stats.Buckets {
		if b.Total != 1 {
			t.Errorf("bucket %d total = %d, want 1", i, b.Total)
		}
		summed += b.Total
	}
	if summed != stats.Total {
		t.Fatalf("buckets sum to %d but total is %d", summed, stats.Total)
	}
}
