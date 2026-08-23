package findings

import (
	"testing"
	"time"
)

func TestFindingsRingRecordsBothKindsAndBounds(t *testing.T) {
	r := NewRing()
	for i := 0; i < maxFindings+500; i++ {
		r.Add(Finding{At: time.Now(), Kind: "anomaly", ExecID: "e", Points: 1})
	}
	r.Add(Finding{At: time.Now(), Kind: "intel", ExecID: "e", Points: 30})

	if got := len(r.Recent("", maxFindings*2)); got > maxFindings {
		t.Fatalf("ring returned %d findings, above its %d bound", got, maxFindings)
	}
	if got := r.Recent("intel", 10); len(got) != 1 {
		t.Fatalf("kind filter returned %d intel findings", len(got))
	}
	// Lifetime totals must survive the wrap, or a busy host reads as a quiet one.
	an, ih := r.Totals()
	if an != maxFindings+500 || ih != 1 {
		t.Fatalf("lifetime totals lost to the wrap: anomalies=%d intel=%d", an, ih)
	}
	// Newest first.
	if got := r.Recent("", 1); len(got) != 1 || got[0].Kind != "intel" {
		t.Fatalf("Recent must return newest first, got %+v", got)
	}
}
