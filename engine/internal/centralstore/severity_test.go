package centralstore

import (
	"path/filepath"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Counting alerts in SQL is what makes a long window EXACT.
//
// The Go-side tally it replaces was bounded by a 200k scan limit; a 7-day view
// scans the window and the one before it, which on the live rig is 935,600
// alert rows — 4.7x the limit — so every count past a day was a floor.

func sevStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "cs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func putAlert(t *testing.T, st *Store, tenant, key, severity string, at time.Time) {
	t.Helper()
	rec := &ebpfsocv1.TelemetryRecord{
		DedupKey: key,
		Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
			Severity: severity, OccurredAt: timestamppb.New(at),
		}},
	}
	if err := st.Put(ingest.StampedRecord{TenantID: tenant, AgentID: "a1", Record: rec}); err != nil {
		t.Fatal(err)
	}
}

// putAlertAt writes a row with a controlled storage timestamp. The store
// stamps `at` itself on Put, so bucketing tests have to set it directly.
func putAlertAt(t *testing.T, st *Store, tenant, key, severity string, at time.Time) {
	t.Helper()
	putAlert(t, st, tenant, key, severity, at)
	if _, err := st.db.Exec(`UPDATE telemetry SET at = ? WHERE tenant_id = ? AND dedup_key = ?`,
		at.UnixNano(), tenant, key); err != nil {
		t.Fatal(err)
	}
}

func TestCountBySeverityAggregatesInSQL(t *testing.T) {
	st := sevStore(t)
	now := time.Now().UTC()
	for i, sev := range []string{"critical", "critical", "high", "medium", "info"} {
		putAlert(t, st, "acme", "k"+string(rune('a'+i)), sev, now)
	}
	// Another tenant's alerts must not be counted.
	putAlert(t, st, "other", "x1", "critical", now)

	got, err := st.CountBySeverity(Scope{TenantID: "acme"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got["critical"] != 2 || got["high"] != 1 || got["medium"] != 1 || got["info"] != 1 {
		t.Fatalf("counts = %v, want 2 critical / 1 high / 1 medium / 1 info", got)
	}
}

func TestCountBySeverityIsTenantScoped(t *testing.T) {
	st := sevStore(t)
	now := time.Now().UTC()
	putAlert(t, st, "acme", "k1", "critical", now)

	got, err := st.CountBySeverity(Scope{TenantID: "other"}, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("another tenant saw %v", got)
	}
	if _, err := st.CountBySeverity(Scope{}, now, now); err != ErrNoScope {
		t.Fatalf("an unscoped count must be refused, got %v", err)
	}
}

func TestCountRespectsTheWindowBounds(t *testing.T) {
	st := sevStore(t)
	now := time.Now().UTC()
	putAlert(t, st, "acme", "in", "critical", now)

	// [from, to) — the upper bound is exclusive, so a row exactly at `to` is
	// the NEXT window's, not this one's. Off by one here double-counts every
	// boundary row when the console polls adjacent windows.
	got, _ := st.CountBySeverity(Scope{TenantID: "acme"}, now.Add(-time.Minute), now)
	if got["critical"] != 0 {
		t.Fatalf("row at the exclusive upper bound was counted: %v", got)
	}
	got, _ = st.CountBySeverity(Scope{TenantID: "acme"}, now, now.Add(time.Minute))
	if got["critical"] != 1 {
		t.Fatalf("row at the inclusive lower bound was missed: %v", got)
	}
}

// TestSeverityBucketsAreGroupedInSQL: the timeline must come back as
// buckets x severities rows, not one row per alert. Streaming every alert to
// bucket it in Go cost ~1.4s of a 7-day request and grew with the window.
func TestSeverityBucketsAreGroupedInSQL(t *testing.T) {
	st := sevStore(t)
	base := time.Now().UTC().Truncate(time.Hour)
	from, to := base, base.Add(4*time.Hour)
	// One alert per hour, alternating severity.
	for i := 0; i < 4; i++ {
		sev := "critical"
		if i%2 == 1 {
			sev = "high"
		}
		putAlertAt(t, st, "acme", "k"+string(rune('a'+i)), sev, from.Add(time.Duration(i)*time.Hour))
	}

	cols, err := st.SeverityBuckets(Scope{TenantID: "acme"}, from, to, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 4 {
		t.Fatalf("got %d buckets, want 4", len(cols))
	}
	for i, want := range []string{"critical", "high", "critical", "high"} {
		if cols[i][want] != 1 {
			t.Fatalf("bucket %d = %v, want one %s", i, cols[i], want)
		}
	}
}

// TestSeverityBucketsClampTheUpperBound: integer division puts a row landing
// exactly on `to` one index past the end; it must clamp, not panic or vanish.
func TestSeverityBucketsClampTheUpperBound(t *testing.T) {
	st := sevStore(t)
	base := time.Now().UTC().Truncate(time.Hour)
	putAlertAt(t, st, "acme", "edge", "critical", base.Add(2*time.Hour).Add(-time.Nanosecond))
	cols, err := st.SeverityBuckets(Scope{TenantID: "acme"}, base, base.Add(2*time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}
	if cols[1]["critical"] != 1 {
		t.Fatalf("edge row landed in %v", cols)
	}
}

// TestIngestStampsSeverity: new rows must never need the backfill.
func TestIngestStampsSeverity(t *testing.T) {
	st := sevStore(t)
	putAlert(t, st, "acme", "k1", "critical", time.Now().UTC())

	pending, err := st.SeverityBackfillPending(Scope{TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("%d freshly ingested rows lack a severity — ingest is not stamping it", pending)
	}
}

// TestBackfillIsIdempotentAndResumable: it only ever touches NULL rows, so a
// restart mid-migration continues rather than redoing work, and a finished one
// costs a single probe.
func TestBackfillIsIdempotentAndResumable(t *testing.T) {
	st := sevStore(t)
	now := time.Now().UTC()
	putAlert(t, st, "acme", "k1", "critical", now)

	// Simulate rows written before the column existed.
	if _, err := st.db.Exec(`UPDATE telemetry SET severity = NULL`); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.SeverityBackfillPending(Scope{TenantID: "acme"}); n != 1 {
		t.Fatalf("pending = %d, want 1", n)
	}

	backfillSeverity(st.db, "sqlite")
	if n, _ := st.SeverityBackfillPending(Scope{TenantID: "acme"}); n != 0 {
		t.Fatalf("pending = %d after backfill, want 0", n)
	}
	got, _ := st.CountBySeverity(Scope{TenantID: "acme"}, now.Add(-time.Hour), now.Add(time.Hour))
	if got["critical"] != 1 {
		t.Fatalf("backfill did not recover severity from the payload: %v", got)
	}

	// Running again must be a no-op, not a rewrite.
	backfillSeverity(st.db, "sqlite")
	got, _ = st.CountBySeverity(Scope{TenantID: "acme"}, now.Add(-time.Hour), now.Add(time.Hour))
	if got["critical"] != 1 {
		t.Fatalf("second backfill changed the data: %v", got)
	}
}
