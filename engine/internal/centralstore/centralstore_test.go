package centralstore

import (
	"path/filepath"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func eventRec(dedup, execID string) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{
		DedupKey: dedup,
		Payload:  &ebpfsocv1.TelemetryRecord_Event{Event: &ebpfsocv1.ProcessEvent{ExecId: execID, Binary: "/bin/sh"}},
	}
}

func put(t *testing.T, s *Store, tenant, agent, dedup, execID string) {
	t.Helper()
	if err := s.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: eventRec(dedup, execID)}); err != nil {
		t.Fatal(err)
	}
}

// TestCrossTenantReadDenial is the headline isolation gate (invariant §7 T3/T4
// at the storage layer): two tenants with IDENTICAL dedup keys and exec ids are
// physically separate; a scoped read returns only its own tenant's rows.
func TestCrossTenantReadDenial(t *testing.T) {
	s := open(t)
	// Identical natural keys across tenants — the fixture that catches code
	// keying on a natural id instead of (tenant_id, id).
	put(t, s, "tenant-a", "agent-a", "evt:1", "exec-1")
	put(t, s, "tenant-a", "agent-a", "evt:2", "exec-2")
	put(t, s, "tenant-b", "agent-b", "evt:1", "exec-1") // same keys, other tenant
	put(t, s, "tenant-b", "agent-b", "evt:3", "exec-3")

	aRows, err := s.Query(Scope{TenantID: "tenant-a"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(aRows) != 2 {
		t.Fatalf("tenant-a rows = %d, want 2", len(aRows))
	}
	for _, r := range aRows {
		if r.TenantID != "tenant-a" {
			t.Fatalf("tenant-a query returned a %q row — CROSS-TENANT LEAK", r.TenantID)
		}
	}
	if n, _ := s.Count(Scope{TenantID: "tenant-b"}); n != 2 {
		t.Fatalf("tenant-b count = %d, want 2", n)
	}
}

// TestReadWithoutScopeFailsClosed: no method returns rows without a tenant.
func TestReadWithoutScopeFailsClosed(t *testing.T) {
	s := open(t)
	put(t, s, "tenant-a", "agent-a", "evt:1", "exec-1")

	if _, err := s.Query(Scope{}, 100); err != ErrNoScope {
		t.Fatalf("Query with empty scope err = %v, want ErrNoScope", err)
	}
	if _, err := s.Count(Scope{}); err != ErrNoScope {
		t.Fatalf("Count with empty scope err = %v, want ErrNoScope", err)
	}
	if _, err := s.QueryAcross(nil, 100); err != ErrNoScope {
		t.Fatalf("QueryAcross(nil) err = %v, want ErrNoScope", err)
	}
}

// TestStorageDedup: idempotent on (tenant, agent, dedup_key) — a replay does not
// double-store (defense in depth with the collector's dedup).
func TestStorageDedup(t *testing.T) {
	s := open(t)
	put(t, s, "tenant-a", "agent-a", "evt:1", "exec-1")
	put(t, s, "tenant-a", "agent-a", "evt:1", "exec-1") // replay
	if n, _ := s.Count(Scope{TenantID: "tenant-a"}); n != 1 {
		t.Fatalf("count after replay = %d, want 1 (storage dedup)", n)
	}
}

// TestPutRejectsUnstamped: a record with no tenant is refused (the collector
// must stamp before storage).
func TestPutRejectsUnstamped(t *testing.T) {
	s := open(t)
	if err := s.Put(ingest.StampedRecord{TenantID: "", Record: eventRec("evt:1", "e")}); err == nil {
		t.Fatal("storing an unstamped record must fail")
	}
}

// TestQueryAcrossIsExplicit: the cross-tenant path returns exactly the named
// tenants' rows (the audited MSOC primitive; authorization is Layer 4).
func TestQueryAcrossIsExplicit(t *testing.T) {
	s := open(t)
	put(t, s, "tenant-a", "agent-a", "evt:1", "exec-1")
	put(t, s, "tenant-b", "agent-b", "evt:1", "exec-1")
	put(t, s, "tenant-c", "agent-c", "evt:1", "exec-1")

	rows, err := s.QueryAcross([]string{"tenant-a", "tenant-b"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("QueryAcross([a,b]) = %d rows, want 2 (never includes c)", len(rows))
	}
	for _, r := range rows {
		if r.TenantID == "tenant-c" {
			t.Fatal("QueryAcross leaked an un-named tenant")
		}
	}
}
