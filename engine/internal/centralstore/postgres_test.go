package centralstore

import (
	"os"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// TestPostgresRLSIsolation is the Layer-3 defense-in-depth proof against a REAL
// Postgres: the store's reads carry NO tenant filter, yet Row-Level Security
// (running as a non-superuser role, FORCE RLS) returns only the scoped tenant's
// rows. Set EBPF_TEST_PG_DSN (e.g. postgres://soc:pass@127.0.0.1:5432/ebpf_soc
// ?sslmode=disable) to run it; skipped otherwise.
func TestPostgresRLSIsolation(t *testing.T) {
	dsn := os.Getenv("EBPF_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set EBPF_TEST_PG_DSN to run the Postgres RLS integration test")
	}
	s, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Clean slate (superuser bypasses RLS for setup; data ops below do not).
	if _, err := s.db.Exec("TRUNCATE telemetry"); err != nil {
		t.Fatal(err)
	}

	put := func(tenant, agent, dedup, execID string) {
		t.Helper()
		if err := s.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: eventRec(dedup, execID)}); err != nil {
			t.Fatalf("put %s/%s: %v", tenant, dedup, err)
		}
	}
	// Identical natural keys across tenants — catches natural-id keying.
	put("tenant-a", "agent-a", "evt:1", "exec-1")
	put("tenant-a", "agent-a", "evt:2", "exec-2")
	put("tenant-b", "agent-b", "evt:1", "exec-1")
	put("tenant-b", "agent-b", "evt:3", "exec-3")

	// Scoped reads (RLS-enforced, no WHERE clause in the SQL).
	if n, err := s.Count(Scope{TenantID: "tenant-a"}); err != nil || n != 2 {
		t.Fatalf("tenant-a count = %d (err %v), want 2 — RLS failed to scope a filterless COUNT", n, err)
	}
	if n, _ := s.Count(Scope{TenantID: "tenant-b"}); n != 2 {
		t.Fatalf("tenant-b count = %d, want 2", n)
	}
	rowsA, err := s.Query(Scope{TenantID: "tenant-a"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsA) != 2 {
		t.Fatalf("tenant-a rows = %d, want 2", len(rowsA))
	}
	for _, r := range rowsA {
		if r.TenantID != "tenant-a" {
			t.Fatalf("RLS leaked a %q row into tenant-a's scoped read", r.TenantID)
		}
	}

	// Fail-closed: no scope ⇒ ErrNoScope (never a filterless read).
	if _, err := s.Query(Scope{}, 100); err != ErrNoScope {
		t.Fatalf("unscoped Query err = %v, want ErrNoScope", err)
	}

	// Storage dedup (ON CONFLICT DO NOTHING).
	put("tenant-a", "agent-a", "evt:1", "exec-1") // replay
	if n, _ := s.Count(Scope{TenantID: "tenant-a"}); n != 2 {
		t.Fatalf("count after replay = %d, want 2 (storage dedup)", n)
	}

	// Cross-tenant MSOC path is explicit + named only.
	rows, err := s.QueryAcross([]string{"tenant-a", "tenant-b"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("QueryAcross([a,b]) = %d rows, want 4", len(rows))
	}
}
