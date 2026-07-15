package centralstore

import (
	"os"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// TestClickHouseTenantIsolation proves the events-firehose backend against a
// REAL ClickHouse: tenant-partitioned storage, tenant-scoped reads (identical
// keys across tenants stay separate), fail-closed unscoped reads, and
// ReplacingMergeTree dedup via FINAL. Set EBPF_TEST_CH_DSN (e.g.
// clickhouse://soc:pass@127.0.0.1:9000/ebpf_soc) to run it; skipped otherwise.
func TestClickHouseTenantIsolation(t *testing.T) {
	dsn := os.Getenv("EBPF_TEST_CH_DSN")
	if dsn == "" {
		t.Skip("set EBPF_TEST_CH_DSN to run the ClickHouse integration test")
	}
	s, err := OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.db.Exec("TRUNCATE TABLE telemetry"); err != nil {
		t.Fatal(err)
	}

	put := func(tenant, agent, dedup, execID string) {
		t.Helper()
		if err := s.Put(ingest.StampedRecord{TenantID: tenant, AgentID: agent, Record: eventRec(dedup, execID)}); err != nil {
			t.Fatalf("put %s/%s: %v", tenant, dedup, err)
		}
	}
	put("tenant-a", "agent-a", "evt:1", "exec-1")
	put("tenant-a", "agent-a", "evt:2", "exec-2")
	put("tenant-b", "agent-b", "evt:1", "exec-1") // identical keys, other tenant
	put("tenant-b", "agent-b", "evt:3", "exec-3")

	if n, err := s.Count(Scope{TenantID: "tenant-a"}); err != nil || n != 2 {
		t.Fatalf("tenant-a count = %d (err %v), want 2", n, err)
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
			t.Fatalf("ClickHouse leaked a %q row into tenant-a's read", r.TenantID)
		}
		if r.Record == nil || r.Record.GetEvent() == nil {
			t.Fatalf("payload not round-tripped through ClickHouse: %+v", r)
		}
	}

	// Fail-closed: no scope ⇒ ErrNoScope.
	if _, err := s.Query(Scope{}, 100); err != ErrNoScope {
		t.Fatalf("unscoped Query err = %v, want ErrNoScope", err)
	}

	// ReplacingMergeTree dedup, surfaced via FINAL.
	put("tenant-a", "agent-a", "evt:1", "exec-1") // replay same key
	if n, _ := s.Count(Scope{TenantID: "tenant-a"}); n != 2 {
		t.Fatalf("count after replay = %d, want 2 (FINAL dedup)", n)
	}

	// Explicit, named cross-tenant path.
	rows, err := s.QueryAcross([]string{"tenant-a", "tenant-b"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("QueryAcross([a,b]) = %d, want 4", len(rows))
	}
}
