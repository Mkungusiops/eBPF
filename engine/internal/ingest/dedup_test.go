package ingest

import (
	"fmt"
	"testing"
)

// The dedup set was one unbounded map holding every record ever ingested for the
// life of the process — ~400k entries/day at measured production rates.
func TestDedupSetIsBounded(t *testing.T) {
	s := NewServer(nil)
	for i := range dedupGenSize*2 + 500 {
		s.duplicate("t1", "agent-a", fmt.Sprintf("evt:%d", i))
	}
	if total := len(s.cur) + len(s.prev); total > dedupGenSize*2 {
		t.Fatalf("dedup set holds %d keys, want <= %d — growth is unbounded", total, dedupGenSize*2)
	}
}

// Recent replays must still be caught; bounding must not break idempotency.
func TestDedupStillCatchesRecentReplays(t *testing.T) {
	s := NewServer(nil)
	if s.duplicate("t1", "agent-a", "evt:1") {
		t.Fatal("first sighting reported as duplicate")
	}
	if !s.duplicate("t1", "agent-a", "evt:1") {
		t.Fatal("immediate replay was not caught — ingest is no longer idempotent")
	}
}

// The key was (agent, key) while the storage primary key is
// (tenant_id, agent_id, dedup_key), so two tenants whose agents happened to
// share an agent_id would silently drop one tenant's record as a replay.
func TestDedupIsTenantScoped(t *testing.T) {
	s := NewServer(nil)
	if s.duplicate("tenant-a", "shared-agent-id", "evt:1") {
		t.Fatal("first sighting reported as duplicate")
	}
	if s.duplicate("tenant-b", "shared-agent-id", "evt:1") {
		t.Fatal("tenant-b's record was dropped as a duplicate of tenant-a's — " +
			"an agent_id collision across tenants silently loses telemetry")
	}
}
