package ingest

import (
	"sync"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// MemSink is an in-memory Sink that keeps stamped records partitioned by
// tenant. It is the test/Phase-0 stand-in for the message bus, and it is the
// concrete proof surface for cross-tenant separation: two tenants' records —
// even with identical natural keys — land in distinct partitions.
type MemSink struct {
	mu       sync.Mutex
	byTenant map[string][]*ebpfsocv1.TelemetryRecord
}

func NewMemSink() *MemSink {
	return &MemSink{byTenant: make(map[string][]*ebpfsocv1.TelemetryRecord)}
}

func (m *MemSink) Put(r StampedRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byTenant[r.TenantID] = append(m.byTenant[r.TenantID], r.Record)
	return nil
}

// Count returns how many records were stamped for tenantID.
func (m *MemSink) Count(tenantID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byTenant[tenantID])
}

// Records returns a copy of the records stamped for tenantID.
func (m *MemSink) Records(tenantID string) []*ebpfsocv1.TelemetryRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.byTenant[tenantID]
	out := make([]*ebpfsocv1.TelemetryRecord, len(src))
	copy(out, src)
	return out
}

// Tenants returns the set of tenants that have any records.
func (m *MemSink) Tenants() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.byTenant))
	for t := range m.byTenant {
		out = append(out, t)
	}
	return out
}
