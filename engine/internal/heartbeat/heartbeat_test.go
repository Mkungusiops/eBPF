package heartbeat

import (
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

func TestRegistryRecordAndGet(t *testing.T) {
	r := NewRegistry()
	req := &ebpfsocv1.HeartbeatRequest{
		AgentInfo:            &ebpfsocv1.AgentInfo{AgentVersion: "0.2.0-agent", Kernel: "6.8.0"},
		DataPlane:            &ebpfsocv1.DataPlaneState{Mode: ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING},
		BufferDepth:          42,
		AppliedPolicyVersion: "pol-7",
	}
	r.Record("tenant-a", "agent-1", req)

	rec, ok := r.Get("tenant-a", "agent-1")
	if !ok {
		t.Fatal("record not found")
	}
	if rec.Version != "0.2.0-agent" || rec.Kernel != "6.8.0" || rec.BufferDepth != 42 ||
		rec.AppliedPolicyVersion != "pol-7" || rec.Mode != ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING {
		t.Fatalf("record fields not mapped: %+v", rec)
	}
	if rec.LastSeen.IsZero() {
		t.Fatal("LastSeen not set")
	}
}

// TestRegistrySeparatesTenants: same agent id under two tenants are distinct
// registry entries (isolation fixture).
func TestRegistrySeparatesTenants(t *testing.T) {
	r := NewRegistry()
	r.Record("tenant-a", "agent-1", &ebpfsocv1.HeartbeatRequest{})
	r.Record("tenant-b", "agent-1", &ebpfsocv1.HeartbeatRequest{})
	if r.Count() != 2 {
		t.Fatalf("count = %d, want 2 (same agent id, different tenants must not collide)", r.Count())
	}
	if _, ok := r.Get("tenant-a", "agent-1"); !ok {
		t.Fatal("tenant-a entry missing")
	}
	if _, ok := r.Get("tenant-c", "agent-1"); ok {
		t.Fatal("unknown tenant should not be found")
	}
}
