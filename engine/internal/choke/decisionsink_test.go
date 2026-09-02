package choke

import (
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/tokens"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce"
	"github.com/jeffmk/ebpf-poc-engine/internal/enforce/bpfmap"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/tree"
)

// Every decision this gateway records must reach the uplink. Events and alerts
// had sinks from the start; decisions never did, so the multi-tenant console
// had no containment audit at all — 431 rows frozen on the day the demo data
// stopped, beside millions of events still arriving.

func sinkGateway(t *testing.T) (*Gateway, *store.Store, *[]*store.Decision) {
	t.Helper()
	st, err := store.New(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var sunk []*store.Decision
	g := NewGateway(Config{
		Store: st, Enforcer: &enforce.Multi{}, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), Policies: policy.NewSet(), BPFMap: bpfmap.NewNoopBackend(),
		Thresholds:   circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40},
		DecisionSink: func(d *store.Decision) { sunk = append(sunk, d) },
	})
	return g, st, &sunk
}

func TestAConfigChangeReachesTheUplink(t *testing.T) {
	// Changing when the platform acts is exactly what a review asks about, and
	// it is recorded through the same path as a containment decision.
	g, _, sunk := sinkGateway(t)

	g.AuditConfigChange("set-thresholds", "20/50/120/200", "10/20/30/40", "op-adanian", "tightening for the migration")

	if len(*sunk) != 1 {
		t.Fatalf("sank %d decisions, want 1", len(*sunk))
	}
	got := (*sunk)[0]
	if got.Actor != "op-adanian" {
		t.Fatalf("actor = %q, want the operator", got.Actor)
	}
	// Sunk AFTER the insert, so the record carries its id and chain link. The
	// other order ships id 0 and empty hashes: one shared dedup key, and
	// nothing the far end can verify.
	if got.ID == 0 {
		t.Fatal("sunk before the insert — every decision would share a dedup key")
	}
	if got.Hash == "" {
		t.Fatal("sunk before the insert — the far end has no chain link to verify")
	}
}

func TestNoSinkIsNotAnError(t *testing.T) {
	// A standalone host has no uplink, and the enforcement path must never
	// depend on one. This is the autonomy contract in a test.
	st, err := store.New(t.TempDir() + "/s.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	g := NewGateway(Config{
		Store: st, Enforcer: &enforce.Multi{}, Tokens: tokens.NewManager(),
		Tree: tree.New(time.Hour), Policies: policy.NewSet(),
		Thresholds: circuit.Config{ThrottleAt: 10, TarpitAt: 20, QuarantineAt: 30, SeverAt: 40},
	})

	g.AuditConfigChange("set-thresholds", "a", "b", "op", "why")

	rows, err := st.RecentDecisions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the decision was not recorded locally: %d rows", len(rows))
	}
}
