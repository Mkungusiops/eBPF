package ingest

import (
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

type capturingSink struct{ got []StampedRecord }

func (c *capturingSink) Put(r StampedRecord) error { c.got = append(c.got, r); return nil }

// Stamped at INGEST, not derived at read time: the agent that produced a
// record may be long gone by the time anyone reads it. The 431 synthetic
// decisions on the live estate came from two simulators that stopped reporting
// on 2026-08-15 and never returned, leaving nothing to join against.

func TestRecordsFromASimulatorAreMarked(t *testing.T) {
	sink := &capturingSink{}
	s := NewServer(sink)
	s.SetSyntheticFn(func(tenant, agent string) bool { return agent == "sim-1" })

	for _, agent := range []string{"sim-1", "real-1"} {
		if err := sink.Put(StampedRecord{
			TenantID: "acme", AgentID: agent,
			Record:    &ebpfsocv1.TelemetryRecord{DedupKey: agent},
			Synthetic: s.synthetic("acme", agent),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !sink.got[0].Synthetic {
		t.Fatal("a simulator's record was not marked — it reads as evidence")
	}
	if sink.got[1].Synthetic {
		t.Fatal("a real agent's record was marked synthetic — it would be filtered out of the audit")
	}
}

func TestWithNoPredicateNothingIsMarkedSynthetic(t *testing.T) {
	// A deployment with no registry must not start labelling real containment
	// as demo data. Assume real; that is the only safe default.
	sink := &capturingSink{}
	s := NewServer(sink)
	if s.synthetic != nil {
		t.Fatal("a server with no predicate must not classify anything")
	}
}
