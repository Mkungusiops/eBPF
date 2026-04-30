package store

import (
	"testing"
	"time"
)

func TestInsertDecisionPopulatesHashChain(t *testing.T) {
	s := newTestStore(t)

	d1 := &Decision{
		ExecID: "A", PID: 1, Binary: "/bin/bash", Action: "throttle",
		FromState: "pristine", ToState: "throttled", Score: 7, Reason: "rising",
		Backend: "logger", Outcome: "ok", Timestamp: time.Now().UTC(),
	}
	if _, err := s.InsertDecision(d1); err != nil {
		t.Fatalf("insert d1: %v", err)
	}
	if d1.PrevHash != "" {
		t.Errorf("first row PrevHash should be empty, got %q", d1.PrevHash)
	}
	if d1.Hash == "" {
		t.Errorf("first row Hash must be populated")
	}

	d2 := &Decision{
		ExecID: "A", PID: 1, Binary: "/bin/bash", Action: "sever",
		FromState: "throttled", ToState: "severed", Score: 50, Reason: "spike",
		Backend: "severer", Outcome: "ok",
	}
	if _, err := s.InsertDecision(d2); err != nil {
		t.Fatalf("insert d2: %v", err)
	}
	if d2.PrevHash != d1.Hash {
		t.Errorf("d2.PrevHash=%s want d1.Hash=%s", d2.PrevHash, d1.Hash)
	}
	if d2.Hash == d1.Hash {
		t.Errorf("hashes should differ across rows")
	}
}

func TestVerifyDecisionChainOK(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 5; i++ {
		_, err := s.InsertDecision(&Decision{
			ExecID: "X", PID: uint32(i + 1), Binary: "/x", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Score: 6,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.VerifyDecisionChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Total != 5 || res.BadAt != 0 {
		t.Fatalf("expected clean chain, got %+v", res)
	}
}

func TestVerifyDecisionChainDetectsTamper(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 3; i++ {
		_, err := s.InsertDecision(&Decision{
			ExecID: "X", PID: uint32(i + 1), Binary: "/x", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Score: 6,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Tamper: silently mutate a non-hash field on row 2.
	if _, err := s.db.Exec(`UPDATE decisions SET reason='altered' WHERE id=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := s.VerifyDecisionChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatalf("verify must detect tamper, got %+v", res)
	}
	if res.BadAt != 2 {
		t.Errorf("BadAt=%d want 2", res.BadAt)
	}
}

func TestRecentDecisionsOrdering(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 3; i++ {
		_, err := s.InsertDecision(&Decision{
			ExecID: "X", PID: uint32(i + 1), Binary: "/x", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Score: 6,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.RecentDecisions(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d decisions want 3", len(out))
	}
	if out[0].ID < out[1].ID || out[1].ID < out[2].ID {
		t.Errorf("expected newest-first ordering, got %v", []int64{out[0].ID, out[1].ID, out[2].ID})
	}
}
