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

// A chain that MIXES rows written before operator attribution existed (no
// actor) with rows written after (actor set) must still verify end to end.
// Adding a field to the canonical form is exactly how an audit log gets
// retroactively invalidated, so this pins the trailer behaviour.
func TestVerifyDecisionChainWithMixedActorRows(t *testing.T) {
	s := newTestStore(t)

	rows := []*Decision{
		// autonomous, score-driven: no operator ordered it
		{ExecID: "A", PID: 1, Binary: "/bin/sh", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Score: 7, Reason: "rising",
			Backend: "logger", Outcome: "ok", Timestamp: time.Now().UTC()},
		// operator-ordered
		{ExecID: "A", PID: 1, Binary: "/bin/sh", Action: "quarantine",
			FromState: "throttled", ToState: "quarantined", Score: 30, Reason: "analyst call",
			Backend: "cgroup", Outcome: "ok", Actor: "msoc"},
		// autonomous again, after an attributed row
		{ExecID: "B", PID: 2, Binary: "/usr/bin/nc", Action: "tarpit",
			FromState: "pristine", ToState: "tarpit", Score: 18, Reason: "chain",
			Backend: "cgroup", Outcome: "ok"},
	}
	for i, d := range rows {
		if _, err := s.InsertDecision(d); err != nil {
			t.Fatalf("insert row %d: %v", i, err)
		}
	}

	res, err := s.VerifyDecisionChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("mixed actor/non-actor chain must verify, broke at id=%d field=%s", res.BadAt, res.BadField)
	}
	if res.Total != len(rows) {
		t.Errorf("Total=%d want %d", res.Total, len(rows))
	}

	// The actor must survive the round trip, and must not leak onto rows that
	// had none (that would mean the column is being read positionally wrong).
	got, err := s.RecentDecisions(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	actors := map[string]string{}
	for _, d := range got {
		actors[d.Action] = d.Actor
	}
	if actors["quarantine"] != "msoc" {
		t.Errorf("operator-ordered row lost its actor: %q", actors["quarantine"])
	}
	if actors["throttle"] != "" || actors["tarpit"] != "" {
		t.Errorf("autonomous rows must have no actor, got throttle=%q tarpit=%q",
			actors["throttle"], actors["tarpit"])
	}
}

// Tamper-evidence must still hold once the actor is part of the canonical form:
// rewriting who ordered an action has to break the chain.
func TestActorTamperBreaksChain(t *testing.T) {
	s := newTestStore(t)
	d := &Decision{ExecID: "A", PID: 1, Binary: "/bin/sh", Action: "sever",
		FromState: "quarantined", ToState: "severed", Score: 90, Reason: "ordered",
		Backend: "severer", Outcome: "ok", Actor: "msoc", Timestamp: time.Now().UTC()}
	if _, err := s.InsertDecision(d); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE decisions SET actor = 'someone-else'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := s.VerifyDecisionChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("rewriting the actor must break the audit chain, but verification passed")
	}
}

// The companion to TestActorTamperBreaksChain, and the case that let the
// forgery ship: REWRITING an existing actor was caught, but ADDING attribution
// to a row that had none was not. Autonomous, score-driven enforcement writes
// exactly such rows — no actor, no origin, no device — so every one of them
// could be re-attributed to a named operator after the fact, with the chain
// still certifying the record as intact.
func TestAttributingAnAutonomousDecisionBreaksChain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper string
	}{
		{"actor", `UPDATE decisions SET actor = 'ceo@corp.example'`},
		{"origin", `UPDATE decisions SET origin_ip = '10.0.0.9', origin_user = 'root'`},
		{"device", `UPDATE decisions SET device_mac = 'de:ad:be:ef:00:01'`},
		{"all", `UPDATE decisions SET actor = 'ceo@corp.example', origin_ip = '10.0.0.9', origin_user = 'root', device_mac = 'de:ad:be:ef:00:01'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			// An autonomous enforcement: nobody ordered it, so no attribution.
			if _, err := s.InsertDecision(&Decision{
				ExecID: "A", PID: 4242, Binary: "/usr/bin/curl", Action: "sever",
				FromState: "tarpit", ToState: "severed", Score: 91,
				Reason: "autonomous: score threshold", Backend: "severer",
				Outcome: "ok", Timestamp: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("insert: %v", err)
			}
			if res, err := s.VerifyDecisionChain(); err != nil || !res.OK {
				t.Fatalf("baseline verify must pass: ok=%v err=%v", res.OK, err)
			}
			if _, err := s.db.Exec(tc.tamper); err != nil {
				t.Fatalf("tamper: %v", err)
			}
			res, err := s.VerifyDecisionChain()
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if res.OK {
				t.Fatalf("forging %s onto an unattributed decision must break the chain, but verification passed", tc.name)
			}
		})
	}
}
