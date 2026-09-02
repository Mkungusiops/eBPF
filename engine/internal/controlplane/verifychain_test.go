package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"

	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// Central verification has a failure mode the agent's does not: a field lost
// in transit produces a different hash, and the endpoint then accuses an
// untouched record of being tampered with. That is worse than not verifying —
// it names a specific decision and a specific operator.
//
// So the round trip is the test: hash a record the way the agent does, send it
// through the real uplink conversion and back through decisionFromWire, and
// require the hash to still verify.

func chainStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.TempDir() + "/v.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestARecordStillVerifiesAfterTheRoundTrip(t *testing.T) {
	st := chainStore(t)
	// Every chain-hashed field populated, so an omission shows up as a hash
	// mismatch rather than being masked by a zero value on both sides.
	d := &store.Decision{
		Timestamp: time.Now().UTC(), ExecID: "exec-1", PID: 4021,
		Binary: "/usr/bin/curl", Action: "sever", FromState: "quarantined",
		ToState: "severed", Score: 210, Reason: "confirmed C2",
		DryRun: true, Backend: "cgroupv2", Outcome: "ok",
		OriginKind: "ssh", OriginIP: "203.0.113.9", OriginPort: 22,
		OriginUser: "root", OriginFingerprint: "SHA256:abc",
		DeviceMAC: "0a:1b:2c:3d:4e:5f", DeviceID: "dev-1",
		Actor: "op-adanian",
	}
	if _, err := st.InsertDecision(d); err != nil {
		t.Fatal(err)
	}
	if !store.VerifyRow(d) {
		t.Fatal("the record does not verify locally; the fixture is wrong")
	}

	// The exact path a real decision takes to the control plane.
	wire := uplink.DecisionRecord(d).GetDecision()
	back := decisionFromWire(wire)

	if !store.VerifyRow(back) {
		t.Fatal("a record that verified on the agent does not verify after the round trip — " +
			"a chain-hashed field is being lost, and the endpoint would accuse this decision of tampering")
	}
}

func TestAnActorlessRecordAlsoSurvives(t *testing.T) {
	// The automatic case. actor is chain-hashed only when present, so the
	// empty path is a distinct canonical form and needs its own check.
	st := chainStore(t)
	d := &store.Decision{
		Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
		FromState: "pristine", ToState: "throttled", Backend: "cgroupv2", Outcome: "ok",
	}
	if _, err := st.InsertDecision(d); err != nil {
		t.Fatal(err)
	}
	if !store.VerifyRow(decisionFromWire(uplink.DecisionRecord(d).GetDecision())) {
		t.Fatal("an automatic decision does not verify after the round trip")
	}
}

func TestAMissingRecordReadsAsIncompleteNotBroken(t *testing.T) {
	// The distinction the whole endpoint turns on. Decisions were not uplinked
	// before 2026-08-24 and an agent's backlog can be evicted under its cap,
	// so gaps are normal. Calling a gap "broken" would accuse the estate of
	// tampering every time an agent had been offline.
	st := chainStore(t)
	var kept []*store.Decision
	for i := 0; i < 4; i++ {
		d := &store.Decision{
			Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Backend: "cgroupv2", Outcome: "ok",
		}
		if _, err := st.InsertDecision(d); err != nil {
			t.Fatal(err)
		}
		if i != 2 { // the control plane never received the third
			kept = append(kept, decisionFromWire(uplink.DecisionRecord(d).GetDecision()))
		}
	}

	v := verifyAgentChain("a1", kept)
	if v.Status != "incomplete" {
		t.Fatalf("status = %q, want incomplete — a gap is a missing record, not a modified one", v.Status)
	}
	if v.BadAt != 0 {
		t.Fatalf("a gap named row %d as bad; only tampering may name a row", v.BadAt)
	}
	if v.Verified != 3 {
		t.Fatalf("verified %d, want the 3 records actually held", v.Verified)
	}
}

func TestAnAlteredRecordIsReportedBroken(t *testing.T) {
	// The finding that IS an accusation.
	st := chainStore(t)
	var got []*store.Decision
	for i := 0; i < 3; i++ {
		d := &store.Decision{
			Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Backend: "cgroupv2", Outcome: "ok",
		}
		if _, err := st.InsertDecision(d); err != nil {
			t.Fatal(err)
		}
		got = append(got, decisionFromWire(uplink.DecisionRecord(d).GetDecision()))
	}
	// Someone rewrote the reason after the fact.
	got[1].Reason = "routine maintenance"

	v := verifyAgentChain("a1", got)
	if v.Status != "broken" {
		t.Fatalf("status = %q, want broken — the record's content no longer matches its hash", v.Status)
	}
	if v.BadAt != got[1].ID {
		t.Fatalf("named row %d, want the altered one (%d)", v.BadAt, got[1].ID)
	}
}

func TestAnIntactChainVerifies(t *testing.T) {
	st := chainStore(t)
	var got []*store.Decision
	for i := 0; i < 5; i++ {
		d := &store.Decision{
			Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Backend: "cgroupv2",
			Outcome: "ok", Actor: "op-adanian",
		}
		if _, err := st.InsertDecision(d); err != nil {
			t.Fatal(err)
		}
		got = append(got, decisionFromWire(uplink.DecisionRecord(d).GetDecision()))
	}
	v := verifyAgentChain("a1", got)
	if v.Status != "verified" || v.Verified != 5 || v.Gaps != 0 {
		t.Fatalf("verdict = %+v, want 5 verified with no gaps", v)
	}
}

// The accusation path, end to end through the HTTP handler with a real store.
//
// Deliberately NOT proved by injecting a corrupt record into the live tenant's
// ledger: writing a fabricated row into an audit table is the exact act this
// endpoint exists to detect, and a failed cleanup would leave a permanent
// false accusation against a real agent.
func TestTheEndpointReportsTamperingThroughTheHandler(t *testing.T) {
	cs, err := centralstore.Open(t.TempDir() + "/c.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	st := chainStore(t)

	put := func(alter bool) {
		d := &store.Decision{
			Timestamp: time.Now().UTC(), ExecID: "e", Action: "throttle",
			FromState: "pristine", ToState: "throttled", Reason: "score exceeded",
			Backend: "cgroupv2", Outcome: "ok", Actor: "op-adanian",
		}
		if _, err := st.InsertDecision(d); err != nil {
			t.Fatal(err)
		}
		if alter {
			// Rewritten AFTER hashing: the hash now describes different content.
			d.Reason = "routine maintenance"
		}
		rec := uplink.DecisionRecord(d)
		if err := cs.Put(ingest.StampedRecord{TenantID: "acme", AgentID: "a1", Record: rec}); err != nil {
			t.Fatal(err)
		}
	}
	put(false)
	put(true)
	put(false)

	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Store = cs
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"

	req := httptest.NewRequest(http.MethodGet, "/api/verify-chain?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleVerifyChain(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["supported"] != true {
		t.Fatal("the endpoint still reports itself unsupported")
	}
	if got["ok"] != false {
		t.Fatalf("a tampered record was reported as ok: %v", got)
	}
	agents, _ := got["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents = %v", agents)
	}
	first, _ := agents[0].(map[string]any)
	if first["status"] != "broken" {
		t.Fatalf("status = %v, want broken", first["status"])
	}
	if bad, _ := first["bad_at"].(float64); bad == 0 {
		t.Fatal("broken but no record named — an accusation must say which row")
	}
}
