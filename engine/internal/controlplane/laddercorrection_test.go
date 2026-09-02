package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// Setting a ladder on ONE host is supported — the agent serves its own console
// and accepts SetThresholds. The tenant policy is authoritative, so the
// reconciler puts that host back within two minutes. Correctly, and silently:
// the operator watched their change apply and then vanish, with the only
// explanation in a control-plane log they have no route to.
//
// The rejected alternative was to adopt the host's value as the new tenant
// policy. That lets a change made on one host silently rewrite the containment
// ladder for every other host in the fleet — the blast radius this platform
// spends its effort bounding everywhere else.
func TestLadderCorrectionsAreRecordedPerTenant(t *testing.T) {
	var log ladderCorrectionLog
	log.record(ladderCorrection{Tenant: "acme", Agent: "a1", From: "10/20/30/40", To: "20/50/120/200", At: time.Now()})
	log.record(ladderCorrection{Tenant: "other", Agent: "b1", From: "1/2/3/4", To: "20/50/120/200", At: time.Now()})
	log.record(ladderCorrection{Tenant: "acme", Agent: "a2", From: "5/6/7/8", To: "20/50/120/200", At: time.Now()})

	got := log.forTenant("acme", 10)
	if len(got) != 2 {
		t.Fatalf("got %d corrections for acme, want 2 — another tenant's rows leaked in", len(got))
	}
	// Newest first: an operator looking for the change they just lost should
	// find it at the top, not after scrolling a month of history.
	if got[0].Agent != "a2" {
		t.Fatalf("newest-first ordering broken: %+v", got)
	}
	if got[0].From != "5/6/7/8" || got[0].To != "20/50/120/200" {
		t.Fatalf("the correction does not say what was replaced with what: %+v", got[0])
	}
}

func TestLadderCorrectionRingIsBounded(t *testing.T) {
	// This process runs for months. An unbounded slice appended to on a timer
	// is a slow leak with no upper limit.
	var log ladderCorrectionLog
	for i := 0; i < ladderCorrectionCap+50; i++ {
		log.record(ladderCorrection{Tenant: "acme", Agent: "a1", From: "1/2/3/4", To: "20/50/120/200"})
	}
	if n := len(log.forTenant("acme", ladderCorrectionCap+100)); n != ladderCorrectionCap {
		t.Fatalf("ring holds %d, want the cap %d", n, ladderCorrectionCap)
	}
}

// The record is worthless if the console cannot read it.
func TestChokeSummaryCarriesLadderCorrections(t *testing.T) {
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Logf = func(string, ...any) {}
	s.cfg.AdminToken = "admin-secret"
	s.registry.Record("acme", "a1", &ebpfsocv1.HeartbeatRequest{
		AgentInfo: &ebpfsocv1.AgentInfo{Hostname: "h1"},
	})
	s.ladderCorrections.record(ladderCorrection{
		Tenant: "acme", Agent: "a1", From: "10/20/30/40", To: "20/50/120/200", At: time.Now().UTC()})

	// /api/choke/state is the posture endpoint the console's ChokeState reads
	// — the one already carrying thresholds and thresholds_diverge, which is
	// where a ladder correction belongs.
	req := httptest.NewRequest(http.MethodGet, "/api/choke/state?tenant=acme", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleChokeStateGW(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	rows, ok := body["ladder_corrections"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("ladder_corrections missing or wrong length: %v", body["ladder_corrections"])
	}
	row := rows[0].(map[string]any)
	if row["agent"] != "a1" || row["from"] != "10/20/30/40" || row["to"] != "20/50/120/200" {
		t.Fatalf("the correction reached the console incomplete: %v", row)
	}
}
