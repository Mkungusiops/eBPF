package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// THE ESTATE VIEW, AND THE TWO WAYS IT CAN LIE.
//
//  1. By averaging posture, which hides one customer on fire behind nine quiet
//     ones — the exact failure a provider console exists to prevent.
//  2. By counting a tenant it could not read as a tenant with nothing to
//     report, which turns an outage into a calm night.
//
// Both are asserted here against a store that fails for one tenant and answers
// for the others, because a fan-out that has never met a failing tenant proves
// nothing about the case that matters.

// oneTenantUnreadable is the central store with one tenant's windowed reads
// broken — a connection this tenant's RLS role cannot open, a statement timeout,
// whatever. It embeds the real store so every other path stays honest.
type oneTenantUnreadable struct {
	*centralstore.Store
	broken string
}

var errTenantUnreadable = errors.New("statement timeout reading this tenant")

func (s oneTenantUnreadable) QueryRange(scope centralstore.Scope, from, to time.Time, limit int) ([]centralstore.Row, error) {
	if scope.TenantID == s.broken {
		return nil, errTenantUnreadable
	}
	return s.Store.QueryRange(scope, from, to, limit)
}

func estateTestServer(t *testing.T) (*Server, *centralstore.Store) {
	t.Helper()
	cs, err := centralstore.Open(t.TempDir() + "/c.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	s := &Server{registry: heartbeat.NewRegistry(), auditor: authz.NewMemAuditor()}
	s.cfg.Store = cs
	s.cfg.Logf = func(string, ...any) {}
	return s, cs
}

func alertOfSeverity(sev, mitre string, at time.Time) *ebpfsocv1.TelemetryRecord {
	return &ebpfsocv1.TelemetryRecord{Payload: &ebpfsocv1.TelemetryRecord_Alert{Alert: &ebpfsocv1.Alert{
		OccurredAt: timestamppb.New(at), Severity: sev, Title: "t", ExecId: "e", MitreId: mitre,
	}}}
}

func readEstate(t *testing.T, s *Server, p authz.Principal, query string) (int, estateSummary) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/estate/summary"+query, nil)
	w := httptest.NewRecorder()
	s.estateSummaryFor(w, r, p)
	var out estateSummary
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v — body %s", err, w.Body.String())
		}
	}
	return w.Code, out
}

func TestEstateSummaryIsRefusedToATenantBoundPrincipal(t *testing.T) {
	s, _ := estateTestServer(t)
	analyst := keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst)

	code, _ := readEstate(t, s, analyst, "")
	// 404, never 403: a 403 would confirm to a customer's own analyst that a
	// provider-wide view exists over their data.
	if code != http.StatusNotFound {
		t.Errorf("a tenant-bound analyst got %d from the estate summary, want 404", code)
	}
}

func TestEstateSummarySumsCountsAndDecomposesThem(t *testing.T) {
	s, cs := estateTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme-corp", "a1", "alt:1", alertOfSeverity("critical", "T1059", now.Add(-time.Minute)))
	putRecord(t, cs, "acme-corp", "a1", "alt:2", alertOfSeverity("high", "T1059", now.Add(-time.Minute)))
	putRecord(t, cs, "globex", "b1", "alt:1", alertOfSeverity("low", "T1105", now.Add(-time.Minute)))
	putRecord(t, cs, "acme-corp", "a1", "dec:1", decisionRecord(1, now.Add(-time.Minute)))
	putRecord(t, cs, "globex", "b1", "dec:1", decisionRecord(2, now.Add(-time.Minute)))
	s.registry.Record("acme-corp", "a1", &ebpfsocv1.HeartbeatRequest{})
	s.registry.Record("globex", "b1", &ebpfsocv1.HeartbeatRequest{})

	code, out := readEstate(t, s, keycloakPrincipal("msoc@provider", "adanian", authz.RoleMSOCAdmin), "?window_min=60")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if out.Totals.Alerts != 3 {
		t.Errorf("estate alerts = %d, want 3 (2 acme-corp + 1 globex)", out.Totals.Alerts)
	}
	if out.Totals.Decisions != 2 {
		t.Errorf("estate decisions = %d, want 2", out.Totals.Decisions)
	}
	if out.Totals.Agents != 2 {
		t.Errorf("estate agents = %d, want 2", out.Totals.Agents)
	}

	// DECOMPOSABLE: the parts must add up to the whole and name their owner.
	byTenant := map[string]estateTenantSummary{}
	sumAlerts, sumDecisions := 0, 0
	for _, tt := range out.Tenants {
		byTenant[tt.Tenant] = tt
		sumAlerts += tt.Alerts
		sumDecisions += tt.Decisions
	}
	if sumAlerts != out.Totals.Alerts || sumDecisions != out.Totals.Decisions {
		t.Errorf("the per-tenant rows sum to %d alerts / %d decisions but the estate reports %d / %d — "+
			"a total a provider cannot break down is the defect this endpoint exists to remove",
			sumAlerts, sumDecisions, out.Totals.Alerts, out.Totals.Decisions)
	}
	if byTenant["acme-corp"].Alerts != 2 || byTenant["globex"].Alerts != 1 {
		t.Errorf("per-tenant alert split wrong: acme-corp=%d globex=%d",
			byTenant["acme-corp"].Alerts, byTenant["globex"].Alerts)
	}

	// TOP TECHNIQUE is the mode, and it carries its split.
	if out.Top.Technique != "T1059" {
		t.Errorf("top technique = %q, want T1059 (2 of 3 alerts)", out.Top.Technique)
	}
	if out.Top.ByTenant["acme-corp"] != 2 {
		t.Errorf("the top technique does not say which tenant produced it: %v", out.Top.ByTenant)
	}
}

func TestEstatePostureReportsTheWorstTenantNotTheAverage(t *testing.T) {
	s, cs := estateTestServer(t)
	now := time.Now().UTC()
	// One customer on fire, three quiet. A mean would bury the first.
	for i := 0; i < 60; i++ {
		putRecord(t, cs, "acme-corp", "a1", "alt:"+strconv.Itoa(i), alertOfSeverity("critical", "T1059", now.Add(-time.Minute)))
	}
	for _, quiet := range []string{"globex", "initech", "umbrella"} {
		putRecord(t, cs, quiet, "b1", "alt:1", alertOfSeverity("low", "T1105", now.Add(-time.Minute)))
		s.registry.Record(quiet, "b1", &ebpfsocv1.HeartbeatRequest{})
	}
	s.registry.Record("acme-corp", "a1", &ebpfsocv1.HeartbeatRequest{})

	_, out := readEstate(t, s, keycloakPrincipal("msoc@provider", "adanian", authz.RoleMSOCAdmin), "?window_min=60")

	worst := estateTenantSummary{}
	var mean int
	for _, tt := range out.Tenants {
		mean += tt.Posture
		if tt.Posture > worst.Posture {
			worst = tt
		}
	}
	mean /= len(out.Tenants)

	if out.Posture.WorstTenant != "acme-corp" {
		t.Errorf("estate posture names %q as worst, want acme-corp", out.Posture.WorstTenant)
	}
	if out.Posture.WorstScore != worst.Posture {
		t.Errorf("estate posture score %d is not the worst tenant's %d", out.Posture.WorstScore, worst.Posture)
	}
	if out.Posture.WorstScore == mean {
		t.Errorf("estate posture %d equals the mean across tenants — averaging hides one customer "+
			"on fire behind three quiet ones", out.Posture.WorstScore)
	}
	if out.Posture.WorstScore < estateConcernScore {
		t.Errorf("60 criticals in an hour scored %d, below the concern threshold %d",
			out.Posture.WorstScore, estateConcernScore)
	}
	if out.Posture.TenantsAtOrAboveConcern != 1 || out.Posture.TenantsBelowConcern != 3 {
		t.Errorf("concern split = %d above / %d below, want 1 / 3",
			out.Posture.TenantsAtOrAboveConcern, out.Posture.TenantsBelowConcern)
	}
	// Worst first: the customer that needs attention is the first row.
	if out.Tenants[0].Tenant != "acme-corp" {
		t.Errorf("the decomposition leads with %q, not the worst tenant", out.Tenants[0].Tenant)
	}
}

func TestAnUnreadableTenantIsUnreadNotZero(t *testing.T) {
	s, cs := estateTestServer(t)
	now := time.Now().UTC()
	putRecord(t, cs, "acme-corp", "a1", "alt:1", alertOfSeverity("critical", "T1059", now.Add(-time.Minute)))
	putRecord(t, cs, "globex", "b1", "alt:1", alertOfSeverity("critical", "T1059", now.Add(-time.Minute)))
	s.cfg.Store = oneTenantUnreadable{Store: cs, broken: "globex"}
	s.registry.Record("acme-corp", "a1", &ebpfsocv1.HeartbeatRequest{})
	s.registry.Record("globex", "b1", &ebpfsocv1.HeartbeatRequest{})

	code, out := readEstate(t, s, keycloakPrincipal("msoc@provider", "adanian", authz.RoleMSOCAdmin), "?window_min=60")
	// A failing tenant must not fail the endpoint: the other customers' state
	// is exactly what an operator needs while one of them is down.
	if code != 200 {
		t.Fatalf("one unreadable tenant took the whole estate view down: status %d", code)
	}
	if out.TenantsRead != 1 || out.TenantsUnread != 1 {
		t.Errorf("read/unread = %d/%d, want 1/1", out.TenantsRead, out.TenantsUnread)
	}
	var broken estateTenantSummary
	for _, tt := range out.Tenants {
		if tt.Tenant == "globex" {
			broken = tt
		}
	}
	if broken.Status != "unread" {
		t.Errorf("globex status = %q, want unread — a tenant that could not be read is not a tenant "+
			"with nothing to report", broken.Status)
	}
	if broken.UnreadReason == "" {
		t.Error("globex is marked unread with no reason, so an operator cannot tell an outage from a quiet night")
	}
	// And it must not have been folded into the totals as a zero.
	if out.Totals.Alerts != 1 {
		t.Errorf("estate alerts = %d, want 1: the unreadable tenant's alerts are unknown, not zero", out.Totals.Alerts)
	}
	if out.Posture.TenantsUnscored != 1 {
		t.Errorf("unscored tenants = %d, want 1 — an unread tenant is not 'below concern'", out.Posture.TenantsUnscored)
	}
	// The concern split must span the tenants that were READ, never the whole
	// estate: counting the unreadable one on either side of the threshold
	// asserts something about a customer nobody looked at.
	if got := out.Posture.TenantsAtOrAboveConcern + out.Posture.TenantsBelowConcern; got != out.TenantsRead {
		t.Errorf("the concern split covers %d tenants but only %d were read — an unread tenant has "+
			"been placed on one side of the threshold", got, out.TenantsRead)
	}
}

func TestEveryEstateTenantReadIsAudited(t *testing.T) {
	s, cs := estateTestServer(t)
	aud := authz.NewMemAuditor()
	s.auditor = aud
	now := time.Now().UTC()
	putRecord(t, cs, "acme-corp", "a1", "alt:1", alertOfSeverity("high", "T1059", now.Add(-time.Minute)))
	putRecord(t, cs, "globex", "b1", "alt:1", alertOfSeverity("high", "T1059", now.Add(-time.Minute)))
	s.registry.Record("acme-corp", "a1", &ebpfsocv1.HeartbeatRequest{})
	s.registry.Record("globex", "b1", &ebpfsocv1.HeartbeatRequest{})

	readEstate(t, s, keycloakPrincipal("msoc@provider", "adanian", authz.RoleMSOCAdmin), "?window_min=60")

	audited := map[string]bool{}
	for _, rec := range aud.Records() {
		if rec.Allowed && rec.CrossTenant {
			audited[rec.Tenant] = true
		}
	}
	for _, want := range []string{"acme-corp", "globex"} {
		if !audited[want] {
			t.Errorf("the estate roll-up read %s and recorded no cross-tenant access — an aggregate is "+
				"not a loophole around the access trail", want)
		}
	}
}
