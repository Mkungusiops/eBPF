package controlplane

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/baseline"
	"github.com/jeffmk/ebpf-poc-engine/internal/findings"
)

// THE ENRICHMENT PANELS, FOR A PROVIDER WHO PICKED A CUSTOMER.
//
// The console's customer selector puts ?tenant= on every request its funnel
// sends, and the SOC route stands over the result saying "every panel below is
// <customer>'s data only". These five endpoints ignored the parameter: they
// resolved the tenant from the principal through the chat scope, which for a
// cross-tenant operator does not answer with a customer at all — it answers
// with the platform pseudo-tenant those operators' chat rows are stamped with,
// and no agent has ever reported under that. So switching customers changed
// nothing on screen, under a banner that said it had.
//
// These tests pin both halves of the fix: the parameter is HONOURED, and
// honouring it widens nobody's reach.

// enrichmentServer is a bare server with only what the enrichment reads touch.
// The bearer admin is the only principal a handler test can present (the
// production identity path is an OIDC session), and it is cross-tenant — which
// is exactly the persona this defect was about.
func enrichmentServer(t *testing.T) (*Server, *authz.MemAuditor) {
	t.Helper()
	aud := authz.NewMemAuditor()
	s := &Server{auditor: aud, enrich: newTenantEnricher(nil, baseline.Warmup{})}
	s.cfg.AdminToken = "admin-secret"
	s.cfg.Logf = func(string, ...any) {}
	return s, aud
}

// seedTenantProfile gives one tenant a profile and one anomaly per observation,
// so a response can be traced back to the tenant it was built from.
func seedTenantProfile(t *testing.T, s *Server, tenant string, observations int) {
	t.Helper()
	p, ring := s.enrich.forTenant(tenant)
	if p == nil {
		t.Fatalf("no profile could be created for %s", tenant)
	}
	at := time.Now()
	for i := 0; i < observations; i++ {
		p.Observe(baseline.Observation{Binary: "/usr/bin/" + tenant + "-tool", UID: 0, At: at})
		ring.Add(findings.Finding{
			At: at, Kind: "anomaly", Binary: "/usr/bin/" + tenant + "-tool", Points: 7,
			Reasons: []string{"first seen on " + tenant},
		})
	}
}

// enrichmentGet issues one enrichment read as the bearer admin and decodes it.
func enrichmentGet(t *testing.T, s *Server, h http.HandlerFunc, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestEnrichmentReadsHonourTheNamedTenant is the defect itself: two customers
// with different histories must not answer with each other's.
func TestEnrichmentReadsHonourTheNamedTenant(t *testing.T) {
	s, _ := enrichmentServer(t)
	seedTenantProfile(t, s, "acme-corp", 3)
	seedTenantProfile(t, s, "globex", 11)

	for _, tc := range []struct {
		tenant string
		want   float64
	}{{"acme-corp", 3}, {"globex", 11}} {
		code, body := enrichmentGet(t, s, s.handleBaseline, "/api/baseline?tenant="+tc.tenant)
		if code != 200 {
			t.Fatalf("%s: status %d: %v", tc.tenant, code, body)
		}
		if body["enabled"] != true {
			t.Fatalf("%s: enabled=%v, want true — the named customer has a profile", tc.tenant, body["enabled"])
		}
		st, _ := body["status"].(map[string]any)
		if got := st["observations"]; got != tc.want {
			t.Errorf("/api/baseline?tenant=%s reported %v observations, want %v — the panel is "+
				"showing another customer's profile under a banner naming this one", tc.tenant, got, tc.want)
		}
		if got := body["anomalies_total"]; got != tc.want {
			t.Errorf("/api/baseline?tenant=%s reported anomalies_total=%v, want %v", tc.tenant, got, tc.want)
		}

		code, body = enrichmentGet(t, s, s.handleBaselineAnomalies, "/api/baseline/anomalies?tenant="+tc.tenant)
		if code != 200 {
			t.Fatalf("%s: anomalies status %d: %v", tc.tenant, code, body)
		}
		found, _ := body["findings"].([]any)
		if len(found) != int(tc.want) {
			t.Errorf("/api/baseline/anomalies?tenant=%s returned %d finding(s), want %v",
				tc.tenant, len(found), tc.want)
		}
		for _, f := range found {
			if bin := f.(map[string]any)["binary"]; bin != "/usr/bin/"+tc.tenant+"-tool" {
				t.Fatalf("a finding from %v leaked into %s's anomaly list", bin, tc.tenant)
			}
		}

		code, body = enrichmentGet(t, s, s.handleIntelMatches, "/api/intel/matches?tenant="+tc.tenant)
		if code != 200 {
			t.Fatalf("%s: matches status %d: %v", tc.tenant, code, body)
		}
	}
}

// A tenant-less read still resolves, and to the same tenant every other read
// path resolves it to. The console names a customer on the requests its funnel
// sends and on none of the others, so a 400 here would blank the panel for the
// personas that never name one.
func TestEnrichmentTenantlessReadStillResolves(t *testing.T) {
	s, _ := enrichmentServer(t)
	seedTenantProfile(t, s, "acme-corp", 4)
	p := keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/baseline", nil)
	tenant, ok := s.authorizeReadAs(w, r, p)
	if !ok {
		t.Fatalf("a tenant-less enrichment read was refused with %d %q",
			w.Code, strings.TrimSpace(w.Body.String()))
	}
	if tenant != "acme-corp" {
		t.Fatalf("resolved to %q, want the tenant on the account", tenant)
	}
	// One fact, one source: whoami tells the console which customer a
	// tenant-less read is about, and the panel must be built from that one.
	if who := s.whoamiFor(p); who["viewing_tenant"] != tenant {
		t.Fatalf("whoami says viewing_tenant=%v while enrichment resolves to %q",
			who["viewing_tenant"], tenant)
	}
}

// A CROSS-TENANT enrichment read is recorded. Reaching another customer's
// behavioural profile is reaching their data, and the whole point of the
// operator trail is that a customer can ask who from the provider opened their
// estate — a read that answers without a row is one they cannot see.
func TestCrossTenantEnrichmentReadIsAudited(t *testing.T) {
	s, aud := enrichmentServer(t)
	seedTenantProfile(t, s, "globex", 2)

	if code, body := enrichmentGet(t, s, s.handleBaseline, "/api/baseline?tenant=globex"); code != 200 {
		t.Fatalf("status %d: %v", code, body)
	}
	var got *authz.AuditRecord
	for _, rec := range aud.Records() {
		if rec.Tenant == "globex" && rec.Action == string(authz.ActionRead) {
			found := rec
			got = &found
			break
		}
	}
	if got == nil {
		t.Fatalf("a provider read globex's behavioural profile and no record was written: %v", aud.Records())
	}
	if !got.CrossTenant || !got.Allowed {
		t.Fatalf("record = %+v, want an allowed cross-tenant read", *got)
	}
	if got.Subject != "admin" {
		t.Fatalf("record names %q, want the operator who read", got.Subject)
	}
}

// HONOURING THE PARAMETER MUST NOT WIDEN ANYONE.
//
// A tenant-bound operator naming another customer is refused exactly as they
// are on every other read: a 404, which does not confirm whether that tenant
// exists (tenant-isolation-invariant §6 side channels). A 403 would answer the
// question the refusal exists to withhold.
//
// Driven through authorizeReadAs rather than the handler because the identity
// path that runs on the estate is an OIDC session no test can construct, and
// the only principal a handler test can present is the break-glass bearer
// token — which is cross-tenant and so is never the one refused. The AST test
// below is what binds this to the handlers.
func TestTenantBoundOperatorCannotNameAnotherCustomersEnrichment(t *testing.T) {
	for _, path := range []string{
		"/api/baseline?tenant=globex",
		"/api/baseline/anomalies?tenant=globex",
		"/api/intel?tenant=globex",
		"/api/intel/matches?tenant=globex",
		"/api/intel/lookup?q=1.2.3.4&tenant=globex",
	} {
		s, aud := enrichmentServer(t)
		seedTenantProfile(t, s, "globex", 5)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)

		tenant, ok := s.authorizeReadAs(w, r, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst))
		if ok {
			t.Fatalf("%s: an acme analyst read %q's enrichment", path, tenant)
		}
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404 — anything else confirms the tenant exists", path, w.Code)
		}
		if len(aud.Records()) == 0 {
			t.Fatalf("%s: a refused cross-tenant attempt was not recorded; a denied attempt is the "+
				"more interesting of the two records", path)
		}
	}
}

// enrichmentReadHandlers are the five reads that must go through the shared
// gate. handlePlatformDoc is deliberately absent: it serves the product
// glossary, which is the same for every tenant and belongs to none.
var enrichmentReadHandlers = []string{
	"handleBaseline",
	"handleBaselineAnomalies",
	"handleIntel",
	"handleIntelMatches",
	"handleIntelLookup",
}

// TestEveryEnrichmentReadUsesTheSharedGate traces the fix from the other end.
//
// The refusal test above proves what authorizeReadAs does, not that these
// handlers call it — and the defect was precisely a set of handlers with their
// OWN tenant resolution, which looked correct in isolation and ignored the
// parameter the console sends. A private resolution is the only shape this can
// come back in, so it is the shape that is pinned.
func TestEveryEnrichmentReadUsesTheSharedGate(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return fi.Name() == "enrichment.go"
	}, 0)
	if err != nil {
		t.Fatalf("parsing enrichment.go: %v", err)
	}
	want := map[string]bool{}
	for _, name := range enrichmentReadHandlers {
		want[name] = true
	}
	gated := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Body == nil || !want[fn.Name.Name] {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, isSel := n.(*ast.SelectorExpr); isSel && sel.Sel.Name == "authorizeRead" {
						gated[fn.Name.Name] = true
					}
					return true
				})
			}
		}
	}
	var missing []string
	for _, name := range enrichmentReadHandlers {
		if !gated[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these enrichment reads do not go through authorizeRead, so ?tenant= is inert on them "+
			"and the console's customer selector does not reach them: %s", strings.Join(missing, ", "))
	}
}
