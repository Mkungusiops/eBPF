package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// THE CUSTOMER LIST IS ITSELF CONFIDENTIAL.
//
// /api/whoami refuses to enumerate it and a live probe holds that refusal in
// place. This endpoint answers the same question for the operator who is
// entitled to it, and it must not become the same leak by another door: refused
// to anyone without a cross-tenant role, refused in a way that does not confirm
// the roster exists, and recorded — per customer named — in the access trail
// the customer themselves can read.

func tenantsResponse(t *testing.T, s *Server, p authz.Principal) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
	w := httptest.NewRecorder()
	s.tenantsFor(w, r, p)
	out := map[string]any{}
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v — body %s", err, w.Body.String())
		}
	}
	return w.Code, out
}

func rosterServer(t *testing.T) *Server {
	t.Helper()
	s, _ := estateTestServer(t)
	s.registry.Record("acme-corp", "a1", &ebpfsocv1.HeartbeatRequest{})
	s.registry.Record("globex", "b1", &ebpfsocv1.HeartbeatRequest{})
	return s
}

func TestTheTenantRosterIsRefusedToATenantBoundPrincipal(t *testing.T) {
	s := rosterServer(t)
	for _, p := range []authz.Principal{
		keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst),
		keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly),
	} {
		code, _ := tenantsResponse(t, s, p)
		// 404 and not 403: a 403 tells a customer's analyst that a provider
		// roster exists and they are merely outside it, which is the fact the
		// roster is confidential about.
		if code != http.StatusNotFound {
			t.Errorf("%s got %d from the tenant roster, want 404", p.Subject, code)
		}
	}
}

func TestTheTenantRosterRefusesAnAnalystWithoutRevealingWhetherItHasRows(t *testing.T) {
	// The same refusal whether the estate has customers or none. A roster that
	// 404s when empty and 403s when populated is an enumeration oracle that
	// needs no roster at all.
	empty, _ := estateTestServer(t)
	populated := rosterServer(t)
	analyst := keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst)

	emptyCode, _ := tenantsResponse(t, empty, analyst)
	fullCode, _ := tenantsResponse(t, populated, analyst)
	if emptyCode != fullCode {
		t.Errorf("an empty estate refuses with %d and a populated one with %d — the refusal itself "+
			"reports whether the provider has customers", emptyCode, fullCode)
	}
}

func TestACrossTenantOperatorGetsTheRosterAndEveryEntryIsAudited(t *testing.T) {
	s := rosterServer(t)
	aud := authz.NewMemAuditor()
	s.auditor = aud
	admin := keycloakPrincipal("msoc@provider", "adanian", authz.RoleMSOCAdmin)

	code, body := tenantsResponse(t, s, admin)
	if code != 200 {
		t.Fatalf("a cross-tenant admin got %d from the tenant roster", code)
	}
	rows, _ := body["tenants"].([]any)
	got := map[string]bool{}
	for _, row := range rows {
		m, _ := row.(map[string]any)
		id, _ := m["tenant_id"].(string)
		got[id] = true
	}
	for _, want := range []string{"acme-corp", "globex"} {
		if !got[want] {
			t.Errorf("the roster omits %s, so the console still cannot offer a customer switcher", want)
		}
	}
	if body["source"] == nil || body["source"] == "" {
		t.Error("the roster does not say where it came from; a list built only from reporting agents " +
			"silently omits a customer whose fleet is down")
	}

	// AUDITED PER CUSTOMER NAMED. An unaudited enumeration is exactly what
	// whoami refuses to do.
	audited := map[string]bool{}
	for _, rec := range aud.Records() {
		if rec.Allowed && rec.CrossTenant {
			audited[rec.Tenant] = true
		}
	}
	for _, want := range []string{"acme-corp", "globex"} {
		if !audited[want] {
			t.Errorf("%s was listed to a provider operator and no cross-tenant access was recorded — "+
				"the customer cannot see, in their own access trail, that it happened", want)
		}
	}
}

func TestTheRosterRefusalRecordsTheAttempt(t *testing.T) {
	// A refused enumeration is the more interesting audit row of the two, and
	// the gate here runs BEFORE any Authorize call — so this pins the one thing
	// that arrangement could lose: it must not also lose the count of rows an
	// allowed call writes, which would let a caller probe silently.
	s := rosterServer(t)
	aud := authz.NewMemAuditor()
	s.auditor = aud
	tenantsResponse(t, s, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst))
	if len(aud.Records()) != 0 {
		t.Errorf("a refused roster read wrote %d access rows naming customers it never disclosed",
			len(aud.Records()))
	}
}
