package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// What /api/whoami says about the operator signed in — the two claims the live
// persona probes caught it getting wrong.
//
// The console renders `role` verbatim on the account surface and `host` as the
// estate identity in the top bar, so a wrong value in either is not cosmetic:
// it is the console stating an authority, or a customer, that is not the one in
// front of the operator.

// keycloakPrincipal reproduces what identity.PrincipalFromClaims makes of a
// real token: the account's role plus the realm's default composites, each
// stamped with the account's `tenant` attribute. The defects below only appear
// with those inert grants present, which is why the probes found them and the
// unit tests did not.
func keycloakPrincipal(subject, tenant string, roles ...authz.Role) authz.Principal {
	all := append([]authz.Role{}, roles...)
	all = append(all, "default-roles-ebpf-soc", "offline_access", "uma_authorization")
	grants := make([]authz.Grant, 0, len(all))
	for _, r := range all {
		grants = append(grants, authz.Grant{Role: r, TenantID: tenant})
	}
	return authz.Principal{Subject: subject, Grants: grants}
}

// whoamiJSON is the document as the CONSOLE receives it: marshalled and read
// back, so a Go nil slice is compared as the JSON null it becomes on the wire
// rather than as an empty list that never leaves the process.
func whoamiJSON(t *testing.T, s *Server, p authz.Principal) map[string]any {
	t.Helper()
	b, err := json.Marshal(s.whoamiFor(p))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWhoamiNamesTheRoleTheOperatorActuallyHolds(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name        string
		p           authz.Principal
		wantRole    string
		wantRespond bool
		wantCross   bool
	}{
		// Published as "tenant-analyst" before this: the name of the role
		// directly above them, the one that can respond.
		{"read-only operator", keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly), "read-only", false, false},
		{"tenant analyst", keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst), "tenant-analyst", true, false},
		{"msoc admin", keycloakPrincipal("msoc@provider", "adanian-internal", authz.RoleMSOCAdmin), "msoc-admin", true, true},
		// Published as "msoc-admin" before this, so nothing on screen told an
		// administrator apart from a responder.
		{"cross-tenant responder", keycloakPrincipal("xr@provider", "adanian-internal", authz.RoleCrossTenantResponder), "cross-tenant-responder", true, true},
	}
	for _, c := range cases {
		who := whoamiJSON(t, s, c.p)
		if got := who["role"]; got != c.wantRole {
			t.Errorf("%s: role = %v, want %q", c.name, got, c.wantRole)
		}
		if got := who["can_respond"]; got != c.wantRespond {
			t.Errorf("%s: can_respond = %v, want %v", c.name, got, c.wantRespond)
		}
		if got := who["cross_tenant"]; got != c.wantCross {
			t.Errorf("%s: cross_tenant = %v, want %v", c.name, got, c.wantCross)
		}
	}
}

// A tenant-bound operator is unchanged: their tenant is their scope and their
// estate label. The fix for the cross-tenant personas must not cost them that.
func TestWhoamiLeavesTheTenantBoundOperatorScopedToTheirTenant(t *testing.T) {
	s := &Server{}
	who := whoamiJSON(t, s, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst))
	if got := who["host"]; got != "acme-corp" {
		t.Fatalf("host = %v, want acme-corp", got)
	}
	tenants, _ := who["tenants"].([]any)
	if len(tenants) != 1 || tenants[0] != "acme-corp" {
		t.Fatalf("tenants = %v, want [acme-corp]", who["tenants"])
	}
	// For a tenant-bound operator the tenant on screen IS their tenant, so the
	// new field must agree with the old two rather than introduce a third
	// answer.
	if got := who["viewing_tenant"]; got != "acme-corp" {
		t.Fatalf("viewing_tenant = %v, want acme-corp", got)
	}
}

// The cross-tenant defect: the estate on screen was ONE customer, chosen by
// TenantScope out of grants that authorize nothing, and identical to what that
// customer's own analyst sees. A cross-tenant principal must be pinned to no
// single tenant — not in `host`, and not by a one-element tenant list.
//
// `viewing_tenant` is how the console is told the truth instead: the server
// still resolves this session's tenant-less reads to one customer (it always
// has, and refusing them blanks the dashboard), so it names that customer
// rather than letting the console present it as the whole book of business.
func TestWhoamiDoesNotPinACrossTenantOperatorToOneCustomer(t *testing.T) {
	s := &Server{}
	for _, role := range []authz.Role{authz.RoleMSOCAdmin, authz.RoleCrossTenantResponder} {
		who := whoamiJSON(t, s, keycloakPrincipal("provider@soc", "adanian-internal", role))
		if got := who["host"]; got == "adanian-internal" {
			t.Fatalf("%s: host = %v — one customer's name presented as the whole estate", role, got)
		}
		if got := who["host"]; got != crossTenantHost {
			t.Fatalf("%s: host = %v, want %q", role, got, crossTenantHost)
		}
		// A cross-tenant role is not a tenant list. It reaches a tenant by
		// naming it, one audited read at a time, so there is nothing here to
		// enumerate and nothing for a caller to pin itself to element 0 of.
		if got := who["tenants"]; got != nil {
			t.Fatalf("%s: tenants = %v, want null for a principal holding no tenant-bound grant", role, got)
		}
		// The one tenant this session is actually being shown, stated. Without
		// it the console has no honest label for the data on screen.
		if got := who["viewing_tenant"]; got != "adanian-internal" {
			t.Fatalf("%s: viewing_tenant = %v, want adanian-internal — the tenant this server resolves this session's reads to", role, got)
		}
	}
}

// THE ROSTER MUST NOT BE PUBLISHED HERE. An MSSP's customer list is itself
// confidential: msoc.probe.spec.ts proves an analyst cannot enumerate it by
// guessing names, and whoami must not be the route that simply hands it over.
//
// An earlier attempt at the pinning fix filled `tenants` for a cross-tenant
// principal from the tenants table — every enrolled customer, with no
// authz.Authorize call and no audit record, on the one endpoint the console
// calls on every poll. This asserts the shape that cannot do that: the document
// names no tenant the principal does not hold a grant for.
//
// A unit test cannot supply a second real tenant (the roster came from the
// Postgres store), so the live probe against a two-tenant estate is what
// measures this; what is pinned here is that every tenant-shaped field in the
// document is derived from the principal's own grants.
func TestWhoamiNamesNoTenantTheOperatorDoesNotHold(t *testing.T) {
	s := &Server{}
	const foreign = "other-customer"
	for _, p := range []authz.Principal{
		keycloakPrincipal("provider@soc", "adanian-internal", authz.RoleMSOCAdmin),
		keycloakPrincipal("xr@provider", "adanian-internal", authz.RoleCrossTenantResponder),
		keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst),
		keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly),
	} {
		doc, err := json.Marshal(s.whoamiFor(p))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(doc), foreign) {
			t.Fatalf("whoami for %s names %q, a tenant it holds no grant for: %s", p.Subject, foreign, doc)
		}
	}
}

// The wiring, end to end over HTTP: the bearer-token admin is a cross-tenant
// principal, and the JSON the console actually receives must carry the same
// answers. A contract proved only against an unexported helper is the shape of
// bug this codebase keeps finding.
func TestWhoamiEndpointPublishesTheCrossTenantAdminHonestly(t *testing.T) {
	s := &Server{}
	s.cfg.AdminToken = "admin-secret"

	req := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	s.handleWhoami(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["role"] != "msoc-admin" || got["cross_tenant"] != true || got["can_respond"] != true {
		t.Fatalf("whoami = %v, want role=msoc-admin cross_tenant=true can_respond=true", got)
	}
	if got["host"] != crossTenantHost {
		t.Fatalf("host = %v, want %q", got["host"], crossTenantHost)
	}
	if got["tenants"] != nil {
		t.Fatalf("tenants = %v, want null for a principal with no tenant-bound grant", got["tenants"])
	}
	// The bearer admin carries no tenant at all, so there is no session tenant
	// to name and none may be invented — the read path refuses instead (see
	// TestTenantLessReadResolvesExactlyAsTheServerAlwaysHas).
	if got["viewing_tenant"] != "" {
		t.Fatalf("viewing_tenant = %v, want empty for a principal that names no tenant", got["viewing_tenant"])
	}
}

func TestWhoamiRefusesAnUnauthenticatedRead(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleWhoami(w, httptest.NewRequest(http.MethodGet, "/api/whoami", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", w.Code)
	}
}

// THE READ PATH, for every persona — and the regression that made this test
// necessary. An attempt at the pinning fix answered 400 to any tenant-less read
// from a cross-tenant principal. The console names a tenant on no request it
// makes (`grep -rn "tenant=" web/src` finds nothing), so that is every panel on
// the MSOC operator's dashboard: an all-error console, in the name of not
// guessing a tenant the server had in fact always resolved.
//
// What the fix changes is what is PUBLISHED (the scope stops claiming a tenant
// the principal holds no grant for, and whoami names the tenant on screen), not
// what is resolved. Both are asserted here together, because the value the
// console is told and the value the server reads by must be the same one.
func TestTenantLessReadResolvesExactlyAsTheServerAlwaysHas(t *testing.T) {
	cases := []struct {
		name        string
		p           authz.Principal
		wantTenant  string
		wantCode    int // when the read is refused
		wantAudited bool
	}{
		{
			name:        "cross-tenant admin, no ?tenant=",
			p:           keycloakPrincipal("msoc@provider", "adanian-internal", authz.RoleMSOCAdmin),
			wantTenant:  "adanian-internal",
			wantAudited: true, // reaching a tenant via a cross-tenant role is always recorded
		},
		{
			name:        "cross-tenant responder, no ?tenant=",
			p:           keycloakPrincipal("xr@provider", "adanian-internal", authz.RoleCrossTenantResponder),
			wantTenant:  "adanian-internal",
			wantAudited: true,
		},
		{
			name:       "tenant analyst, no ?tenant=",
			p:          keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst),
			wantTenant: "acme-corp",
		},
		{
			name:       "read-only operator, no ?tenant=",
			p:          keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly),
			wantTenant: "acme-corp",
		},
		{
			// The break-glass bearer token names no tenant anywhere, so there
			// is nothing to resolve and nothing may be invented.
			name:     "admin bearer token, which carries no tenant",
			p:        authz.Principal{Subject: "admin", Grants: []authz.Grant{{Role: authz.RoleMSOCAdmin}}},
			wantCode: http.StatusBadRequest,
		},
	}
	for _, c := range cases {
		aud := authz.NewMemAuditor()
		s := &Server{auditor: aud}
		w := httptest.NewRecorder()
		tenant, ok := s.authorizeReadAs(w, httptest.NewRequest(http.MethodGet, "/api/alerts", nil), c.p)

		if c.wantCode != 0 {
			if ok {
				t.Errorf("%s: read allowed on tenant %q, want refusal", c.name, tenant)
			}
			if w.Code != c.wantCode {
				t.Errorf("%s: status %d, want %d", c.name, w.Code, c.wantCode)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: tenant-less read refused with %d %q — this is every panel on the console", c.name, w.Code, w.Body.String())
			continue
		}
		if tenant != c.wantTenant {
			t.Errorf("%s: resolved to %q, want %q", c.name, tenant, c.wantTenant)
		}
		// Cross-tenant reach is audited whether the tenant was named in the
		// query or resolved from the account; own-tenant reads are the ordinary
		// case and are not recorded.
		if got := len(aud.Records()) > 0; got != c.wantAudited {
			t.Errorf("%s: audited=%v, want %v (records: %v)", c.name, got, c.wantAudited, aud.Records())
		}
		// And what whoami told the console is the tenant it is actually being
		// served. Two sources for one fact is how they drift.
		if who := whoamiJSON(t, s, c.p); who["viewing_tenant"] != tenant {
			t.Errorf("%s: whoami says viewing_tenant=%v while reads resolve to %q", c.name, who["viewing_tenant"], tenant)
		}
	}
}

// Naming another tenant is still refused as a 404, not a 403: confirming the
// resource exists is the side channel the invariant forbids (§6). The
// resolution change above must not have softened it.
func TestNamingAnotherTenantIsStillRefusedWithoutConfirmingItExists(t *testing.T) {
	s := &Server{auditor: authz.NewMemAuditor()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/alerts?tenant=adanian-internal", nil)
	if tenant, ok := s.authorizeReadAs(w, r, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst)); ok {
		t.Fatalf("an analyst read another tenant: %q", tenant)
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
}
