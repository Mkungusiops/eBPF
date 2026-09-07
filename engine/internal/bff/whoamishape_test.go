package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// Handler.Whoami is not mounted by Routes and nothing in cmd/controlplane wires
// it: the console's /api/whoami is controlplane.whoamiFor. It is kept for the
// Keycloak integration test above, which needs a protected endpoint to prove a
// session maps to a principal — and that is exactly how it drifted, because a
// shape nobody exercises without a live Keycloak is a shape nobody checks.
//
// So this pins the fields it publishes against the control plane's meanings:
// the role the principal HOLDS (not a name derived from cross-tenant reach),
// no enumeration of tenants it holds no grant for, and the session's resolved
// tenant stated rather than implied by element 0 of a list.
func TestWhoamiPublishesTheSameFactsAsTheControlPlane(t *testing.T) {
	kc := func(tenant string, roles ...authz.Role) authz.Principal {
		all := append(append([]authz.Role{}, roles...), "default-roles-ebpf-soc", "offline_access")
		grants := make([]authz.Grant, 0, len(all))
		for _, r := range all {
			grants = append(grants, authz.Grant{Role: r, TenantID: tenant})
		}
		return authz.Principal{Subject: "who@example.com", Grants: grants}
	}
	cases := []struct {
		name       string
		p          authz.Principal
		wantRole   string
		wantCross  bool
		wantView   string
		wantTenant any // "tenants", as it lands on the wire
	}{
		{"read-only operator", kc("acme-corp", authz.RoleReadOnly), "read-only", false, "acme-corp", []any{"acme-corp"}},
		{"tenant analyst", kc("acme-corp", authz.RoleTenantAnalyst), "tenant-analyst", false, "acme-corp", []any{"acme-corp"}},
		// A cross-tenant principal holds no tenant-bound grant, so it is listed
		// under no tenant at all — and the roster is NOT substituted in, here or
		// anywhere else: the provider's customer list is confidential and would
		// be published with no Authorize call and no audit record.
		{"msoc admin", kc("adanian-internal", authz.RoleMSOCAdmin), "msoc-admin", true, "adanian-internal", nil},
		{"cross-tenant responder", kc("adanian-internal", authz.RoleCrossTenantResponder), "cross-tenant-responder", true, "adanian-internal", nil},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/whoami", nil).
			WithContext(context.WithValue(context.Background(), ctxKey{}, c.p))
		(&Handler{}).Whoami(w, r)

		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %v (%s)", c.name, err, w.Body.String())
		}
		if got["role"] != c.wantRole {
			t.Errorf("%s: role = %v, want %q", c.name, got["role"], c.wantRole)
		}
		if got["cross_tenant"] != c.wantCross {
			t.Errorf("%s: cross_tenant = %v, want %v", c.name, got["cross_tenant"], c.wantCross)
		}
		if got["viewing_tenant"] != c.wantView {
			t.Errorf("%s: viewing_tenant = %v, want %q", c.name, got["viewing_tenant"], c.wantView)
		}
		switch want := c.wantTenant.(type) {
		case nil:
			if got["tenants"] != nil {
				t.Errorf("%s: tenants = %v, want null", c.name, got["tenants"])
			}
		case []any:
			list, _ := got["tenants"].([]any)
			if len(list) != len(want) || (len(want) > 0 && list[0] != want[0]) {
				t.Errorf("%s: tenants = %v, want %v", c.name, got["tenants"], want)
			}
		}
	}
}

func TestWhoamiRefusesARequestWithNoPrincipal(t *testing.T) {
	w := httptest.NewRecorder()
	(&Handler{}).Whoami(w, httptest.NewRequest(http.MethodGet, "/api/whoami", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", w.Code)
	}
}
