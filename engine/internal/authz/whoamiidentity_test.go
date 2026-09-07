package authz

import "testing"

// The two facts whoami publishes about an operator — what they are called, and
// which customers they are shown — and the ways both used to be wrong.
//
// Both defects were found by the live persona probes against the AWS estate,
// not by a unit test, because both depend on what Keycloak actually puts in the
// token. keycloakGrants below reproduces that: identity.PrincipalFromClaims
// stamps the account's `tenant` attribute onto EVERY realm role, the realm's
// default composites included, and those carry no capability here.

// keycloakGrants builds the grants a real token produces: the account's own
// role plus the realm defaults Keycloak adds to every user, each stamped with
// the account's tenant attribute.
func keycloakGrants(tenant string, roles ...Role) []Grant {
	all := append([]Role{}, roles...)
	all = append(all, "default-roles-ebpf-soc", "offline_access", "uma_authorization")
	grants := make([]Grant, 0, len(all))
	for _, r := range all {
		grants = append(grants, Grant{Role: r, TenantID: tenant})
	}
	return grants
}

// A cross-tenant principal must not come back scoped to one customer. Its only
// capable role is cross-tenant and therefore excluded from the scope by design;
// what remained were the realm defaults, which authorize nothing — so callers
// that fall back to scope[0] pinned the provider's estate-wide operator to
// whichever tenant its Keycloak account happened to be stamped with.
func TestTenantScopeIgnoresGrantsThatAuthorizeNothing(t *testing.T) {
	for _, role := range []Role{RoleMSOCAdmin, RoleCrossTenantResponder} {
		p := Principal{Subject: "msoc@provider", Grants: keycloakGrants("adanian-internal", role)}
		if scope := TenantScope(p); len(scope) != 0 {
			t.Fatalf("%s scope = %v, want none: every grant left in it authorizes no read at all", role, scope)
		}
	}

	// The realm defaults are equally inert for a tenant-bound operator: their
	// scope is their real grant, not that grant plus three copies of itself.
	ro := Principal{Subject: "ro@acme", Grants: keycloakGrants("acme-corp", RoleReadOnly)}
	scope := TenantScope(ro)
	if len(scope) != 1 || scope[0] != "acme-corp" {
		t.Fatalf("read-only scope = %v, want [acme-corp]", scope)
	}
}

// A read-only operator keeps their tenant scope: the fix must not cost the
// least-privileged persona the console they are entitled to.
func TestTenantScopeKeepsEveryTenantTheOperatorCanRead(t *testing.T) {
	p := Principal{Subject: "mixed", Grants: []Grant{
		{Role: RoleReadOnly, TenantID: "tenant-a"},
		{Role: RoleTenantAnalyst, TenantID: "tenant-b"},
	}}
	scope := TenantScope(p)
	if len(scope) != 2 || scope[0] != "tenant-a" || scope[1] != "tenant-b" {
		t.Fatalf("scope = %v, want [tenant-a tenant-b]", scope)
	}
}

// The published role name must follow the two axes that separate the roles —
// reach and capability — not a single cross-tenant bit. Under the old
// derivation a read-only operator was named "tenant-analyst" and a
// cross-tenant responder "msoc-admin": in both cases the name of a role the
// principal does not hold.
func TestPrimaryRoleNamesTheRoleTheOperatorHolds(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
		want Role
	}{
		{"read-only operator", Principal{Grants: keycloakGrants("acme-corp", RoleReadOnly)}, RoleReadOnly},
		{"tenant analyst", Principal{Grants: keycloakGrants("acme-corp", RoleTenantAnalyst)}, RoleTenantAnalyst},
		{"msoc admin", Principal{Grants: keycloakGrants("adanian-internal", RoleMSOCAdmin)}, RoleMSOCAdmin},
		{"cross-tenant responder", Principal{Grants: keycloakGrants("adanian-internal", RoleCrossTenantResponder)}, RoleCrossTenantResponder},
		// Precedence, not token order: the strongest held role names the
		// operator, whichever way round Keycloak listed them.
		{"analyst who also holds read-only", Principal{Grants: []Grant{
			{Role: RoleReadOnly, TenantID: "acme-corp"},
			{Role: RoleTenantAnalyst, TenantID: "acme-corp"},
		}}, RoleTenantAnalyst},
		{"read-only listed after the analyst grant", Principal{Grants: []Grant{
			{Role: RoleTenantAnalyst, TenantID: "acme-corp"},
			{Role: RoleReadOnly, TenantID: "acme-corp"},
		}}, RoleTenantAnalyst},
		// No recognised role: the honest answer is no name. Inventing one
		// would restate the same lie about an account that can do nothing.
		{"realm defaults only", Principal{Grants: keycloakGrants("acme-corp")}, ""},
		{"no grants at all", Principal{}, ""},
	}
	for _, c := range cases {
		if got := PrimaryRole(c.p); got != c.want {
			t.Errorf("%s: PrimaryRole = %q, want %q", c.name, got, c.want)
		}
	}
}

// The name and the capability must agree, because the console states both: a
// role named "read-only" beside an enabled containment button, or a responder
// named as an administrator, is exactly the confusion these fields exist to
// prevent.
func TestPrimaryRoleAgreesWithCanRespond(t *testing.T) {
	ro := Principal{Grants: keycloakGrants("acme-corp", RoleReadOnly)}
	if PrimaryRole(ro) != RoleReadOnly || CanRespond(ro) {
		t.Fatalf("read-only operator published as %q with can_respond=%v", PrimaryRole(ro), CanRespond(ro))
	}
	xr := Principal{Grants: keycloakGrants("adanian-internal", RoleCrossTenantResponder)}
	if PrimaryRole(xr) != RoleCrossTenantResponder || !CanRespond(xr) || !HasCrossTenant(xr) {
		t.Fatalf("cross-tenant responder published as %q, can_respond=%v, cross_tenant=%v",
			PrimaryRole(xr), CanRespond(xr), HasCrossTenant(xr))
	}
}

// The scope and the DEFAULT are two different questions, and collapsing them
// broke the provider console in the other direction.
//
// TenantScope answers "which tenants are yours" — for a cross-tenant operator,
// none. DefaultTenant answers "which tenant does a request that named none
// resolve to" — for the same operator, the tenant stamped on their Keycloak
// account, which is what the server has always resolved those reads to and what
// the console is already being shown. A read path routed through the scope
// instead answers "tenant required" to every panel on the dashboard, because
// the console names a tenant on no request it makes.
func TestDefaultTenantAnswersForThePrincipalTheScopeDeliberatelyDoesNot(t *testing.T) {
	for _, role := range []Role{RoleMSOCAdmin, RoleCrossTenantResponder} {
		p := Principal{Subject: "provider@soc", Grants: keycloakGrants("adanian-internal", role)}
		if scope := TenantScope(p); len(scope) != 0 {
			t.Fatalf("%s: scope = %v, want none", role, scope)
		}
		if got := DefaultTenant(p); got != "adanian-internal" {
			t.Fatalf("%s: DefaultTenant = %q, want adanian-internal — every tenant-less read from this console would be refused", role, got)
		}
	}

	// A tenant-bound operator resolves to the same tenant either way; the two
	// functions differ only for the persona the scope excludes.
	an := Principal{Subject: "op@acme", Grants: keycloakGrants("acme-corp", RoleTenantAnalyst)}
	if got := DefaultTenant(an); got != "acme-corp" {
		t.Fatalf("analyst DefaultTenant = %q, want acme-corp", got)
	}

	// The break-glass admin bearer token carries a cross-tenant role and NO
	// tenant at all. There is nothing to resolve to and nothing may be
	// invented: the caller has to refuse.
	bearer := Principal{Subject: "admin", Grants: []Grant{{Role: RoleMSOCAdmin}}}
	if got := DefaultTenant(bearer); got != "" {
		t.Fatalf("bearer admin DefaultTenant = %q, want empty — a tenant was invented for a principal that names none", got)
	}
}

// DefaultTenant must never be read as a grant. It names a tenant; whether the
// principal may read it is still Authorize's answer, and for a cross-tenant
// principal that answer is recorded.
func TestDefaultTenantConfersNothingWithoutAuthorize(t *testing.T) {
	aud := NewMemAuditor()
	p := Principal{Subject: "provider@soc", Grants: keycloakGrants("adanian-internal", RoleMSOCAdmin)}
	d := Authorize(p, DefaultTenant(p), ActionRead, aud)
	if !d.Allowed || !d.CrossTenant {
		t.Fatalf("read of the resolved tenant: allowed=%v crossTenant=%v, want true/true", d.Allowed, d.CrossTenant)
	}
	if len(aud.Records()) != 1 {
		t.Fatalf("records = %d, want 1: a cross-tenant read resolved from the default must still be audited", len(aud.Records()))
	}

	// A read-only tenant-bound operator resolves to their own tenant and gets
	// no respond capability out of it.
	ro := Principal{Subject: "ro@acme", Grants: keycloakGrants("acme-corp", RoleReadOnly)}
	if Authorize(ro, DefaultTenant(ro), ActionRespond, nil).Allowed {
		t.Fatal("a read-only operator was authorized to respond on the tenant DefaultTenant resolved")
	}
}
