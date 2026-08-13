package authz

import "testing"

func analystA() Principal {
	return Principal{Subject: "analyst@a", Grants: []Grant{{Role: RoleTenantAnalyst, TenantID: "tenant-a"}}}
}
func readOnlyA() Principal {
	return Principal{Subject: "ro@a", Grants: []Grant{{Role: RoleReadOnly, TenantID: "tenant-a"}}}
}
func msocAdmin() Principal {
	return Principal{Subject: "msoc@soc", Grants: []Grant{{Role: RoleMSOCAdmin}}}
}

// TestOwnTenantAllowedSilently: a tenant-analyst reaches their own tenant with
// no cross-tenant flag and no audit.
func TestOwnTenantAllowedSilently(t *testing.T) {
	aud := NewMemAuditor()
	d := Authorize(analystA(), "tenant-a", ActionRead, aud)
	if !d.Allowed || d.CrossTenant {
		t.Fatalf("own-tenant read = %+v, want allowed & not cross-tenant", d)
	}
	if len(aud.Records()) != 0 {
		t.Fatal("own-tenant access must not be audited as cross-tenant")
	}
}

// TestNoWideningToOtherTenant is the Layer 4 core: a tenant-bound operator
// cannot reach another tenant.
func TestNoWideningToOtherTenant(t *testing.T) {
	if d := Authorize(analystA(), "tenant-b", ActionRead, nil); d.Allowed {
		t.Fatalf("analyst@a reached tenant-b: %+v — Layer 4 widening!", d)
	}
}

func TestReadOnlyCannotRespond(t *testing.T) {
	if d := Authorize(readOnlyA(), "tenant-a", ActionRead, nil); !d.Allowed {
		t.Fatal("read-only must be able to read its tenant")
	}
	if d := Authorize(readOnlyA(), "tenant-a", ActionRespond, nil); d.Allowed {
		t.Fatalf("read-only must NOT be able to respond: %+v", d)
	}
}

// TestCrossTenantIsAllowedButAudited: the MSOC role reaches other tenants, and
// every such access is recorded (invariant T5).
func TestCrossTenantIsAllowedButAudited(t *testing.T) {
	aud := NewMemAuditor()
	d := Authorize(msocAdmin(), "tenant-b", ActionRespond, aud)
	if !d.Allowed || !d.CrossTenant {
		t.Fatalf("msoc-admin cross-tenant = %+v, want allowed & cross-tenant", d)
	}
	recs := aud.Records()
	if len(recs) != 1 || recs[0].Subject != "msoc@soc" || recs[0].Tenant != "tenant-b" || recs[0].Action != "respond" {
		t.Fatalf("cross-tenant access not audited correctly: %+v", recs)
	}
}

func TestEmptyTenantAndNoGrantsFailClosed(t *testing.T) {
	if d := Authorize(analystA(), "", ActionRead, nil); d.Allowed {
		t.Fatal("empty tenant must be denied (fail closed)")
	}
	if d := Authorize(Principal{Subject: "nobody"}, "tenant-a", ActionRead, nil); d.Allowed {
		t.Fatal("principal with no grants must be denied")
	}
}

// TestTenantScopeExcludesCrossTenant: scope lists only tenant-bound grants, so a
// cross-tenant role is never enumerated implicitly.
func TestTenantScopeExcludesCrossTenant(t *testing.T) {
	p := Principal{Subject: "mixed", Grants: []Grant{
		{Role: RoleReadOnly, TenantID: "tenant-a"},
		{Role: RoleTenantAnalyst, TenantID: "tenant-b"},
		{Role: RoleMSOCAdmin}, // cross-tenant — must NOT appear in scope
	}}
	scope := TenantScope(p)
	if len(scope) != 2 {
		t.Fatalf("scope = %v, want [tenant-a tenant-b]", scope)
	}
	for _, s := range scope {
		if s == "" {
			t.Fatal("scope contains an empty tenant (cross-tenant leaked in)")
		}
	}
	if !HasCrossTenant(p) {
		t.Fatal("HasCrossTenant should be true")
	}
}
