package identity

import (
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// TestPrincipalFromClaims: a tenant-bound role maps to own-tenant access and
// cannot widen (Layer 4); unknown roles are inert; preferred_username wins.
func TestPrincipalFromClaims(t *testing.T) {
	c := &Claims{Subject: "u1", PreferredUsername: "alice", Tenant: "tenant-a"}
	c.RealmAccess.Roles = []string{"tenant-analyst", "offline_access"} // 2nd is inert

	p := PrincipalFromClaims(c)
	if p.Subject != "alice" {
		t.Fatalf("subject = %q, want alice", p.Subject)
	}
	if !authz.Authorize(p, "tenant-a", authz.ActionRead, nil).Allowed {
		t.Fatal("own-tenant read denied")
	}
	if !authz.Authorize(p, "tenant-a", authz.ActionRespond, nil).Allowed {
		t.Fatal("tenant-analyst should be able to respond in its tenant")
	}
	if authz.Authorize(p, "tenant-b", authz.ActionRead, nil).Allowed {
		t.Fatal("mapped principal widened to tenant-b — Layer 4 violation")
	}
}

// TestCrossTenantRoleNotConfined: an msoc-admin claim maps to a cross-tenant
// grant that is not confined to the token's tenant, and its use is audited.
func TestCrossTenantRoleNotConfined(t *testing.T) {
	c := &Claims{Subject: "msoc", Tenant: "tenant-a"}
	c.RealmAccess.Roles = []string{"msoc-admin"}

	p := PrincipalFromClaims(c)
	aud := authz.NewMemAuditor()
	d := authz.Authorize(p, "tenant-b", authz.ActionRead, aud)
	if !d.Allowed || !d.CrossTenant {
		t.Fatalf("msoc-admin cross-tenant read = %+v, want allowed & cross-tenant", d)
	}
	if len(aud.Records()) != 1 {
		t.Fatal("cross-tenant access via mapped principal was not audited")
	}
}

// TestNoRolesFailsClosed: an authenticated user with no platform roles reaches
// nothing.
func TestNoRolesFailsClosed(t *testing.T) {
	p := PrincipalFromClaims(&Claims{Subject: "nobody", Tenant: "tenant-a"})
	if authz.Authorize(p, "tenant-a", authz.ActionRead, nil).Allowed {
		t.Fatal("a user with no roles must be denied")
	}
}
