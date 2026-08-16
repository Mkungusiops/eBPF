package controlplane

import (
	"errors"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/chatstore"
)

// scopeFor is the security boundary of the chat feature: it turns a verified
// session into the only thing that can reach a stored row. These tests exist
// because the failure mode is silent — a scope derived from the wrong place
// still works, it just works for the wrong person.

func TestScopeComesFromThePrincipalNotTheRequest(t *testing.T) {
	p := authz.Principal{
		Subject: "op-acme",
		Grants:  []authz.Grant{{Role: authz.RoleTenantAnalyst, TenantID: "acme-corp"}},
	}
	s, err := scopeFor(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.UserID != "op-acme" || s.TenantID != "acme-corp" {
		t.Errorf("scope = %+v, want user op-acme tenant acme-corp", s)
	}
	if s.CrossTenant {
		t.Error("a tenant-analyst was marked cross-tenant")
	}
}

func TestPrincipalWithNoSubjectIsRefused(t *testing.T) {
	// An unnamed caller must not get a scope. Chat history is per-operator, so
	// a scope with no user would either fail later in a confusing way or, worse,
	// match rows belonging to whoever had an empty user id.
	for _, p := range []authz.Principal{
		{},
		{Grants: []authz.Grant{{Role: authz.RoleMSOCAdmin}}},
		{Subject: "   ", Grants: []authz.Grant{{Role: authz.RoleTenantAnalyst, TenantID: "acme"}}},
	} {
		if _, err := scopeFor(p); !errors.Is(err, chatstore.ErrNoScope) {
			t.Errorf("principal %+v produced a scope; want ErrNoScope", p)
		}
	}
}

func TestCrossTenantRoleIsMarkedAndGetsASentinelTenant(t *testing.T) {
	p := authz.Principal{Subject: "msoc", Grants: []authz.Grant{{Role: authz.RoleMSOCAdmin}}}
	s, err := scopeFor(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.CrossTenant {
		t.Error("msoc-admin was not marked cross-tenant")
	}
	// Empty would make the RLS predicate compare against NULL and match
	// nothing, which reads as data loss rather than a scoping decision.
	if s.TenantID == "" {
		t.Error("cross-tenant scope has an empty tenant; RLS would match nothing")
	}
}

func TestCrossTenantDefinitionMatchesAuthz(t *testing.T) {
	// Two independent notions of "cross-tenant" is how they drift apart. This
	// asserts scopeFor uses authz's definition, not its own list.
	for _, role := range []authz.Role{authz.RoleMSOCAdmin, authz.RoleCrossTenantResponder} {
		s, err := scopeFor(authz.Principal{Subject: "u", Grants: []authz.Grant{{Role: role}}})
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if !s.CrossTenant {
			t.Errorf("%s is cross-tenant in authz but not in scopeFor", role)
		}
	}
	for _, role := range []authz.Role{authz.RoleTenantAnalyst, authz.RoleReadOnly} {
		s, err := scopeFor(authz.Principal{Subject: "u", Grants: []authz.Grant{{Role: role, TenantID: "acme"}}})
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if s.CrossTenant {
			t.Errorf("%s is single-tenant in authz but cross-tenant in scopeFor", role)
		}
	}
}

func TestFirstTenantGrantWins(t *testing.T) {
	// A principal can hold grants in several tenants. The scope takes one and
	// is deterministic about it; the assistant's ANSWERS are still bounded by
	// the forwarded session, so this choice affects only which chats are
	// stamped where — never what can be read.
	p := authz.Principal{Subject: "u", Grants: []authz.Grant{
		{Role: authz.RoleTenantAnalyst, TenantID: "acme-corp"},
		{Role: authz.RoleTenantAnalyst, TenantID: "adanian-internal"},
	}}
	s, err := scopeFor(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.TenantID != "acme-corp" {
		t.Errorf("tenant = %q, want the first grant", s.TenantID)
	}
}
