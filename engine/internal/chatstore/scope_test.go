package chatstore

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// This file is the ratchet for docs/plan/platform-assistant.md §1.
//
// The design rule is that the menu-bar chat is "a wider door into the same
// room, never a bigger room". The specific failure it guards against is not a
// mistake in this code — it is a plausible future optimisation: a global chat
// surface feels like one pane of glass, which invites giving the assistant a
// service identity so it can answer platform-wide questions. That single change
// would defeat RLS and every guard in internal/isolationguard.
//
// These tests make that change break the build.

func TestEveryStoreMethodTakesAScope(t *testing.T) {
	// The structural guarantee: there is no way to reach a row without
	// presenting a caller identity. A method that omits Scope is the shape the
	// dangerous refactor would take, so assert on the INTERFACE, not on an
	// implementation that could be swapped.
	iface := reflect.TypeOf((*Store)(nil)).Elem()
	scope := reflect.TypeOf(Scope{})
	if iface.NumMethod() == 0 {
		t.Fatal("Store has no methods — this test is vacuous")
	}
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		if m.Type.NumIn() == 0 || m.Type.In(0) != scope {
			t.Errorf("Store.%s does not take a Scope as its first argument; "+
				"every store call must carry the caller's identity (platform-assistant.md §1)",
				m.Name)
		}
	}
}

func TestNoAdminOrUnscopedMethodExists(t *testing.T) {
	// A named escape hatch is how this gets defeated in practice: not by
	// removing Scope, but by adding ListAllChats or GetChatAsService beside it.
	iface := reflect.TypeOf((*Store)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		name := strings.ToLower(iface.Method(i).Name)
		for _, bad := range []string{"all", "admin", "service", "system", "unscoped", "global"} {
			if strings.Contains(name, bad) {
				t.Errorf("Store.%s looks like a scope escape hatch (%q). If a caller "+
					"needs wider reach it must present a Scope that grants it, so the "+
					"widening is visible at the call site.", iface.Method(i).Name, bad)
			}
		}
	}
}

func TestScopeWithoutAUserIsRefused(t *testing.T) {
	// The convenient mistake: run the assistant with no caller so it can "see
	// everything". It must fail at the first store call, loudly, rather than
	// quietly returning someone else's conversations.
	for _, s := range []Scope{
		{},
		{TenantID: "acme-corp"},
		{TenantID: "acme-corp", CrossTenant: true},
		{UserID: "   "},
	} {
		if err := s.valid(); !errors.Is(err, ErrNoScope) {
			t.Errorf("Scope%+v was accepted (err=%v); a scope with no user must be refused", s, err)
		}
	}
}

func TestScopeRequiresATenantUnlessCrossTenant(t *testing.T) {
	if err := (Scope{UserID: "op-acme"}).valid(); !errors.Is(err, ErrNoScope) {
		t.Error("a single-tenant caller with no tenant was accepted")
	}
	// A cross-tenant role legitimately has no single tenant.
	if err := (Scope{UserID: "msoc", CrossTenant: true}).valid(); err != nil {
		t.Errorf("cross-tenant scope rejected: %v", err)
	}
	if err := (Scope{UserID: "op-acme", TenantID: "acme-corp"}).valid(); err != nil {
		t.Errorf("valid scope rejected: %v", err)
	}
}

func TestNotFoundIsIndistinguishableFromNotYours(t *testing.T) {
	// Absent and out-of-scope must be the same answer. Distinguishing them
	// tells a caller that a chat EXISTS in another scope, which is a
	// cross-tenant existence oracle — the same side-channel isolationguard
	// checks for on denials.
	if strings.Contains(strings.ToLower(ErrNotFound.Error()), "permission") ||
		strings.Contains(strings.ToLower(ErrNotFound.Error()), "denied") ||
		strings.Contains(strings.ToLower(ErrNotFound.Error()), "forbidden") {
		t.Errorf("ErrNotFound leaks that the row exists but is not yours: %q", ErrNotFound)
	}
}

func TestSchemaForcesRLSOnEveryTable(t *testing.T) {
	// ENABLE alone is not enough: the table OWNER bypasses RLS without FORCE,
	// and migrations run as the owner. Both tables carry their own tenant_id so
	// no policy depends on a join.
	for _, table := range []string{"assistant_chat", "assistant_message"} {
		for _, clause := range []string{
			"ALTER TABLE " + table + "    ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE " + table + "    FORCE  ROW LEVEL SECURITY",
		} {
			normalised := strings.Join(strings.Fields(clause), " ")
			if !strings.Contains(strings.Join(strings.Fields(schema), " "), normalised) {
				t.Errorf("schema is missing: %s", normalised)
			}
		}
		if !strings.Contains(schema, "CREATE POLICY tenant_isolation ON "+table) {
			t.Errorf("%s has no tenant_isolation policy", table)
		}
	}
	// A read query with its own tenant predicate would mask a policy that had
	// stopped working. RLS does the scoping.
	if strings.Contains(schema, "WHERE tenant_id =") {
		t.Error("schema carries a tenant predicate; RLS must do the scoping")
	}
}

func TestIDsAreNotSequential(t *testing.T) {
	// Chat ids appear in URLs. Sequential ids let a caller count their way to
	// the existence of other conversations.
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := newID()
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		if len(id) < 20 {
			t.Fatalf("id %q is too short to be unguessable", id)
		}
		seen[id] = true
	}
}
