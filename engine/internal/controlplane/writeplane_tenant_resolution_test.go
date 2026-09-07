package controlplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

// THE WRITE PLANE, FOR AN OPERATOR WHO NAMED NO TENANT.
//
// The console names a tenant on NO request it makes — not a containment, not a
// revert, not a mode change, not a settings write. So how the server resolves a
// tenant-less request IS the write plane, and resolving it through the wrong
// question takes every write down at once.
//
// The wrong question was authz.TenantScope, which answers "which tenants may
// this principal reach without naming one". For a cross-tenant role the honest
// answer is none — such an operator reaches a tenant by naming it, one audited
// access at a time — so the scope is empty and every containment, revert, mode
// change, policy push, attack and settings write by an MSOC admin or a
// cross-tenant responder answered 400 "tenant required".
//
// The right question is "which tenant is this tenant-less request ABOUT", whose
// answer is the tenant stamped on the account: authz.DefaultTenant, which is
// what the read plane already resolves with and what whoami publishes as
// viewing_tenant.
//
// These tests drive authorizeRespondAs / authorizeApproveAs rather than the
// handlers because the identity path that runs on the estate is an OIDC session
// no test can construct, and the only principal a handler test can otherwise
// reach is the break-glass bearer token — which carries no tenant and so never
// exercises the resolution at all. That is exactly why this shipped green.
// TestEveryTenantResolutionAsksTheRightQuestion below closes the gap from the
// other end: it pins that no handler anywhere in the package has its own copy.

// writeGateServer is a bare server with only what the authorization gates read.
func writeGateServer(aud authz.Auditor) *Server { return &Server{auditor: aud} }

func TestTenantlessWriteResolvesForEveryPersona(t *testing.T) {
	cases := []struct {
		name        string
		p           authz.Principal
		wantTenant  string
		wantCode    int // when the write is refused
		wantAudited bool
	}{
		{
			// The blocker. An MSOC admin's every write 400'd.
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
			// Unchanged, and it has to stay that way: a tenant-bound analyst
			// resolved correctly before the regression and must still.
			name:       "tenant analyst, no ?tenant=",
			p:          keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst),
			wantTenant: "acme-corp",
		},
		{
			// Resolution is not permission. read-only resolves to a tenant and
			// is then refused for the ACTION, as a 404 — never a 403, which
			// would confirm the tenant exists (§6 side channels).
			name:        "read-only operator may not respond",
			p:           keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly),
			wantCode:    http.StatusNotFound,
			wantAudited: true, // a refused attempt is the more interesting record
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
		s := writeGateServer(aud)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/choke/manual", nil)
		tenant, ok := s.authorizeRespondAs(w, r, c.p)

		if c.wantCode != 0 {
			if ok {
				t.Errorf("%s: write allowed on tenant %q, want refusal", c.name, tenant)
			} else if w.Code != c.wantCode {
				t.Errorf("%s: status %d, want %d", c.name, w.Code, c.wantCode)
			}
		} else {
			if !ok {
				t.Errorf("%s: a tenant-less containment was refused with %d %q — that is the whole write plane",
					c.name, w.Code, strings.TrimSpace(w.Body.String()))
				continue
			}
			if tenant != c.wantTenant {
				t.Errorf("%s: resolved to %q, want %q", c.name, tenant, c.wantTenant)
			}
			// The write must land on the tenant the console says is on screen.
			// Two sources for one fact is how they drift, and here a drift
			// means containing a host in the wrong customer's estate.
			if who := whoamiJSON(t, s, c.p); who["viewing_tenant"] != tenant {
				t.Errorf("%s: whoami says viewing_tenant=%v while writes resolve to %q",
					c.name, who["viewing_tenant"], tenant)
			}
		}
		// A write resolved through a cross-tenant role is audited wherever a
		// read would be — operator_audit is written from Authorize's outcome,
		// so the check is that the call still runs, not that a second trail
		// exists.
		if got := len(aud.Records()) > 0; got != c.wantAudited {
			t.Errorf("%s: audited=%v, want %v (records: %v)", c.name, got, c.wantAudited, aud.Records())
		}
	}
}

// Naming ANOTHER tenant is still refused as a 404. Resolving a tenant-less
// request more generously must not have softened the named case: confirming
// another tenant's resource exists is the side channel the invariant forbids.
func TestNamingAnotherTenantOnAWriteIsStillRefused(t *testing.T) {
	s := writeGateServer(authz.NewMemAuditor())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/choke/manual?tenant=adanian-internal", nil)
	if tenant, ok := s.authorizeRespondAs(w, r, keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst)); ok {
		t.Fatalf("an analyst contained a host in another tenant: %q", tenant)
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

// The approval queue is the release valve for exactly the destructive actions
// change-control gates, and the operators who staff it across customers are the
// cross-tenant ones — so it had the same defect and needs the same proof.
func TestTenantlessApprovalDecisionResolvesForEveryPersona(t *testing.T) {
	cases := []struct {
		name       string
		p          authz.Principal
		bodyTenant string
		wantTenant string
		wantCode   int
	}{
		{
			name:       "cross-tenant admin decides with no tenant in the body",
			p:          keycloakPrincipal("msoc@provider", "adanian-internal", authz.RoleMSOCAdmin),
			wantTenant: "adanian-internal",
		},
		{
			name:       "cross-tenant responder decides with no tenant in the body",
			p:          keycloakPrincipal("xr@provider", "adanian-internal", authz.RoleCrossTenantResponder),
			wantTenant: "adanian-internal",
		},
		{
			name:       "tenant analyst is unchanged",
			p:          keycloakPrincipal("op@acme", "acme-corp", authz.RoleTenantAnalyst),
			wantTenant: "acme-corp",
		},
		{
			// An explicit tenant still wins over the default.
			name:       "an explicit tenant in the body still wins",
			p:          keycloakPrincipal("msoc@provider", "adanian-internal", authz.RoleMSOCAdmin),
			bodyTenant: "acme-corp",
			wantTenant: "acme-corp",
		},
		{
			name:     "read-only operator may not approve",
			p:        keycloakPrincipal("ro@acme", "acme-corp", authz.RoleReadOnly),
			wantCode: http.StatusNotFound,
		},
		{
			name:     "admin bearer token, which carries no tenant",
			p:        authz.Principal{Subject: "admin", Grants: []authz.Grant{{Role: authz.RoleMSOCAdmin}}},
			wantCode: http.StatusBadRequest,
		},
	}
	for _, c := range cases {
		s := writeGateServer(authz.NewMemAuditor())
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/approvals/decide", nil)
		tenant, ok := s.authorizeApproveAs(w, r, c.p, c.bodyTenant)
		if c.wantCode != 0 {
			if ok {
				t.Errorf("%s: decision allowed on tenant %q, want refusal", c.name, tenant)
			} else if w.Code != c.wantCode {
				t.Errorf("%s: status %d, want %d", c.name, w.Code, c.wantCode)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: a tenant-less decision was refused with %d %q — the approval queue is the way OUT",
				c.name, w.Code, strings.TrimSpace(w.Body.String()))
			continue
		}
		if tenant != c.wantTenant {
			t.Errorf("%s: resolved to %q, want %q", c.name, tenant, c.wantTenant)
		}
	}
}

// tenantScopeIsReachNotResolution names the only two places in this package
// entitled to call authz.TenantScope. Both publish REACH — "which tenants are
// yours" — which is the question TenantScope actually answers:
//
//   - whoamiFor, which publishes it as `tenants` (and resolution separately, as
//     `viewing_tenant`).
//   - handleOperatorAudit, which uses it to pick WHICH tenant's access rows a
//     tenant-bound analyst may read, and takes a different branch entirely for
//     a cross-tenant one.
//
// Anywhere else it is being used to answer "which tenant is this request
// about", and that substitution is what killed the write plane.
var tenantScopeIsReachNotResolution = map[string]bool{
	"whoamiFor":           true,
	"handleOperatorAudit": true,
}

// TestEveryTenantResolutionAsksTheRightQuestion traces the fix to the call
// sites from the other end.
//
// The previous two passes each reported this fixed while a handler kept its own
// copy of the bad resolution, so a fix to the shared gate alone proves nothing.
// This walks every non-test function in the package and fails on any NEW caller
// of authz.TenantScope, which is the only shape the regression can take: a
// tenant-less request resolved through a value that is empty for exactly the
// operators who work across tenants.
func TestEveryTenantResolutionAsksTheRightQuestion(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}
	var offenders []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, isFunc := decl.(*ast.FuncDecl)
				if !isFunc || fn.Body == nil || tenantScopeIsReachNotResolution[fn.Name.Name] {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					sel, isSel := n.(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != "TenantScope" {
						return true
					}
					if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "authz" {
						offenders = append(offenders,
							fn.Name.Name+" ("+fset.Position(sel.Pos()).String()+")")
					}
					return true
				})
			}
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("authz.TenantScope states REACH and is EMPTY for a cross-tenant role; using it to "+
			"resolve a tenant-less request answers 400 to every write a provider operator makes. "+
			"Use authz.DefaultTenant (see authorizeRespondAs). Offenders: %s",
			strings.Join(offenders, ", "))
	}
}
