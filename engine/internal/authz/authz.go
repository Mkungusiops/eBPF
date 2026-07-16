// Package authz is the API-layer tenant-scoping and RBAC decision point — Layer
// 4 of the tenant isolation invariant (docs/plan/tenant-isolation-invariant.md).
//
// It is default-deny: an operator reaches exactly the tenants named by their
// role grants and no more. Widening beyond one's own tenant is possible ONLY via
// an explicit cross-tenant MSOC role, and every such access is recorded through
// an Auditor — the "explicit, audited cross-tenant" exception the invariant
// permits (§4 Layer 4, §7 T5).
//
// This package is transport-agnostic: it makes the decision; the API gateway
// turns a denial into a 404 (never confirming another tenant's resource exists —
// §6 side channels) and hands the authorized tenant scope to the Layer-3 store.
package authz

import (
	"sync"
	"time"
)

// Role is a coarse RBAC role. For tenant isolation the load-bearing distinction
// is whether a role is tenant-bound or cross-tenant (see isCrossTenant).
type Role string

const (
	RoleReadOnly             Role = "read-only"              // tenant-bound: read
	RoleTenantAnalyst        Role = "tenant-analyst"         // tenant-bound: read + respond
	RoleMSOCAdmin            Role = "msoc-admin"             // cross-tenant: read + respond
	RoleCrossTenantResponder Role = "cross-tenant-responder" // cross-tenant: read + respond
)

// Action is what the operator wants to do; it gates role capability.
type Action string

const (
	ActionRead    Action = "read"
	ActionRespond Action = "respond" // enforcement/response actions
)

// Grant binds a role to a tenant. For cross-tenant roles TenantID is ignored.
type Grant struct {
	Role     Role
	TenantID string
}

// Principal is an authenticated operator with its role grants.
type Principal struct {
	Subject string // user id / email — appears in cross-tenant audit records
	Grants  []Grant
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed     bool
	CrossTenant bool   // granted via a cross-tenant role (was audited)
	Reason      string // populated when denied
}

// AuditRecord is one cross-tenant access.
type AuditRecord struct {
	Subject string
	Tenant  string
	Action  string
	At      time.Time
}

// Auditor records cross-tenant accesses. Passing one to Authorize makes the
// audit atomic with the grant, so a cross-tenant read can never be unlogged.
type Auditor interface {
	RecordCrossTenant(subject, tenant, action string)
}

// Authorize decides whether p may perform action on tenant. Own-tenant access
// (a tenant-bound grant naming this tenant) is allowed silently; cross-tenant
// access (via a cross-tenant role) is allowed but recorded through aud. An empty
// tenant, or no matching grant, is denied (fail closed).
func Authorize(p Principal, tenant string, action Action, aud Auditor) Decision {
	if tenant == "" {
		return Decision{Reason: "no tenant in request (fail-closed)"}
	}
	// 1. Own-tenant grants first — the common path, no audit.
	for _, g := range p.Grants {
		if !isCrossTenant(g.Role) && g.TenantID == tenant && roleCan(g.Role, action) {
			return Decision{Allowed: true}
		}
	}
	// 2. Cross-tenant roles — explicit, audited widening.
	for _, g := range p.Grants {
		if isCrossTenant(g.Role) && roleCan(g.Role, action) {
			if aud != nil {
				aud.RecordCrossTenant(p.Subject, tenant, string(action))
			}
			return Decision{Allowed: true, CrossTenant: true}
		}
	}
	return Decision{Reason: "no grant authorizes " + string(action) + " on this tenant"}
}

// TenantScope is the set of tenants a principal may reach WITHOUT invoking a
// cross-tenant role — i.e. the tenants safe to list as "yours". Cross-tenant
// roles are excluded here on purpose: they must name a tenant explicitly and be
// audited via Authorize, not enumerated implicitly.
func TenantScope(p Principal) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, g := range p.Grants {
		if isCrossTenant(g.Role) || g.TenantID == "" {
			continue
		}
		if _, dup := seen[g.TenantID]; dup {
			continue
		}
		seen[g.TenantID] = struct{}{}
		out = append(out, g.TenantID)
	}
	return out
}

// HasCrossTenant reports whether the principal holds any cross-tenant role.
func HasCrossTenant(p Principal) bool {
	for _, g := range p.Grants {
		if isCrossTenant(g.Role) {
			return true
		}
	}
	return false
}

func isCrossTenant(r Role) bool {
	return r == RoleMSOCAdmin || r == RoleCrossTenantResponder
}

// CanRespond reports whether the principal holds any role that grants the
// respond action. The console uses it to enable/disable action controls; the
// server still authorizes every action per-tenant (Authorize) regardless.
func CanRespond(p Principal) bool {
	for _, g := range p.Grants {
		if roleCan(g.Role, ActionRespond) {
			return true
		}
	}
	return false
}

func roleCan(r Role, a Action) bool {
	switch r {
	case RoleReadOnly:
		return a == ActionRead
	case RoleTenantAnalyst, RoleMSOCAdmin, RoleCrossTenantResponder:
		return a == ActionRead || a == ActionRespond
	default:
		return false
	}
}

// MemAuditor is an in-memory Auditor for tests and the Phase 1 stub. The real
// control plane writes cross-tenant accesses to the durable audit log.
type MemAuditor struct {
	mu      sync.Mutex
	records []AuditRecord
}

func NewMemAuditor() *MemAuditor { return &MemAuditor{} }

func (m *MemAuditor) RecordCrossTenant(subject, tenant, action string) {
	m.mu.Lock()
	m.records = append(m.records, AuditRecord{Subject: subject, Tenant: tenant, Action: action, At: time.Now()})
	m.mu.Unlock()
}

// Records returns a copy of the recorded cross-tenant accesses.
func (m *MemAuditor) Records() []AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditRecord, len(m.records))
	copy(out, m.records)
	return out
}
