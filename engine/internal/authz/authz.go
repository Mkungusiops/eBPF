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
	// ActionApprove authorizes a destructive action REQUESTED BY SOMEONE ELSE
	// (threat-model EN-2 change-control). It carries the same role capability as
	// respond today, and is a separate Action so an approver-only role can be
	// introduced later without revisiting every call site.
	//
	// The capability is not the control here — dual control is: the approver may
	// not be the requester, which authz cannot see and approval.Store enforces.
	ActionApprove Action = "approve"
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
	// Allowed and CrossTenant describe the outcome. A denied attempt is the
	// more interesting record of the two.
	Allowed     bool
	CrossTenant bool
	Detail      string
}

// Auditor records cross-tenant accesses. Passing one to Authorize makes the
// audit atomic with the grant, so a cross-tenant read can never be unlogged.
type Auditor interface {
	RecordCrossTenant(subject, tenant, action string)
}

// AccessAuditor records every authorization outcome, not just allowed
// cross-tenant ones.
//
// A DENIED attempt is the more interesting record of the two: an operator
// repeatedly failing to reach a tenant they have no grant for is the signal an
// incident review looks for, and Authorize used to return those silently.
//
// A separate interface so an existing Auditor keeps working unchanged;
// Authorize prefers this one when the implementation offers it.
type AccessAuditor interface {
	RecordAccess(subject, tenant, action string, allowed, crossTenant bool, detail string)
}

// audit reports one decision to whichever interface the auditor implements.
func audit(aud Auditor, p Principal, tenant string, action Action, d Decision) {
	if aud == nil {
		return
	}
	if a, ok := aud.(AccessAuditor); ok {
		a.RecordAccess(p.Subject, tenant, string(action), d.Allowed, d.CrossTenant, d.Reason)
		return
	}
	// Older auditors only understand the allowed cross-tenant case.
	if d.Allowed && d.CrossTenant {
		aud.RecordCrossTenant(p.Subject, tenant, string(action))
	}
}

// Authorize decides whether p may perform action on tenant. Own-tenant access
// (a tenant-bound grant naming this tenant) is allowed silently; cross-tenant
// access (via a cross-tenant role) is allowed but recorded through aud. An empty
// tenant, or no matching grant, is denied (fail closed).
func Authorize(p Principal, tenant string, action Action, aud Auditor) Decision {
	if tenant == "" {
		d := Decision{Reason: "no tenant in request (fail-closed)"}
		audit(aud, p, tenant, action, d)
		return d
	}
	// 1. Own-tenant grants first — the common path, no audit.
	for _, g := range p.Grants {
		if !isCrossTenant(g.Role) && g.TenantID == tenant && roleCan(g.Role, action) {
			d := Decision{Allowed: true}
			audit(aud, p, tenant, action, d)
			return d
		}
	}
	// 2. Cross-tenant roles — explicit, audited widening.
	for _, g := range p.Grants {
		if isCrossTenant(g.Role) && roleCan(g.Role, action) {
			d := Decision{Allowed: true, CrossTenant: true}
			audit(aud, p, tenant, action, d)
			return d
		}
	}
	d := Decision{Reason: "no grant authorizes " + string(action) + " on this tenant"}
	audit(aud, p, tenant, action, d)
	return d
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

// IsCrossTenant reports whether the role grants reach beyond one tenant.
// Exported so callers deriving a scope from a principal use the SAME definition
// as authorization does — two independent notions of "cross-tenant" is how they
// drift apart.
func (r Role) IsCrossTenant() bool { return isCrossTenant(r) }

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
		return a == ActionRead || a == ActionRespond || a == ActionApprove
	default:
		return false
	}
}

// MemAuditor is an in-memory Auditor for tests and the Phase 1 stub. The real
// control plane writes cross-tenant accesses to the durable audit log.
// memAuditorCap bounds the in-memory ring.
//
// The slice was appended to without limit and read only by tests, so a control
// plane leaked one record per cross-tenant access for the life of the process.
// Same failure class this codebase has already bounded twice — the uplink
// backlog and the connection pool — one layer up.
//
// This is a debugging aid, not the audit trail: the durable record belongs in
// operator_audit. Keeping the newest is the right end to keep for that purpose,
// and dropped is counted so the count never silently lies.
const memAuditorCap = 1000

type MemAuditor struct {
	mu      sync.Mutex
	records []AuditRecord
	dropped uint64
}

func NewMemAuditor() *MemAuditor { return &MemAuditor{} }

func (m *MemAuditor) RecordCrossTenant(subject, tenant, action string) {
	m.RecordAccess(subject, tenant, action, true, true, "")
}

// RecordAccess implements AccessAuditor.
func (m *MemAuditor) RecordAccess(subject, tenant, action string, allowed, crossTenant bool, detail string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Only cross-tenant and denied outcomes are worth holding in memory. Every
	// own-tenant read would otherwise fill the ring with the ordinary case and
	// evict the interesting ones.
	if allowed && !crossTenant {
		return
	}
	m.records = append(m.records, AuditRecord{
		Subject: subject, Tenant: tenant, Action: action, At: time.Now(),
		Allowed: allowed, CrossTenant: crossTenant, Detail: detail,
	})
	if excess := len(m.records) - memAuditorCap; excess > 0 {
		m.records = append(m.records[:0], m.records[excess:]...)
		m.dropped += uint64(excess)
	}
}

// Dropped counts records evicted by the cap. Never reset: a count that has
// lost entries must keep saying so.
func (m *MemAuditor) Dropped() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

// Records returns a copy of the recorded cross-tenant accesses.
func (m *MemAuditor) Records() []AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditRecord, len(m.records))
	copy(out, m.records)
	return out
}
