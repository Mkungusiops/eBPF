package controlplane

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// The provider's customer roster, served to the provider — and to nobody else.
//
// # Why it did not exist
//
// A cross-tenant operator's console cannot offer a customer switcher without a
// list of customers, and nothing published one. /api/whoami deliberately
// refuses: authz.TenantScope excludes cross-tenant roles precisely so a
// cross-tenant principal cannot enumerate the estate implicitly, and a live
// probe asserts that whoami never names a tenant the operator merely has reach
// over (web/e2e/probe/msoc.probe.spec.ts). PGStore.Tenants() has existed since
// the roster started being written and had no HTTP caller at all.
//
// # Why this is not the same leak by another door
//
// whoami refuses because enumeration there would be UNAUDITED and UNCHECKED —
// one read handing over the customer list without an Authorize call or an audit
// row. An MSSP's customer list is itself confidential: knowing that Safaricom
// buys managed detection from this provider is commercially sensitive before a
// single alert is read. So this endpoint is the opposite of that read in the
// two ways that matter:
//
//   - It is refused to anyone without a cross-tenant role, with the same 404
//     every other unauthorized read here answers (§6 side channels — a 403
//     would confirm the roster exists and is merely out of reach).
//   - Every tenant it names goes through authz.Authorize first, so listing a
//     customer is recorded in operator_audit exactly like reading that
//     customer's alerts is. That matters in the direction people forget: the
//     customer reads their own rows through /api/operator-audit, so a provider
//     operator who enumerates the book of business is visible TO EACH CUSTOMER
//     NAMED, not only to the provider.
//
// # Where the list comes from
//
// The tenants table, when this deployment has Postgres — the roster
// EnsureTenant maintains from the enrollment/heartbeat path. Otherwise the
// heartbeat registry, which knows only tenants with an agent reporting right
// now. Those are different questions ("who is a customer" vs "who is reporting")
// and the response says which one it answered, because a switcher silently
// missing a quiet customer is worse than one that explains itself.
func (s *Server) registerTenantRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/tenants", s.handleTenants)
}

// tenantRosterEntry is one customer as the estate switcher needs it.
type tenantRosterEntry struct {
	TenantID    string `json:"tenant_id"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status,omitempty"`
	// CreatedAt is zero when the roster came from the heartbeat registry, which
	// has no idea when a tenant was onboarded — omitted rather than sent as the
	// zero time, which renders as the year 1.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Agents/AgentsFresh describe reporting state, so the switcher can show a
	// customer whose fleet has gone silent instead of an identical-looking row.
	// Freshness uses the same agentFreshWindow as /api/system-health, so the
	// two surfaces cannot disagree about whether a fleet is live.
	Agents      int `json:"agents"`
	AgentsFresh int `json:"agents_fresh"`
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	s.tenantsFor(w, r, p)
}

// tenantsFor is handleTenants once the operator is known.
//
// Split for the same reason authorizeReadAs is: the identity path that runs on
// the estate is an OIDC session no test can construct, and the only principal a
// handler test can otherwise reach is the break-glass bearer — which is
// cross-tenant, so the refusal this endpoint turns on would never be exercised.
func (s *Server) tenantsFor(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	// The gate is the ROLE, not a per-tenant grant. A tenant-bound analyst has
	// no legitimate use for the provider's customer list — they already know
	// the one tenant they belong to — and 404 rather than 403 so the refusal
	// does not confirm that a roster is there to be had.
	if !authz.HasCrossTenant(p) {
		http.NotFound(w, r)
		return
	}

	roster, source := s.tenantRoster()
	out := make([]tenantRosterEntry, 0, len(roster))
	for _, t := range roster {
		// Authorize per tenant, and never merely for the audit row: this is the
		// same decision every cross-tenant read makes, so a role that later
		// stops authorizing reads stops being able to enumerate too, without
		// this handler being revisited. Denied tenants are omitted silently —
		// saying "there are 3 more you may not see" would leak the count.
		if !authz.Authorize(p, t.TenantID, authz.ActionRead, s.auditor).Allowed {
			continue
		}
		e := tenantRosterEntry{TenantID: t.TenantID, DisplayName: t.DisplayName, Status: t.Status}
		if !t.CreatedAt.IsZero() {
			at := t.CreatedAt.UTC()
			e.CreatedAt = &at
		}
		for _, a := range s.registry.ListTenant(t.TenantID) {
			e.Agents++
			if time.Since(a.LastSeen) <= agentFreshWindow {
				e.AgentsFresh++
			}
		}
		out = append(out, e)
	}

	writeJSON(w, 200, map[string]any{
		"count":   len(out),
		"tenants": out,
		"source":  source,
		// Stated on the response because an operator should be able to see,
		// from the thing itself, that reading it was not free.
		"audited": "listing a customer is recorded in the operator access trail " +
			"against that customer, and is visible to them via /api/operator-audit",
	})
}

// tenantRoster returns the estate's tenants and names where they came from.
//
// Postgres first: the tenants table is the roster, and it includes a customer
// whose agents are all down — which is exactly the customer an operator is most
// likely to be looking for. The registry fallback cannot see those, so it says
// so rather than presenting a partial list as the whole one.
func (s *Server) tenantRoster() ([]centralstore.Tenant, string) {
	if pg, ok := s.pgStore(); ok {
		rows, err := pg.Tenants()
		if err == nil {
			return rows, "tenants table: every customer this control plane has enrolled"
		}
		// Falling through rather than failing: a switcher built from live
		// agents is degraded, and an error here would take the whole
		// cross-tenant console down with it. The response names the weaker
		// source so nobody reads the short list as the full roster.
		slog.Error("tenant roster unreadable; falling back to the heartbeat registry", "error", err)
	}
	ids := s.registry.Tenants()
	out := make([]centralstore.Tenant, 0, len(ids))
	for _, id := range ids {
		out = append(out, centralstore.Tenant{TenantID: id})
	}
	return out, "heartbeat registry: only tenants with an agent reporting to this " +
		"control plane. A customer whose fleet is entirely offline is missing from this list."
}
