package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Change control (EN-2) as a live, per-tenant setting.
//
// # The floor
//
// cfg.RequireApproval is a FLOOR, not a default. If the platform was deployed
// with -require-approval, no tenant row can switch four-eyes off. A tenant may
// only ever tighten from here — the same asymmetry as the protected-binary
// floor, and for the same reason: a setting that can only make the platform
// safer needs no second guard, while one that can weaken it needs an owner
// higher up than the person using the console.
//
// Where the deploy has NOT mandated it, a tenant can turn it on and off, and
// both directions are recorded with an actor and a reason.
//
// # Why this is cached
//
// approvalRequired is called on the containment path, before anything is
// signed. A database round trip there would put the store on the critical path
// of an operator trying to stop an attack. The cache is populated on first use
// per tenant and updated by writes, so the store is read once per tenant per
// process.
//
// # Failure behaviour, stated because it is a safety control
//
// If the store cannot be read and the tenant has no cached value, the
// DEPLOYMENT default applies and the read error is surfaced on the settings
// endpoint rather than swallowed. Once a value has been read it is kept for
// the life of the process, so a database outage cannot silently drop a
// tenant's four-eyes requirement.
type changeControlCache struct {
	mu     sync.RWMutex
	known  map[string]bool   // tenant -> require_approval
	errors map[string]string // tenant -> last read error, for the settings surface
}

func newChangeControlCache() *changeControlCache {
	return &changeControlCache{known: map[string]bool{}, errors: map[string]string{}}
}

// approvalRequired reports whether this tenant's destructive actions must be
// approved by a second operator. It is the single source of truth for every
// EN-2 gate; four separate reads of cfg.RequireApproval is four places to
// forget when the setting became per-tenant.
func (s *Server) approvalRequired(tenant string) bool {
	// The deploy floor wins outright, so the cheapest check is first and no
	// store read happens at all on a deployment that mandates four-eyes.
	if s.cfg.RequireApproval {
		return true
	}
	if s.changeControl == nil || tenant == "" {
		return false
	}

	s.changeControl.mu.RLock()
	v, ok := s.changeControl.known[tenant]
	s.changeControl.mu.RUnlock()
	if ok {
		return v
	}

	pg, isPG := s.pgStore()
	if !isPG {
		return false
	}
	cc, err := pg.ChangeControlFor(tenant)
	switch {
	case errors.Is(err, centralstore.ErrNoChangeControlRow):
		// Never set for this tenant. Cache the deployment default so the miss
		// is not re-queried on every containment request.
		s.cacheChangeControl(tenant, false, "")
		return false
	case err != nil:
		// Not cached as a value: a transient error must not become this
		// tenant's setting for the life of the process.
		s.changeControl.mu.Lock()
		s.changeControl.errors[tenant] = err.Error()
		s.changeControl.mu.Unlock()
		s.cfg.Logf("[change-control] could not read the setting for tenant=%s (%v); "+
			"falling back to the deployment default (require_approval=%v)", tenant, err, s.cfg.RequireApproval)
		return s.cfg.RequireApproval
	}
	s.cacheChangeControl(tenant, cc.RequireApproval, "")
	return cc.RequireApproval
}

func (s *Server) cacheChangeControl(tenant string, v bool, readErr string) {
	if s.changeControl == nil {
		return
	}
	s.changeControl.mu.Lock()
	s.changeControl.known[tenant] = v
	if readErr == "" {
		delete(s.changeControl.errors, tenant)
	} else {
		s.changeControl.errors[tenant] = readErr
	}
	s.changeControl.mu.Unlock()
}

func (s *Server) changeControlReadError(tenant string) string {
	if s.changeControl == nil {
		return ""
	}
	s.changeControl.mu.RLock()
	defer s.changeControl.mu.RUnlock()
	return s.changeControl.errors[tenant]
}

// handleSettingsChangeControl — GET the posture, PUT to change it.
func (s *Server) handleSettingsChangeControl(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tenant, ok := s.authorizeRead(w, r)
		if !ok {
			return
		}
		s.readChangeControl(w, tenant)
	case http.MethodPut, http.MethodPost:
		tenant, ok := s.authorizeRespondMethods(w, r, http.MethodPut, http.MethodPost)
		if !ok {
			return
		}
		s.writeChangeControl(w, r, tenant)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) readChangeControl(w http.ResponseWriter, tenant string) {
	enabled := s.approvalRequired(tenant)
	body := map[string]any{
		"enabled": enabled,
		// mandated: the deploy set the floor, so this console cannot turn it
		// off. Rendered as a locked control rather than one that 400s on use.
		"mandated":    s.cfg.RequireApproval,
		"can_disable": enabled && !s.cfg.RequireApproval,
		"gated":       []string{"quarantine", "sever", "fleet arming"},
		// Stated as a property, not an omission: the exit from a bad state
		// must never wait on a quorum.
		"never_gated": []string{"thaw", "throttle", "tarpit", "kill-switch", "detect-only"},
		"available":   s.approvals != nil,
	}
	if s.approvals != nil {
		body["pending"] = s.approvals.PendingCount(tenant)
	}
	if pg, ok := s.pgStore(); ok {
		if cc, err := pg.ChangeControlFor(tenant); err == nil {
			body["reason"] = cc.Reason
			body["actor"] = cc.Actor
			body["updated_at"] = cc.UpdatedAt
		} else if !errors.Is(err, centralstore.ErrNoChangeControlRow) {
			body["error"] = err.Error()
		}
	} else {
		body["error"] = "this control plane has no Postgres store, so the setting cannot be stored per tenant"
	}
	if e := s.changeControlReadError(tenant); e != "" && body["error"] == nil {
		body["error"] = e
	}
	writeJSON(w, 200, body)
}

func (s *Server) writeChangeControl(w http.ResponseWriter, r *http.Request, tenant string) {
	var b struct {
		Enabled *bool  `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Enabled == nil {
		// Explicitly required, not defaulted. A missing field decoding to
		// false would DISABLE a safety control from a malformed request —
		// the same shape of bug as the threshold body that zeroed sever_at.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "enabled must be present and boolean"})
		return
	}
	// The floor is checked before storage, so a deployment that mandates
	// four-eyes gives the same answer whatever the database is doing. A policy
	// refusal that depends on a store being reachable is not a policy.
	if !*b.Enabled && s.cfg.RequireApproval {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this platform was deployed with change control mandated, so it cannot be switched off " +
				"for a single tenant. Change it where the platform is deployed, with whoever owns that decision."})
		return
	}
	if s.approvals == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "this control plane has no approval queue, so nothing would hold a request for a second operator"})
		return
	}
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "this control plane has no Postgres store, so the setting cannot be stored per tenant"})
		return
	}
	cc, err := pg.SetChangeControl(tenant, *b.Enabled, b.Reason, s.subject(r))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.cacheChangeControl(tenant, cc.RequireApproval, "")
	s.cfg.Logf("[change-control] %s set require_approval=%v for tenant=%s (%s)",
		cc.Actor, cc.RequireApproval, tenant, cc.Reason)

	out := map[string]any{
		"ok": true, "enabled": cc.RequireApproval, "reason": cc.Reason,
		"actor": cc.Actor, "updated_at": cc.UpdatedAt,
		"applies_to": "requests made from now on",
	}
	// Disabling does NOT approve what is already parked. Said out loud,
	// because the opposite assumption is the dangerous one: an operator who
	// believed it did would walk away from a queue holding a sever.
	if pending := s.approvals.PendingCount(tenant); pending > 0 {
		out["pending"] = pending
		if !cc.RequireApproval {
			out["note"] = "requests already in the queue stay there. Turning change control off does not " +
				"approve them — approve or deny them individually, or let them expire."
		}
	}
	writeJSON(w, 200, out)
}
