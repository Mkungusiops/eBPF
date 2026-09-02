package controlplane

import (
	"encoding/json"
	"net/http"

	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

// Per-tenant retention — the setting the schema promised and never delivered.
//
// # What was wrong
//
// tenants.retention_days shipped in migration 0001 and no code ever read it.
// The Settings page said so, honestly, in a caveat: "a per-tenant column exists
// in the schema and nothing reads it, so this cannot yet differ by tenant —
// which a data-residency agreement may require." That caveat was the whole
// problem written down. A customer whose contract says 14 days could have that
// number stored in the platform and keep 30.
//
// # Only shorter, never longer
//
// A tenant may cut their horizon below the deployment's, not extend it past it.
// The global prune has already deleted the older rows by the time a longer
// tenant horizon would want them, so honouring the request would be a promise
// the platform cannot keep — and a retention policy that silently fails is
// worse than one that is visibly refused. The response says which of the two
// happened rather than echoing the number back as though it took effect.
//
// # The floor still applies
//
// Below two console windows, every window-over-window delta on the dashboard is
// computed against data that no longer exists. A tenant asking for 3 days gets
// 14 and is told so.
func (s *Server) registerRetentionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/settings/retention", s.handleSettingsRetention)
}

func (s *Server) handleSettingsRetention(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tenant, ok := s.authorizeRead(w, r)
		if !ok {
			return
		}
		s.readRetention(w, tenant)
	case http.MethodPut, http.MethodPost:
		tenant, ok := s.authorizeRespondMethods(w, r, http.MethodPut, http.MethodPost)
		if !ok {
			return
		}
		s.writeRetention(w, r, tenant)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) readRetention(w http.ResponseWriter, tenant string) {
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, 200, map[string]any{
			"editable": false,
			"error": "this control plane has no Postgres store, so retention cannot differ " +
				"by tenant and the deployment-wide setting stands",
		})
		return
	}
	policy := centralstore.EffectiveRetention(pg.RetentionDaysFor(tenant))
	body := map[string]any{
		"editable": true,
		"policy":   policy,
		"detail": "decisions are never pruned, whatever this is set to — the containment " +
			"audit chain has to outlive the telemetry it was made from.",
	}
	if policy.Ignored {
		body["note"] = "this tenant asked to keep data longer than the deployment does. " +
			"The platform-wide prune has already removed those rows, so the request has no effect."
	}
	if policy.Clamped {
		body["note"] = "the requested horizon was below the floor and has been raised to it."
	}
	writeJSON(w, 200, body)
}

func (s *Server) writeRetention(w http.ResponseWriter, r *http.Request, tenant string) {
	var b struct {
		Days   *int   `json:"days"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Days == nil {
		// Required, never defaulted: a missing field decoding to 0 would clear
		// a tenant's data-residency horizon from a malformed request.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "days must be present and a number; send 0 to fall back to the deployment default"})
		return
	}
	if *b.Days < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "days cannot be negative"})
		return
	}
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this control plane has no Postgres store, so retention cannot be set per tenant"})
		return
	}
	if err := pg.SetRetentionDays(tenant, *b.Days); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	policy := centralstore.EffectiveRetention(*b.Days)

	// Report the EFFECTIVE horizon, not the requested one. Echoing the number
	// back is how a compliance sign-off gets made against a setting that was
	// clamped, ignored, or both.
	res := map[string]any{"ok": true, "policy": policy}
	switch {
	case *b.Days == 0:
		res["applies_to"] = "cleared — this tenant now follows the deployment default"
	case policy.Ignored:
		res["ok"] = false
		res["applies_to"] = "stored, but it has no effect: the deployment keeps less than this, " +
			"and the rows a longer horizon would need are already pruned"
	case policy.Clamped:
		res["applies_to"] = "stored and raised to the floor: below it the console's " +
			"window-over-window comparisons have no prior window to read"
	default:
		res["applies_to"] = "events and alerts for this tenant are now pruned on the next " +
			"retention pass, which runs every six hours"
	}
	if s.cfg.Logf != nil {
		s.cfg.Logf("retention set tenant=%s days=%d reason=%q", tenant, *b.Days, b.Reason)
	}
	writeJSON(w, 200, res)
}
