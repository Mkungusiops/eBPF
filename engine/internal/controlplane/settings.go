package controlplane

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	// Aliased: a test in this package already binds the identifier "choke".
	chokelib "github.com/jeffmk/ebpf-poc-engine/internal/choke"
)

// Per-tenant settings on the control plane.
//
// # Why this exists separately from the engine's
//
// The engine stores suppressions in its own SQLite and applies them to the one
// scorer it owns. The control plane owns no scorer: it holds the tenant's
// DESIRED state and distributes it to that tenant's agents over the signed
// command channel, exactly as a detection-policy push does.
//
// Building the engine half alone would have put a Settings entry in a shared
// nav that worked on one console and failed on the other — a surface implying
// a capability the deployment behind it does not have, which is the defect
// class this codebase keeps producing.
//
// # Honesty about reach
//
// This DISPATCHES. It does not converge. An agent offline right now does not
// get the change and is not retried, so the response reports what each agent
// ACKED and never claims the tenant is updated. Same contract as the policy
// push, for the same reason.

func (s *Server) handleSettingsSuppressions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// A read: seeing the tenant's rules is not a privileged act.
		tenant, ok := s.authorizeRead(w, r)
		if !ok {
			return
		}
		s.listTenantSuppressions(w, tenant)
	case http.MethodPost, http.MethodDelete:
		// A write narrows what the tenant's whole fleet detects.
		// DELETE included: a suppression is removed, and dressing that up as
		// a POST to satisfy a method guard would make the audit trail read
		// wrong.
		tenant, ok := s.authorizeRespondMethods(w, r, http.MethodPost, http.MethodDelete)
		if !ok {
			return
		}
		if r.Method == http.MethodPost {
			s.addTenantSuppression(w, r, tenant)
		} else {
			s.deleteTenantSuppression(w, r, tenant)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listTenantSuppressions(w http.ResponseWriter, tenant string) {
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "this control plane has no Postgres store, so it cannot hold tenant settings"})
		return
	}
	rules, err := pg.Suppressions(tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"suppressions": rules,
		// The control plane cannot count fires: the counter lives in each
		// agent's scorer and no heartbeat field carries it. Absent rather than
		// zero, because a zero would read as "this rule does nothing" and
		// invite deleting a rule that is working.
		"hits_known": false,
		"effect": "a suppression withholds the SCORE only. The event is still recorded, the chain is still " +
			"in the process tree, and the binary can still be contained by hand — the score is what drives " +
			"automatic action, and that is the only thing being stopped.",
	})
}

func (s *Server) addTenantSuppression(w http.ResponseWriter, r *http.Request, tenant string) {
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no tenant settings store"})
		return
	}
	var body struct {
		Binary string `json:"binary"`
		Policy string `json:"policy"`
		Parent string `json:"parent"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}
	sup := &centralstore.Suppression{
		Binary: strings.TrimSpace(body.Binary), Policy: strings.TrimSpace(body.Policy),
		Parent: strings.TrimSpace(body.Parent), Reason: strings.TrimSpace(body.Reason),
		Actor: s.subject(r),
	}
	if err := pg.AddSuppression(tenant, sup); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.dispatchSuppressions(w, r, pg, tenant, "added "+sup.Binary+": "+sup.Reason)
}

func (s *Server) deleteTenantSuppression(w http.ResponseWriter, r *http.Request, tenant string) {
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no tenant settings store"})
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id is required"})
		return
	}
	gone, err := pg.DeleteSuppression(tenant, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	if !gone {
		// Reporting success for a rule that was never there is the small lie
		// that makes an operator stop trusting the surface.
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no suppression with that id for this tenant"})
		return
	}
	s.dispatchSuppressions(w, r, pg, tenant, "removed suppression")
}

// dispatchSuppressions sends the tenant's FULL set to its agents.
//
// Replace, not merge: the desired state is unambiguous, and removal is
// otherwise inexpressible. A stored rule that never reaches an agent is a
// setting that looks applied and changes nothing, which is precisely what the
// engine-only version of this feature would have been on this console.
func (s *Server) dispatchSuppressions(w http.ResponseWriter, r *http.Request, pg *centralstore.PGStore, tenant, reason string) {
	rules, err := pg.Suppressions(tenant)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	wire := make([]*ebpfsocv1.Suppression, 0, len(rules))
	for _, x := range rules {
		wire = append(wire, &ebpfsocv1.Suppression{
			Binary: x.Binary, Policy: x.Policy, Parent: x.Parent, Reason: x.Reason,
		})
	}
	applied, total, detail := s.dispatchAll(r, tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_UpdateSuppressions{UpdateSuppressions: &ebpfsocv1.UpdateSuppressions{
			Suppressions: wire, Reason: reason}}})

	writeJSON(w, 200, map[string]any{
		"ok": true, "stored": len(rules), "acked": applied, "dispatched_to": total, "detail": detail,
		// "acked", never "updated". An agent offline now did not get this and
		// is not retried; its scorer still holds the previous set.
		"converged": false,
		"note": "stored for this tenant and dispatched to the agents currently known. An agent that was " +
			"offline will keep its previous set until the next change — this push is not retried.",
	})
}

// pgStore narrows the configured TenantStore to Postgres.
//
// Tenant settings need RLS, which only the Postgres implementation provides. A
// deployment on another store reports that plainly rather than silently
// storing settings somewhere with no isolation — one tenant's suppression
// leaking into another's fleet is the failure this refuses to risk.
func (s *Server) pgStore() (*centralstore.PGStore, bool) {
	pg, ok := s.cfg.Store.(*centralstore.PGStore)
	return pg, ok
}

// Guardrails — the tenant's protect-lists.
//
// Same store-then-dispatch contract as suppressions, and the same refusal to
// claim convergence. The wire shape is deliberately IDENTICAL to the engine's
// /api/settings/protected so one console component drives both planes; two
// shapes for one concept is how a console ends up working on single-tenant
// and quietly broken on the control plane.
//
// Two things about this surface are not symmetrical, and the response says so
// rather than letting the console infer a symmetry that does not exist:
//
//  1. There is a floor. DefaultSystemCriticalBinaries is compiled into every
//     agent and re-unioned on every apply, so a tenant can widen protection
//     and cannot remove the login path — not by mistake, and not with a valid
//     signature from a compromised control plane.
//  2. Removing a MAC does not un-protect a running agent. The agent's
//     SetProtectedMACs is add-only on purpose: dropping the uplink from the
//     allow-list is the single edit that can blackhole the path you would use
//     to undo it. The removal lives in the desired state and takes effect on
//     that agent's next restart.
func (s *Server) handleSettingsProtected(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tenant, ok := s.authorizeRead(w, r)
		if !ok {
			return
		}
		s.listTenantProtected(w, tenant)
	case http.MethodPut, http.MethodPost:
		tenant, ok := s.authorizeRespondMethods(w, r, http.MethodPut, http.MethodPost)
		if !ok {
			return
		}
		s.putTenantProtected(w, r, tenant)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// protectedFloor is the compiled-in minimum every agent re-unions on apply.
func protectedFloor() []string {
	floor := append([]string(nil), chokelib.DefaultSystemCriticalBinaries()...)
	sort.Strings(floor)
	return floor
}

func (s *Server) listTenantProtected(w http.ResponseWriter, tenant string) {
	body := map[string]any{
		"floor":             protectedFloor(),
		"binaries":          []string{},
		"macs":              []string{},
		"process_plane":     true,
		"device_plane":      true,
		"macs_are_add_only": true,
		// The control plane holds the DESIRED state. It cannot report what
		// each agent currently has, because no heartbeat field carries the
		// protect-list — so this is labelled as intent, never as fact.
		"desired_only": true,
	}
	pg, ok := s.pgStore()
	if !ok {
		body["error"] = "tenant guardrails need the Postgres store; this deployment does not have one"
		writeJSON(w, http.StatusServiceUnavailable, body)
		return
	}
	entries, err := pg.ProtectedList(tenant)
	if err != nil {
		body["error"] = err.Error()
		writeJSON(w, http.StatusInternalServerError, body)
		return
	}
	bins, macs := splitProtected(entries)
	body["binaries"] = bins
	body["macs"] = macs
	writeJSON(w, 200, body)
}

func splitProtected(entries []centralstore.Protected) (bins, macs []string) {
	bins, macs = []string{}, []string{}
	for _, e := range entries {
		switch e.Kind {
		case centralstore.KindBinary:
			bins = append(bins, e.Value)
		case centralstore.KindMAC:
			macs = append(macs, e.Value)
		}
	}
	return bins, macs
}

func (s *Server) putTenantProtected(w http.ResponseWriter, r *http.Request, tenant string) {
	pg, ok := s.pgStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no tenant settings store"})
		return
	}
	var b struct {
		Binaries []string `json:"binaries"`
		MACs     []string `json:"macs"`
		Reason   string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return
	}
	reason := strings.TrimSpace(b.Reason)
	if reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "a reason is required: this states what the platform will refuse to contain across the tenant"})
		return
	}
	actor := s.subject(r)
	want := make([]centralstore.Protected, 0, len(b.Binaries)+len(b.MACs))
	for _, v := range b.Binaries {
		if strings.TrimSpace(v) == "" {
			continue
		}
		want = append(want, centralstore.Protected{Kind: centralstore.KindBinary, Value: v, Reason: reason, Actor: actor})
	}
	for _, v := range b.MACs {
		if strings.TrimSpace(v) == "" {
			continue
		}
		want = append(want, centralstore.Protected{Kind: centralstore.KindMAC, Value: v, Reason: reason, Actor: actor})
	}
	stored, err := pg.ReplaceProtected(tenant, want)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	bins, macs := splitProtected(stored)
	applied, total, detail := s.dispatchAll(r, tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_UpdateProtectedList{UpdateProtectedList: &ebpfsocv1.UpdateProtectedList{
			ProtectedBinaries: bins, ProtectedMacs: macs}}})

	writeJSON(w, 200, map[string]any{
		"ok": true, "binaries": bins, "macs": macs, "floor": protectedFloor(),
		"acked": applied, "dispatched_to": total, "detail": detail,
		"converged": false,
		"note": "stored for this tenant and dispatched to the agents currently known. An agent that was offline " +
			"keeps its previous list until the next change — this push is not retried. Removing an address takes " +
			"effect on that agent's next restart, because the agent's device protect-list is add-only at runtime.",
	})
}
