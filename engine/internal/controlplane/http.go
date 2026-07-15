package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
)

func (s *Server) buildHTTP() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"status": "ok"}) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"status": "ready"}) })
	mux.HandleFunc("/api/whoami", s.handleWhoami)
	mux.HandleFunc("/api/telemetry", s.handleTelemetry)
	mux.HandleFunc("/api/fleet", s.handleFleet)
	mux.HandleFunc("/api/choke", s.handleChoke)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/admin/enroll-token", s.handleEnrollToken)
	mux.HandleFunc("/api/admin/command", s.handleCommand)
	if s.cfg.BFF != nil {
		s.cfg.BFF.Routes(mux) // /auth/login, /auth/callback, /auth/logout
	}
	return mux
}

// principal resolves the operator's identity. A valid OIDC (BFF) session wins
// when present; otherwise the admin bearer token maps to an msoc-admin principal.
// Both are honored when configured, so a break-glass/headless admin token keeps
// working (agent-enrollment minting, automation) alongside human OIDC login.
func (s *Server) principal(r *http.Request) (authz.Principal, bool) {
	if s.cfg.BFF != nil {
		if p, ok := s.cfg.BFF.Principal(r); ok {
			return p, true
		}
	}
	if s.cfg.AdminToken != "" {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.AdminToken)) == 1 {
			return authz.Principal{Subject: "admin", Grants: []authz.Grant{{Role: authz.RoleMSOCAdmin}}}, true
		}
	}
	return authz.Principal{}, false
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	writeJSON(w, 200, map[string]any{
		"subject":      p.Subject,
		"tenants":      authz.TenantScope(p),
		"cross_tenant": authz.HasCrossTenant(p),
	})
}

type telemetryRow struct {
	Tenant  string `json:"tenant"`
	Agent   string `json:"agent"`
	Kind    string `json:"kind"`
	ExecID  string `json:"exec_id,omitempty"`
	Binary  string `json:"binary,omitempty"`
	AtUnixN int64  `json:"at"`
}

// handleTelemetry serves a tenant-scoped read of the central store. Authorization
// is a Layer-4 authz decision; a denial returns 404 (never 403 — the caller must
// not learn whether another tenant's data exists, §6 side channels).
func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return
	}
	if !authz.Authorize(p, tenant, authz.ActionRead, s.auditor).Allowed {
		http.NotFound(w, r) // 404, not 403
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant}, limit)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	out := make([]telemetryRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, telemetryRow{
			Tenant: row.TenantID, Agent: row.AgentID, Kind: row.Kind,
			ExecID: row.ExecID, Binary: row.Binary, AtUnixN: row.At.UnixNano(),
		})
	}
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "records": out})
}

// handleEnrollToken mints a one-time bootstrap token for a tenant. The operator
// must be authorized to act in that tenant (respond) — a tenant-analyst for
// their own tenant, or a cross-tenant MSOC role. Returns the token + CA bundle
// the agent pins.
func (s *Server) handleEnrollToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		Tenant string `json:"tenant"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return
	}
	if !authz.Authorize(p, body.Tenant, authz.ActionRespond, s.auditor).Allowed {
		http.NotFound(w, r)
		return
	}
	tok, err := s.tokens.Mint(body.Tenant, s.cfg.EnrollTTL)
	if err != nil {
		http.Error(w, "mint failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]any{
		"token":         tok,
		"tenant":        body.Tenant,
		"expires_in_s":  int(s.cfg.EnrollTTL / time.Second),
		"ca_bundle_pem": string(s.CABundlePEM()),
	})
}

// authorizeRead resolves the operator, requires a ?tenant=, and checks the READ
// grant. On any failure it writes the response and returns ("", false) — a
// denial is a 404 (side-channel rule), same as handleTelemetry.
func (s *Server) authorizeRead(w http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return "", false
	}
	if !authz.Authorize(p, tenant, authz.ActionRead, s.auditor).Allowed {
		http.NotFound(w, r)
		return "", false
	}
	return tenant, true
}

// handleFleet lists a tenant's agents from the heartbeat registry — the central
// Fleet view (agent id, version, kernel, mode, liveness, buffer depth).
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type agentView struct {
		AgentID       string `json:"agent_id"`
		Version       string `json:"version"`
		Kernel        string `json:"kernel"`
		Mode          string `json:"mode"`
		LastSeen      int64  `json:"last_seen"`
		BufferDepth   uint64 `json:"buffer_depth"`
		PolicyVersion string `json:"policy_version"`
		ChokeCount    int    `json:"choke_count"`
		DeviceCount   int    `json:"device_count"`
	}
	recs := s.registry.ListTenant(tenant)
	out := make([]agentView, 0, len(recs))
	for _, rec := range recs {
		out = append(out, agentView{
			AgentID: rec.AgentID, Version: rec.Version, Kernel: rec.Kernel,
			Mode:      strings.TrimPrefix(rec.Mode.String(), "ENFORCEMENT_MODE_"),
			LastSeen:  rec.LastSeen.UnixNano(), BufferDepth: rec.BufferDepth,
			PolicyVersion: rec.AppliedPolicyVersion, ChokeCount: len(rec.Chokes), DeviceCount: len(rec.Devices),
		})
	}
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "agents": out})
}

// handleChoke aggregates the choke snapshots reported by a tenant's agents.
func (s *Server) handleChoke(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type chokeView struct {
		Agent  string `json:"agent"`
		Binary string `json:"binary"`
		State  string `json:"state"`
		Score  int32  `json:"score"`
		PID    uint32 `json:"pid"`
		ExecID string `json:"exec_id"`
	}
	out := []chokeView{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, c := range rec.Chokes {
			out = append(out, chokeView{
				Agent: rec.AgentID, Binary: c.GetBinary(), State: c.GetState(),
				Score: c.GetScore(), PID: c.GetPid(), ExecID: c.GetExecId(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "chokes": out})
}

// handleDevices aggregates the device snapshots reported by a tenant's agents.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type deviceView struct {
		Agent string `json:"agent"`
		MAC   string `json:"mac"`
		State string `json:"state"`
		Label string `json:"label"`
	}
	out := []deviceView{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, d := range rec.Devices {
			out = append(out, deviceView{Agent: rec.AgentID, MAC: d.GetMac(), State: d.GetState(), Label: d.GetLabel()})
		}
	}
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "devices": out})
}

// handleCommand dispatches a signed operator command to one agent over the mTLS
// command channel and returns the agent's ack. Commands require the RESPOND
// action; a denial is a 404 (same side-channel rule as reads). Delivery is
// tenant-safe by construction: the dispatcher only hands a command to the agent
// whose mTLS cert matches the target agent_id.
func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var body struct {
		Tenant        string `json:"tenant"`
		AgentID       string `json:"agent_id"`
		SetMode       string `json:"set_mode"` // detect | dry-run | enforce
		SetThresholds *struct {
			ThrottleAt   int32 `json:"throttle_at"`
			TarpitAt     int32 `json:"tarpit_at"`
			QuarantineAt int32 `json:"quarantine_at"`
			SeverAt      int32 `json:"sever_at"`
		} `json:"set_thresholds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if body.Tenant == "" || body.AgentID == "" {
		http.Error(w, "tenant and agent_id required", http.StatusBadRequest)
		return
	}
	if !authz.Authorize(p, body.Tenant, authz.ActionRespond, s.auditor).Allowed {
		http.NotFound(w, r) // 404, not 403
		return
	}

	cmd := &ebpfsocv1.Command{}
	switch {
	case body.SetThresholds != nil:
		cmd.Action = &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt:   body.SetThresholds.ThrottleAt,
			TarpitAt:     body.SetThresholds.TarpitAt,
			QuarantineAt: body.SetThresholds.QuarantineAt,
			SeverAt:      body.SetThresholds.SeverAt,
		}}
	case body.SetMode != "":
		mode, ok := parseEnforcementMode(body.SetMode)
		if !ok {
			http.Error(w, "set_mode must be detect | dry-run | enforce", http.StatusBadRequest)
			return
		}
		cmd.Action = &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: mode}}
	default:
		http.Error(w, "no action: provide set_mode or set_thresholds", http.StatusBadRequest)
		return
	}

	id := s.dispatcher.Enqueue(body.AgentID, cmd)
	// The command channel is an agent dial-out stream; the agent verifies the
	// signature, applies, and acks within a couple of seconds. Wait briefly so
	// the operator gets the outcome inline.
	var status, detail string
	for i := 0; i < 60; i++ {
		if a, ok := s.dispatcher.Ack(id); ok {
			status, detail = a.GetStatus().String(), a.GetDetail()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	writeJSON(w, 200, map[string]any{"command_id": id, "status": status, "detail": detail})
}

func parseEnforcementMode(s string) (ebpfsocv1.EnforcementMode, bool) {
	switch s {
	case "detect", "detect-only":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY, true
	case "dry-run":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN, true
	case "enforce", "enforcing":
		return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, true
	}
	return ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
