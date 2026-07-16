package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
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
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/system-health", s.handleSystemHealth)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/fleet", s.handleFleet)
	mux.HandleFunc("/api/choke", s.handleChoke)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/decisions", s.handleDecisions)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policy-stats", s.handlePolicyStats)
	mux.HandleFunc("/api/process/", s.handleProcess)
	mux.HandleFunc("/api/stream", s.handleStream)
	s.registerChokeRoutes(mux)  // rich Choke Gateway + Devices API, tenant-scoped
	s.registerFleetRoutes(mux)  // Fleet view: tenant's agents as hosts
	s.registerAttackRoutes(mux) // quick-fire attacks + honeypots (demo/lab)
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
	scope := authz.TenantScope(p)
	host := "control-plane"
	if len(scope) > 0 {
		host = scope[0]
	}
	writeJSON(w, 200, map[string]any{
		"subject":      p.Subject,
		"tenants":      scope,
		"cross_tenant": authz.HasCrossTenant(p),
		"can_respond":  authz.CanRespond(p),
		// Aliases the reused SOC frontend reads (normalizeWhoami): user + host.
		"user": p.Subject,
		"host": host,
		"role": func() string {
			if authz.HasCrossTenant(p) {
				return "msoc-admin"
			}
			return "tenant-analyst"
		}(),
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
		// The reused SOC frontend makes tenant-less calls; default to the
		// operator's primary tenant. A tenant switcher can override via ?tenant=.
		if scope := authz.TenantScope(p); len(scope) > 0 {
			tenant = scope[0]
		}
	}
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

// handleAlerts serves a tenant's recent alerts (the triage queue). The frontend
// derives the severity timeline from the same list, so one endpoint covers both.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "alert"}, limit)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type alertView struct {
		Agent       string `json:"agent"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Score       int32  `json:"score"`
		ExecID      string `json:"exec_id"`
		Process     string `json:"process"`
		MitreID     string `json:"mitre_id"`
		Tactic      string `json:"tactic"`
		At          int64  `json:"at"`
		Timestamp   string `json:"timestamp"` // RFC3339 — the SOC frontend reads this
	}
	out := make([]alertView, 0, len(rows))
	for _, row := range rows {
		a := row.Record.GetAlert()
		if a == nil {
			continue
		}
		at := row.At
		if a.GetOccurredAt() != nil {
			at = a.GetOccurredAt().AsTime()
		}
		out = append(out, alertView{
			Agent: row.AgentID, Severity: a.GetSeverity(), Title: a.GetTitle(),
			Description: a.GetDescription(), Score: a.GetScore(), ExecID: a.GetExecId(),
			Process: row.Binary, MitreID: a.GetMitreId(), Tactic: a.GetTactic(),
			At: at.UnixNano(), Timestamp: at.UTC().Format(time.RFC3339Nano),
		})
	}
	// Bare array: the engine's contract. The SOC dashboard unwraps either shape,
	// but the Choke feature does getJSON<Alert[]> and iterates the result directly.
	writeJSON(w, 200, out)
}

// handleEvents serves a tenant's recent process events (the live feed / KPIs).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "event"}, limit)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type eventView struct {
		Agent      string `json:"agent"`
		ExecID     string `json:"exec_id"`
		PID        uint32 `json:"pid"`
		EventType  string `json:"event_type"`
		Process    string `json:"process"`
		Args       string `json:"args"`
		PolicyName string `json:"policy_name"`
		DestIP     string `json:"dest_ip,omitempty"`
		DestPort   uint32 `json:"dest_port,omitempty"`
		Proto      string `json:"proto,omitempty"`
		RemoteIP   string `json:"remote_ip,omitempty"`
		Timestamp  string `json:"timestamp"`
	}
	out := make([]eventView, 0, len(rows))
	for _, row := range rows {
		e := row.Record.GetEvent()
		if e == nil {
			continue
		}
		at := row.At
		if e.GetOccurredAt() != nil {
			at = e.GetOccurredAt().AsTime()
		}
		out = append(out, eventView{
			Agent: row.AgentID, ExecID: e.GetExecId(), PID: e.GetPid(),
			EventType: e.GetEventType(), Process: e.GetBinary(), Args: e.GetArgs(),
			PolicyName: e.GetPolicyName(), DestIP: e.GetDestIp(), DestPort: e.GetDestPort(),
			Proto: e.GetProto(), RemoteIP: e.GetRemoteIp(), Timestamp: at.UTC().Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "events": out})
}

// handleSystemHealth reports the tenant's control-plane-side health (the SOC
// dashboard's Operations tile). Derived from the agent registry.
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	agents := s.registry.ListTenant(tenant)
	status := "healthy"
	if len(agents) == 0 {
		status = "degraded"
	}
	writeJSON(w, 200, map[string]any{
		"status": status, "host": tenant, "tetragon": "connected",
		"agents": len(agents), "stream": "live",
	})
}

// handleVersion returns the control-plane build (public; not sensitive).
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"sha": cpBuild, "version": cpBuild})
}

// cpBuild identifies the control-plane build to the console version tile.
const cpBuild = "0.3.0-controlplane"

// handleDecisions serves a tenant's recent enforcement decisions (the SOC
// dashboard's decision ledger). Sourced from the store's "decision" records
// that agents already report — no agent change.
func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "decision"}, limit)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type decisionView struct {
		Action    string `json:"action"`
		State     string `json:"state"`
		Target    string `json:"target"`
		Reason    string `json:"reason"`
		Score     int32  `json:"score"`
		Timestamp string `json:"timestamp"`
		OK        bool   `json:"ok"`
	}
	out := make([]decisionView, 0, len(rows))
	for _, row := range rows {
		d := row.Record.GetDecision()
		if d == nil {
			continue
		}
		at := row.At
		if d.GetOccurredAt() != nil {
			at = d.GetOccurredAt().AsTime()
		}
		target := d.GetBinary()
		if target == "" {
			target = d.GetExecId()
		}
		out = append(out, decisionView{
			Action: d.GetAction(), State: d.GetToState(), Target: target,
			Reason: d.GetReason(), Score: d.GetScore(),
			Timestamp: at.UTC().Format(time.RFC3339Nano), OK: d.GetOutcome() == "ok",
		})
	}
	// Bare array (engine contract): the Choke feature iterates it directly.
	writeJSON(w, 200, out)
}

// policyPosts folds the tenant's recent events into policy_name → observed
// count. The store has no GROUP BY, so we aggregate in Go over a window — enough
// for the dashboard's policy posture / MITRE coverage tiles. No agent change:
// events already carry policy_name.
func (s *Server) policyPosts(tenant string, window int) (map[string]int, error) {
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "event"}, window)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, row := range rows {
		if e := row.Record.GetEvent(); e != nil {
			if p := e.GetPolicyName(); p != "" {
				counts[p]++
			}
		}
	}
	return counts, nil
}

// handlePolicies lists the tenant's active policies — those actually firing in
// its telemetry (distinct policy_name), so the list reflects real tenant state.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	counts, err := s.policyPosts(tenant, 5000)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type policyView struct {
		Name  string `json:"name"`
		Posts int    `json:"posts"`
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]policyView, 0, len(names))
	for _, n := range names {
		out = append(out, policyView{Name: n, Posts: counts[n]})
	}
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "policies": out})
}

// handlePolicyStats reports per-policy post counts (the observability tile),
// most-active first.
func (s *Server) handlePolicyStats(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	counts, err := s.policyPosts(tenant, 5000)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type statView struct {
		Name  string `json:"name"`
		Posts int    `json:"posts"`
	}
	out := make([]statView, 0, len(counts))
	for n, c := range counts {
		out = append(out, statView{Name: n, Posts: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Posts > out[j].Posts })
	writeJSON(w, 200, map[string]any{"tenant": tenant, "count": len(out), "stats": out})
}

// handleProcess reconstructs a process drill-down for an alert's exec_id (the
// SOC alert triage click-through). The store has no exec_id index, so we fold
// the tenant's recent events in Go — enough for the recent alerts an operator
// drills into. Full parent lineage is a follow-up (needs exec-tree reporting).
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	// Mounted at both /api/process/ and /api/choke/process/ — take the id after
	// the last "/process/" so either prefix resolves correctly.
	execID := r.URL.Path
	if i := strings.LastIndex(execID, "/process/"); i >= 0 {
		execID = execID[i+len("/process/"):]
	}
	if execID == "" {
		http.Error(w, "exec id required", http.StatusBadRequest)
		return
	}
	rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "event"}, 5000)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	type node struct {
		ExecID    string `json:"exec_id"`
		PID       uint32 `json:"pid"`
		Binary    string `json:"binary"`
		Args      string `json:"args"`
		Timestamp string `json:"timestamp"`
	}
	type eventView struct {
		Agent      string `json:"agent"`
		ExecID     string `json:"exec_id"`
		PID        uint32 `json:"pid"`
		EventType  string `json:"event_type"`
		Process    string `json:"process"`
		Args       string `json:"args"`
		PolicyName string `json:"policy_name"`
		Timestamp  string `json:"timestamp"`
	}
	var chain []node
	events := []eventView{}
	haveNode := false
	for _, row := range rows {
		e := row.Record.GetEvent()
		if e == nil || e.GetExecId() != execID {
			continue
		}
		at := row.At
		if e.GetOccurredAt() != nil {
			at = e.GetOccurredAt().AsTime()
		}
		ts := at.UTC().Format(time.RFC3339Nano)
		events = append(events, eventView{
			Agent: row.AgentID, ExecID: e.GetExecId(), PID: e.GetPid(),
			EventType: e.GetEventType(), Process: e.GetBinary(), Args: e.GetArgs(),
			PolicyName: e.GetPolicyName(), Timestamp: ts,
		})
		if !haveNode && e.GetBinary() != "" {
			haveNode = true
			chain = append(chain, node{ExecID: execID, PID: e.GetPid(), Binary: e.GetBinary(), Args: e.GetArgs(), Timestamp: ts})
		}
	}
	writeJSON(w, 200, map[string]any{"exec_id": execID, "chain": chain, "events": events})
}

// handleStream is the tenant-scoped live feed (SSE) the SOC dashboard's
// EventSource connects to. The control plane has no in-process event pipeline
// (agents feed it over gRPC), so this bridges the store: it emits new event /
// alert / decision rows as StreamFrames and keeps the connection warm with
// heartbeats. The high-water mark starts at connect time, so it never replays
// the REST snapshot the client already loaded.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: don't buffer this response
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "data: {\"type\":\"heartbeat\"}\n\n") // flip client to "connected" at once
	flusher.Flush()

	ctx := r.Context()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	lastSeen := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, "data: {\"type\":\"heartbeat\"}\n\n")
			flusher.Flush()
		case <-poll.C:
			rows, err := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant}, 200)
			if err != nil {
				continue
			}
			// rows are newest-first; keep those newer than the watermark and
			// emit oldest-first so the live feed prepends in chronological order.
			fresh := make([]centralstore.Row, 0, len(rows))
			newest := lastSeen
			for _, row := range rows {
				if row.At.After(lastSeen) {
					fresh = append(fresh, row)
					if row.At.After(newest) {
						newest = row.At
					}
				}
			}
			lastSeen = newest
			for i := len(fresh) - 1; i >= 0; i-- {
				if frame := streamFrame(fresh[i]); frame != "" {
					fmt.Fprintf(w, "data: %s\n\n", frame)
					flusher.Flush()
				}
			}
		}
	}
}

// streamFrame renders a stored row as a StreamFrame JSON the SOC frontend's
// normalizers (normalizeAlert / normalizeEvent / normalizeDecisionFrame)
// understand — the same field shapes as /api/alerts, /api/events, /api/decisions.
func streamFrame(row centralstore.Row) string {
	var frame map[string]any
	switch row.Kind {
	case "event":
		e := row.Record.GetEvent()
		if e == nil {
			return ""
		}
		at := row.At
		if e.GetOccurredAt() != nil {
			at = e.GetOccurredAt().AsTime()
		}
		frame = map[string]any{"type": "event", "payload": map[string]any{
			"id": row.DedupKey, "agent": row.AgentID, "exec_id": e.GetExecId(),
			"pid": e.GetPid(), "event_type": e.GetEventType(), "process": e.GetBinary(),
			"args": e.GetArgs(), "policy_name": e.GetPolicyName(),
			"dest_ip": e.GetDestIp(), "dest_port": e.GetDestPort(), "proto": e.GetProto(),
			"remote_ip": e.GetRemoteIp(), "timestamp": at.UTC().Format(time.RFC3339Nano),
		}}
	case "alert":
		a := row.Record.GetAlert()
		if a == nil {
			return ""
		}
		at := row.At
		if a.GetOccurredAt() != nil {
			at = a.GetOccurredAt().AsTime()
		}
		frame = map[string]any{"type": "alert", "payload": map[string]any{
			"id": row.DedupKey, "agent": row.AgentID, "severity": a.GetSeverity(),
			"title": a.GetTitle(), "description": a.GetDescription(), "score": a.GetScore(),
			"exec_id": a.GetExecId(), "process": row.Binary,
			"mitre_id": a.GetMitreId(), "tactic": a.GetTactic(),
			"timestamp": at.UTC().Format(time.RFC3339Nano),
		}}
	case "decision":
		d := row.Record.GetDecision()
		if d == nil {
			return ""
		}
		at := row.At
		if d.GetOccurredAt() != nil {
			at = d.GetOccurredAt().AsTime()
		}
		target := d.GetBinary()
		if target == "" {
			target = d.GetExecId()
		}
		frame = map[string]any{"type": "decision", "payload": map[string]any{
			"action": d.GetAction(), "state": d.GetToState(), "target": target,
			"reason": d.GetReason(), "ok": d.GetOutcome() == "ok",
			"timestamp": at.UTC().Format(time.RFC3339Nano),
		}}
	default:
		return ""
	}
	b, err := json.Marshal(frame)
	if err != nil {
		return ""
	}
	return string(b)
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
		Jail *struct {
			ExecID string `json:"exec_id"`
			PID    uint32 `json:"pid"`
			Tier   string `json:"tier"` // throttle | tarpit | quarantine | sever
		} `json:"jail"`
		Thaw *struct {
			ExecID string `json:"exec_id"`
			PID    uint32 `json:"pid"`
		} `json:"thaw"`
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
	case body.Jail != nil:
		switch body.Jail.Tier {
		case "throttle", "tarpit", "quarantine", "sever":
		default:
			http.Error(w, "jail.tier must be throttle | tarpit | quarantine | sever", http.StatusBadRequest)
			return
		}
		cmd.Action = &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{
			ExecId: body.Jail.ExecID, Pid: body.Jail.PID, Tier: body.Jail.Tier,
		}}
	case body.Thaw != nil:
		cmd.Action = &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{
			ExecId: body.Thaw.ExecID, Pid: body.Thaw.PID,
		}}
	default:
		http.Error(w, "no action: provide set_mode, set_thresholds, jail, or thaw", http.StatusBadRequest)
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
