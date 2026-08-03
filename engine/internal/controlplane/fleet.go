package controlplane

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/centralstore"
	"github.com/jeffmk/ebpf-poc-engine/internal/fleetprobe"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// This file re-plumbs the engine's Fleet view for the control plane. The engine
// Fleet page federates a fleet of single-host engines; here each of the tenant's
// agents IS a "host", so the multi-tenant Fleet is the tenant's agents. Reads
// answer the frontend's FleetEnvelope<T> = {hosts: HostResult<T>[]} contract
// per-agent, tenant-scoped. Writes (fleet-wide preset/thresholds/kill-switch/
// thaw) are stubbed 501 — they change live enforcement and are gated behind the
// interactive-write increment.

// registerFleetRoutes wires the Fleet API onto the mux.
func (s *Server) registerFleetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/fleet/hosts", s.handleFleetHosts)
	mux.HandleFunc("/api/fleet/state", s.handleFleetState)
	mux.HandleFunc("/api/fleet/cgroups", s.handleFleetCgroups)
	mux.HandleFunc("/api/fleet/decisions", s.handleFleetDecisions)
	mux.HandleFunc("/api/fleet/alerts", s.handleFleetAlerts)
	mux.HandleFunc("/api/fleet/devices", s.handleFleetDevices)
	mux.HandleFunc("/api/fleet/probe", s.handleFleetProbe)
	for _, p := range []string{
		"/api/fleet/preset", "/api/fleet/thresholds",
		"/api/fleet/kill-switch", "/api/fleet/thaw",
	} {
		mux.HandleFunc(p, s.handleChokeWriteStub) // same clean 501
	}
}

// hostResult is the frontend's HostResult<T> — one per agent.
type hostResult struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
	OK   bool   `json:"ok"`
	Data any    `json:"data"`
}

// chokeStateCounts folds an agent's choke summaries into per-state counts.
func chokeStateCounts(chokes []*ebpfsocv1.ChokeSummary) map[string]int {
	counts := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	for _, c := range chokes {
		if _, ok := counts[c.GetState()]; ok {
			counts[c.GetState()]++
		}
	}
	return counts
}

func (s *Server) handleFleetHosts(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type peer struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	out := []peer{}
	for _, rec := range s.registry.ListTenant(tenant) {
		out = append(out, peer{Name: rec.AgentID, URL: "agent://" + rec.AgentID})
	}
	writeJSON(w, 200, map[string]any{"hosts": out})
}

func (s *Server) handleFleetState(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	hosts := []hostResult{}
	for _, rec := range s.registry.ListTenant(tenant) {
		mode, _, dryRun := chokePosture([]heartbeat.Record{rec})
		hosts = append(hosts, hostResult{Name: rec.AgentID, OK: true, Data: map[string]any{
			"mode": mode, "dry_run": dryRun, "kill_switched": false,
			"tracked": len(rec.Chokes), "counts": chokeStateCounts(rec.Chokes),
			"thresholds": map[string]int{"throttle_at": 5, "tarpit_at": 15, "quarantine_at": 25, "sever_at": 40},
			"audit":      map[string]any{"ok": true, "total": 0},
		}})
	}
	writeJSON(w, 200, map[string]any{"hosts": hosts})
}

// handleFleetCgroups — agents don't report the cgroup map centrally; empty per host.
func (s *Server) handleFleetCgroups(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	hosts := []hostResult{}
	for _, rec := range s.registry.ListTenant(tenant) {
		hosts = append(hosts, hostResult{Name: rec.AgentID, OK: true, Data: map[string]any{}})
	}
	writeJSON(w, 200, map[string]any{"hosts": hosts})
}

func (s *Server) handleFleetDecisions(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n * 4 // per-tenant budget; grouped per-agent below
		}
	}
	rows, _ := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "decision"}, limit)
	byAgent := map[string][]map[string]any{}
	for _, row := range rows {
		d := row.Record.GetDecision()
		if d == nil {
			continue
		}
		at := row.At
		if d.GetOccurredAt() != nil {
			at = d.GetOccurredAt().AsTime()
		}
		byAgent[row.AgentID] = append(byAgent[row.AgentID], map[string]any{
			"timestamp": at.UTC().Format(time.RFC3339Nano), "action": d.GetAction(),
			"binary": d.GetBinary(), "reason": d.GetReason(), "score": d.GetScore(),
			"exec_id": d.GetExecId(), "pid": d.GetPid(),
		})
	}
	writeJSON(w, 200, map[string]any{"hosts": s.fleetEnvelope(tenant, byAgent)})
}

func (s *Server) handleFleetAlerts(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	rows, _ := s.cfg.Store.Query(centralstore.Scope{TenantID: tenant, Kind: "alert"}, 800)
	byAgent := map[string][]map[string]any{}
	for _, row := range rows {
		a := row.Record.GetAlert()
		if a == nil {
			continue
		}
		at := row.At
		if a.GetOccurredAt() != nil {
			at = a.GetOccurredAt().AsTime()
		}
		byAgent[row.AgentID] = append(byAgent[row.AgentID], map[string]any{
			"timestamp": at.UTC().Format(time.RFC3339Nano), "severity": a.GetSeverity(),
			"title": a.GetTitle(), "summary": a.GetDescription(), "score": a.GetScore(),
			"exec_id": a.GetExecId(),
		})
	}
	writeJSON(w, 200, map[string]any{"hosts": s.fleetEnvelope(tenant, byAgent)})
}

func (s *Server) handleFleetDevices(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	hosts := []hostResult{}
	for _, rec := range s.registry.ListTenant(tenant) {
		devices := []map[string]any{}
		for _, d := range rec.Devices {
			devices = append(devices, map[string]any{
				"mac": d.GetMac(), "state": d.GetState(), "hostname": d.GetLabel(), "protected": false,
			})
		}
		hosts = append(hosts, hostResult{Name: rec.AgentID, OK: true, Data: devices})
	}
	writeJSON(w, 200, map[string]any{"hosts": hosts})
}

// handleFleetProbe reports whether ad-hoc peer consoles answer HTTP. The
// tenant's own agents never need this — they are known from heartbeats, and
// dial the CP rather than listening — so this exists for peers the operator
// adds by hand, such as a single-tenant engine console alongside the CP.
//
// Read authorization is required, but the probe is not tenant-scoped data:
// it carries no credentials and returns only reachability plus a status code.
func (s *Server) handleFleetProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	var req struct {
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	writeJSON(w, 200, map[string]any{
		"hosts": fleetprobe.New().Probe(r.Context(), req.URLs),
	})
}

// fleetEnvelope builds a HostResult per tenant agent, attaching each agent's
// grouped rows (empty array when it has none, so every agent still appears).
func (s *Server) fleetEnvelope(tenant string, byAgent map[string][]map[string]any) []hostResult {
	hosts := []hostResult{}
	for _, rec := range s.registry.ListTenant(tenant) {
		data := byAgent[rec.AgentID]
		if data == nil {
			data = []map[string]any{}
		}
		hosts = append(hosts, hostResult{Name: rec.AgentID, OK: true, Data: data})
	}
	return hosts
}
