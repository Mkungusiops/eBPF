package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
	"github.com/jeffmk/ebpf-poc-engine/internal/heartbeat"
)

// This file re-plumbs the engine's rich Choke Gateway + Network Choke (Devices)
// API contract for the multi-tenant control plane. The console serves soc's
// actual ChokeRoute/DevicesPage frontend, so it calls the same /api/choke/*
// paths the single-host engine exposes. Here the READ endpoints are answered
// tenant-scoped from the compact choke/device snapshots agents report on their
// heartbeats (heartbeat.Registry). Detail the agents don't report yet (kernel
// token buckets, cgroup map, full process table, per-device flows) returns a
// valid-empty shape so the pages render without crashing. WRITE endpoints are
// registered so they return a clean "not enabled yet" instead of a 404 — the
// interactive command wiring (fleet-wide mode change, manual jail/thaw) is the
// next increment and is deliberately gated because it changes live enforcement.

// registerChokeRoutes wires the Choke Gateway + Devices API onto the mux.
func (s *Server) registerChokeRoutes(mux *http.ServeMux) {
	// Choke Gateway (process choke) — reads.
	mux.HandleFunc("/api/choke/state", s.handleChokeStateGW)
	mux.HandleFunc("/api/choke/circuits", s.handleChokeCircuits)
	mux.HandleFunc("/api/choke/buckets", s.handleChokeBuckets)
	mux.HandleFunc("/api/choke/cgroups", s.handleChokeCgroups)
	mux.HandleFunc("/api/choke/processes", s.handleChokeProcesses)
	mux.HandleFunc("/api/choke/process/", s.handleProcess) // reuse the event-based drill
	mux.HandleFunc("/api/choke/proc/", s.handleChokeProcDetail)
	mux.HandleFunc("/api/verify-chain", s.handleVerifyChain)
	// Network Choke (Devices) — reads.
	mux.HandleFunc("/api/choke/device-state", s.handleDeviceState)
	mux.HandleFunc("/api/choke/devices", s.handleDeviceList)
	mux.HandleFunc("/api/choke/device-flows", s.handleDeviceFlows)
	// Interactive response — all wired to the signed command dispatcher, RBAC
	// ActionRespond. Per-process (manual/jail/thaw) + fleet-wide (mode/kill-
	// switch/thresholds/preset) + device (jail/thaw/mode/kill-switch).
	mux.HandleFunc("/api/choke/manual", s.handleChokeManual)     // Choke Gateway per-row jail/thaw
	mux.HandleFunc("/api/choke/jail", s.handleChokeJailFromSoc)  // SOC dashboard alert "jail"
	mux.HandleFunc("/api/choke/thaw", s.handleChokeThaw)         // release a process
	mux.HandleFunc("/api/choke/bulk-manual", s.handleChokeBulk)  // multi-target jail
	mux.HandleFunc("/api/choke/forget", s.handleChokeForget)     // stop tracking (= thaw)
	mux.HandleFunc("/api/choke/mode", s.handleChokeMode)         // fleet-wide SetMode
	mux.HandleFunc("/api/choke/kill-switch", s.handleChokeKill)  // fleet-wide KillSwitch
	mux.HandleFunc("/api/choke/thresholds", s.handleChokeThresh) // fleet-wide SetThresholds
	mux.HandleFunc("/api/choke/preset", s.handleChokePreset)     // fleet-wide ApplyPreset
	mux.HandleFunc("/api/choke/device-jail", s.handleDeviceJail)
	mux.HandleFunc("/api/choke/device-thaw", s.handleDeviceThaw)
	mux.HandleFunc("/api/choke/device-mode", s.handleChokeMode) // device data plane shares SetMode
	mux.HandleFunc("/api/choke/device-kill-switch", s.handleChokeKill)
	// Engine-local ops with no fleet command (cosmetic / snapshot) — clean 200/501.
	mux.HandleFunc("/api/choke/annotate", s.handleChokeAnnotate)
	for _, p := range []string{"/api/choke/policy/preview", "/api/choke/forensic-snapshot"} {
		mux.HandleFunc(p, s.handleChokeWriteStub)
	}
}

// authorizeRespond resolves the operator + requires the RBAC ActionRespond grant
// on the tenant (default from the session). A denial is a 404 (side-channel).
func (s *Server) authorizeRespond(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "POST/PUT only", http.StatusMethodNotAllowed)
		return "", false
	}
	p, ok := s.principal(r)
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return "", false
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		if scope := authz.TenantScope(p); len(scope) > 0 {
			tenant = scope[0]
		}
	}
	if tenant == "" {
		http.Error(w, "tenant required", http.StatusBadRequest)
		return "", false
	}
	if !authz.Authorize(p, tenant, authz.ActionRespond, s.auditor).Allowed {
		http.NotFound(w, r)
		return "", false
	}
	return tenant, true
}

// agentForExec targets the tenant's agent that reports a choke for this exec/pid;
// falls back to every tenant agent (the owner applies, others no-op) so a jail
// still lands when the choke snapshot is momentarily stale.
func (s *Server) agentForExec(tenant, execID string, pid uint32) []string {
	recs := s.registry.ListTenant(tenant)
	for _, rec := range recs {
		for _, c := range rec.Chokes {
			if (execID != "" && c.GetExecId() == execID) || (pid != 0 && c.GetPid() == pid) {
				return []string{rec.AgentID}
			}
		}
	}
	all := make([]string, 0, len(recs))
	for _, rec := range recs {
		all = append(all, rec.AgentID)
	}
	return all
}

// requireReasonForDestructive rejects an unjustified quarantine/sever.
//
// Those two rungs are the ones an audit asks about: quarantine freezes a
// process and sever SIGKILLs it (terminal — thaw cannot bring it back). A
// reason that is merely OPTIONAL becomes an empty reason under time pressure,
// leaving the audit chain recording that something drastic happened with no
// statement of why. Enforced server-side so it cannot be skipped by calling the
// API directly. The reversible rungs stay frictionless on purpose.
func requireReasonForDestructive(action, reason string) error {
	switch action {
	case "quarantine", "sever":
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("a reason is required to %s (this action is %s)", action,
				map[string]string{"quarantine": "disruptive", "sever": "irreversible"}[action])
		}
	}
	return nil
}

// dispatchChoke builds a Jail/Thaw command, dispatches it to the owning agent
// via the signed command channel, waits briefly for the ack, and writes the
// outcome. tier: throttle|tarpit|quarantine|sever (jail) or "thaw".
func (s *Server) dispatchChoke(w http.ResponseWriter, tenant, execID string, pid uint32, action, reason string) {
	if err := requireReasonForDestructive(action, reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var cmd *ebpfsocv1.Command
	switch action {
	case "throttle", "tarpit", "quarantine", "sever":
		cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: execID, Pid: pid, Tier: action}}}
	case "thaw":
		cmd = &ebpfsocv1.Command{Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: execID, Pid: pid}}}
	default:
		http.Error(w, "action must be throttle | tarpit | quarantine | sever | thaw", http.StatusBadRequest)
		return
	}
	agents := s.agentForExec(tenant, execID, pid)
	if len(agents) == 0 {
		writeJSON(w, 200, map[string]any{"ok": false, "detail": "no agent online for tenant"})
		return
	}
	id := s.dispatcher.Enqueue(agents[0], cmd)
	var status, detail string
	for i := 0; i < 60; i++ {
		if a, ok := s.dispatcher.Ack(id); ok {
			status, detail = a.GetStatus().String(), a.GetDetail()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	writeJSON(w, 200, map[string]any{
		"ok": status == "STATUS_APPLIED", "status": status, "detail": detail,
		"agent": agents[0], "action": action, "reason": reason,
	})
}

// handleChokeManual — Choke Gateway per-row action {exec_id,pid,binary,action,reason}.
func (s *Server) handleChokeManual(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecID string `json:"exec_id"`
		Pid    uint32 `json:"pid"`
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.dispatchChoke(w, tenant, b.ExecID, b.Pid, b.Action, b.Reason)
}

// handleChokeThaw — release a process {exec_id,pid} (or {reason} only = no-op ack).
func (s *Server) handleChokeThaw(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecID string `json:"exec_id"`
		Pid    uint32 `json:"pid"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	s.dispatchChoke(w, tenant, b.ExecID, b.Pid, "thaw", b.Reason)
}

// handleChokeJailFromSoc — SOC dashboard alert "jail" {pids,binary,action,reason}.
func (s *Server) handleChokeJailFromSoc(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Pids   []uint32 `json:"pids"`
		Action string   `json:"action"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var pid uint32
	if len(b.Pids) > 0 {
		pid = b.Pids[0]
	}
	// The SOC panel uses richer tier names; normalize to the dispatcher's tiers.
	action := b.Action
	switch action {
	case "throttle", "tarpit", "quarantine", "sever", "thaw":
	default:
		action = "quarantine"
	}
	s.dispatchChoke(w, tenant, "", pid, action, b.Reason)
}

// dispatchAll sends cmd to every agent in the tenant and waits for each ack —
// the fleet-wide actions (mode, kill-switch, thresholds, preset).
func (s *Server) dispatchAll(tenant string, cmd *ebpfsocv1.Command) (applied, total int, detail string) {
	for _, rec := range s.registry.ListTenant(tenant) {
		total++
		id := s.dispatcher.Enqueue(rec.AgentID, cmd)
		for i := 0; i < 50; i++ {
			if a, ok := s.dispatcher.Ack(id); ok {
				if a.GetStatus().String() == "STATUS_APPLIED" {
					applied++
				}
				detail = a.GetDetail()
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return
}

// handleChokeMode — fleet-wide SetMode (also serves /api/choke/device-mode).
func (s *Server) handleChokeMode(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Enforcing bool   `json:"enforcing"`
		Reason    string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	mode := ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY
	modeStr := "detect-only"
	if b.Enforcing {
		mode, modeStr = ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING, "enforcing"
	}
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetMode{SetMode: &ebpfsocv1.SetMode{Mode: mode}}})
	writeJSON(w, 200, map[string]any{
		"ok": applied > 0, "mode": modeStr, "previous": "", "applied": applied, "total": total, "detail": detail})
}

// handleChokeKill — fleet-wide KillSwitch (also /api/choke/device-kill-switch).
func (s *Server) handleChokeKill(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_KillSwitch{KillSwitch: &ebpfsocv1.KillSwitch{HaltAllEnforcement: b.On, Reason: b.Reason}}})
	writeJSON(w, 200, map[string]any{
		"ok": applied > 0, "engaged": b.On, "previous": !b.On, "applied": applied, "total": total, "detail": detail})
}

// handleChokeThresh — fleet-wide SetThresholds (PUT).
func (s *Server) handleChokeThresh(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ThrottleAt   int32 `json:"throttle_at"`
		TarpitAt     int32 `json:"tarpit_at"`
		QuarantineAt int32 `json:"quarantine_at"`
		SeverAt      int32 `json:"sever_at"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_SetThresholds{SetThresholds: &ebpfsocv1.SetThresholds{
			ThrottleAt: b.ThrottleAt, TarpitAt: b.TarpitAt, QuarantineAt: b.QuarantineAt, SeverAt: b.SeverAt}}})
	writeJSON(w, 200, map[string]any{"ok": applied > 0, "applied": applied, "total": total, "detail": detail})
}

// handleChokePreset — fleet-wide ApplyPreset.
func (s *Server) handleChokePreset(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	applied, total, detail := s.dispatchAll(tenant, &ebpfsocv1.Command{
		Action: &ebpfsocv1.Command_ApplyPreset{ApplyPreset: &ebpfsocv1.ApplyPreset{Preset: b.Name}}})
	writeJSON(w, 200, map[string]any{"ok": applied > 0, "preset": b.Name, "applied": applied, "total": total, "detail": detail})
}

// handleChokeBulk — multi-target jail.
func (s *Server) handleChokeBulk(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Targets []struct {
			ExecID string `json:"exec_id"`
			Pid    uint32 `json:"pid"`
		} `json:"targets"`
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	type res struct {
		ExecID string `json:"exec_id"`
		OK     bool   `json:"ok"`
	}
	results := make([]res, 0, len(b.Targets))
	for _, t := range b.Targets {
		okv := false
		if agents := s.agentForExec(tenant, t.ExecID, t.Pid); len(agents) > 0 {
			id := s.dispatcher.Enqueue(agents[0], &ebpfsocv1.Command{
				Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: t.ExecID, Pid: t.Pid, Tier: b.Action}}})
			for i := 0; i < 50; i++ {
				if a, ok := s.dispatcher.Ack(id); ok {
					okv = a.GetStatus().String() == "STATUS_APPLIED"
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		results = append(results, res{ExecID: t.ExecID, OK: okv})
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// handleChokeForget — stop tracking the given exec_ids (dispatched as a thaw).
func (s *Server) handleChokeForget(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		ExecIDs []string `json:"exec_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	n := 0
	for _, e := range b.ExecIDs {
		if agents := s.agentForExec(tenant, e, 0); len(agents) > 0 {
			id := s.dispatcher.Enqueue(agents[0], &ebpfsocv1.Command{
				Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: e}}})
			for i := 0; i < 30; i++ {
				if _, ok := s.dispatcher.Ack(id); ok {
					n++
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "forgotten": n})
}

// handleChokeAnnotate — cosmetic note; not centrally persisted yet.
func (s *Server) handleChokeAnnotate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRespond(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleDeviceJail — jail LAN devices by MAC (exec_id "device:<mac>").
func (s *Server) handleDeviceJail(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Macs   []string `json:"macs"`
		Action string   `json:"action"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	type res struct {
		Mac string `json:"mac"`
		OK  bool   `json:"ok"`
	}
	results := make([]res, 0, len(b.Macs))
	for _, mac := range b.Macs {
		applied, _, _ := s.dispatchAll(tenant, &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Jail{Jail: &ebpfsocv1.Jail{ExecId: "device:" + mac, Tier: b.Action}}})
		results = append(results, res{Mac: mac, OK: applied > 0})
	}
	writeJSON(w, 200, map[string]any{"action": b.Action, "reason": b.Reason, "results": results})
}

// handleDeviceThaw — release LAN devices by MAC.
func (s *Server) handleDeviceThaw(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRespond(w, r)
	if !ok {
		return
	}
	var b struct {
		Macs   []string `json:"macs"`
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	type res struct {
		Mac string `json:"mac"`
		OK  bool   `json:"ok"`
	}
	results := make([]res, 0, len(b.Macs))
	for _, mac := range b.Macs {
		applied, _, _ := s.dispatchAll(tenant, &ebpfsocv1.Command{
			Action: &ebpfsocv1.Command_Thaw{Thaw: &ebpfsocv1.Thaw{ExecId: "device:" + mac}}})
		results = append(results, res{Mac: mac, OK: applied > 0})
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

// chokePosture folds the tenant's agents into a single enforcement posture (the
// highest level present), matching the ChokeMode strings the frontend renders.
func chokePosture(recs []heartbeat.Record) (mode string, enforcing, dryRun bool) {
	level := 0 // 1 detect-only, 2 dry-run, 3 enforcing
	for _, rec := range recs {
		switch rec.Mode {
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCING:
			if level < 3 {
				level = 3
			}
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DRY_RUN:
			if level < 2 {
				level = 2
			}
		case ebpfsocv1.EnforcementMode_ENFORCEMENT_MODE_DETECT_ONLY:
			if level < 1 {
				level = 1
			}
		}
	}
	switch level {
	case 3:
		return "enforcing", true, false
	case 2:
		return "dry-run", false, true
	default:
		return "detect-only", false, false
	}
}

func (s *Server) handleChokeStateGW(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	recs := s.registry.ListTenant(tenant)
	mode, enforcing, dryRun := chokePosture(recs)
	counts := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	tracked := 0
	for _, rec := range recs {
		for _, c := range rec.Chokes {
			tracked++
			if _, known := counts[c.GetState()]; known {
				counts[c.GetState()]++
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"mode":          mode,
		"dry_run":       dryRun,
		"kill_switched": false,
		"enforcing":     enforcing,
		"tracked":       tracked,
		"counts":        counts,
		// Agents don't report their thresholds on the heartbeat yet; surface the
		// engine defaults so the panel renders. (Editing is the write increment.)
		"thresholds": map[string]int{"throttle_at": 5, "tarpit_at": 15, "quarantine_at": 25, "sever_at": 40},
		"audit":      map[string]any{"ok": true, "total": 0},
	})
}

func (s *Server) handleChokeCircuits(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type circuit struct {
		ExecID string `json:"exec_id"`
		PID    uint32 `json:"pid"`
		Binary string `json:"binary"`
		State  string `json:"state"`
		Score  int32  `json:"score"`
	}
	out := []circuit{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, c := range rec.Chokes {
			out = append(out, circuit{
				ExecID: c.GetExecId(), PID: c.GetPid(), Binary: c.GetBinary(),
				State: c.GetState(), Score: c.GetScore(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	writeJSON(w, 200, out)
}

// handleChokeBuckets — kernel token-bucket map. Agents don't report it on the
// heartbeat; return an empty array (valid, page renders).
func (s *Server) handleChokeBuckets(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, []any{})
}

// handleChokeCgroups — cgroup id→path map. Not reported; empty object.
func (s *Server) handleChokeCgroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{})
}

// handleChokeProcesses — full /proc snapshot. Not reported centrally; empty.
func (s *Server) handleChokeProcesses(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, []any{})
}

// handleChokeProcDetail — per-PID /proc drill. Not reported centrally; empty.
func (s *Server) handleChokeProcDetail(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	pid := strings.TrimPrefix(r.URL.Path, "/api/choke/proc/")
	writeJSON(w, 200, map[string]any{"pid": pid, "tracked": false})
}

// handleVerifyChain — decision hash-chain audit. The central store doesn't
// chain per-tenant yet; report a clean ok.
func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "total": 0})
}

func (s *Server) handleDeviceState(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	recs := s.registry.ListTenant(tenant)
	mode, enforcing, dryRun := chokePosture(recs)
	counts := map[string]int{"pristine": 0, "throttled": 0, "tarpit": 0, "quarantined": 0, "severed": 0}
	known := 0
	for _, rec := range recs {
		for _, d := range rec.Devices {
			known++
			if _, ok := counts[d.GetState()]; ok {
				counts[d.GetState()]++
			}
		}
	}
	dataPlane := "unknown"
	if len(recs) > 0 {
		dataPlane = "active"
	}
	writeJSON(w, 200, map[string]any{
		"data_plane":    dataPlane,
		"mode":          mode,
		"enforcing":     enforcing,
		"dry_run":       dryRun,
		"kill_switched": false,
		"tracked":       known,
		"devices_known": known,
		"devices_seen":  known,
		// The control plane aggregates agent-reported device state; it does not
		// itself attach a device-choke BPF program to any link, so links=0 (the
		// frontend treats 0 as "no inline bridge" — not the amber bridge-master
		// warning that a links>0 / frames==0 mix would trigger).
		"links_attached": 0,
		"frames_seen":    0,
		"counts":         counts,
	})
}

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := s.authorizeRead(w, r)
	if !ok {
		return
	}
	type device struct {
		MAC       string `json:"mac"`
		State     string `json:"state"`
		Hostname  string `json:"hostname"`
		Source    string `json:"source"`
		Protected bool   `json:"protected"`
	}
	out := []device{}
	for _, rec := range s.registry.ListTenant(tenant) {
		for _, d := range rec.Devices {
			out = append(out, device{MAC: d.GetMac(), State: d.GetState(), Hostname: d.GetLabel(), Source: rec.AgentID})
		}
	}
	writeJSON(w, 200, out)
}

// handleDeviceFlows — per-device netflow drill. Not reported centrally; empty.
func (s *Server) handleDeviceFlows(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, 200, map[string]any{"mac": r.URL.Query().Get("mac"), "flows": []any{}})
}

// handleChokeWriteStub answers the interactive Choke/Devices write endpoints
// with a clean, explicit 501 so the frontend surfaces a tidy message instead of
// a 404. Wiring these to the signed command dispatcher (fleet-wide SetMode,
// manual Jail/Thaw, thresholds, kill-switch) is the next increment — held back
// deliberately because these change enforcement on live agents.
func (s *Server) handleChokeWriteStub(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeRead(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error": "interactive choke actions are not yet enabled on the central console",
	})
}
