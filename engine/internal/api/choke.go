package api

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"

	"gopkg.in/yaml.v3"
)

//go:embed choke.html
var chokeHTML string

// SetGateway hands the gateway pointer to the server so the /api/choke/*
// endpoints can call it. Wired from main(); separate from NewServer so the
// server can start listening before the gateway is fully constructed.
func (s *Server) SetGateway(g *choke.Gateway) { s.gateway = g }

// gatewayOrErr returns the wired gateway, or 503s when the engine is
// running without enforcement enabled. Centralises the nil-check so each
// handler stays a one-liner.
func (s *Server) gatewayOrErr(w http.ResponseWriter) *choke.Gateway {
	if s.gateway == nil {
		http.Error(w, "choke gateway not enabled", http.StatusServiceUnavailable)
		return nil
	}
	return s.gateway
}

// GET /choke — the embedded console.
func (s *Server) handleChokeConsole(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write([]byte(chokeHTML))
}

// GET /api/choke/state — single-call dashboard hydrate. Returns mode,
// thresholds, kill-switch, audit chain status, and per-state counts.
func (s *Server) handleChokeState(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	res, _ := s.store.VerifyDecisionChain()
	thr := g.Thresholds()
	writeJSON(w, map[string]interface{}{
		"mode":          string(g.Mode()),
		"dry_run":       g.DryRun(),
		"kill_switched": g.KillSwitched(),
		"tracked":       g.Tracked(),
		"counts":        g.StateCounts(),
		"thresholds": map[string]int{
			"throttle_at":   thr.ThrottleAt,
			"tarpit_at":     thr.TarpitAt,
			"quarantine_at": thr.QuarantineAt,
			"sever_at":      thr.SeverAt,
		},
		"audit": res,
	})
}

// GET /api/choke/circuits — full snapshot of every tracked process.
func (s *Server) handleChokeCircuits(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	writeJSON(w, g.Snapshot())
}

// GET /api/choke/buckets — kernel-side per-PID throttle map.
func (s *Server) handleChokeBuckets(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	snap, err := g.BucketsSnapshot()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// flatten map → array for stable JSON ordering on the client side.
	type row struct {
		PID        uint32 `json:"pid"`
		RatePerSec uint32 `json:"rate_per_sec"`
		Burst      uint32 `json:"burst"`
		Tokens     uint32 `json:"tokens"`
		Flags      uint32 `json:"flags"`
	}
	out := make([]row, 0, len(snap))
	for pid, b := range snap {
		out = append(out, row{pid, b.RatePerSec, b.Burst, b.Tokens, b.Flags})
	}
	writeJSON(w, out)
}

// PUT /api/choke/thresholds — body: {throttle_at, tarpit_at, quarantine_at, sever_at}
func (s *Server) handleChokeThresholds(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ThrottleAt   int `json:"throttle_at"`
		TarpitAt     int `json:"tarpit_at"`
		QuarantineAt int `json:"quarantine_at"`
		SeverAt      int `json:"sever_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := circuit.Config{
		ThrottleAt:   body.ThrottleAt,
		TarpitAt:     body.TarpitAt,
		QuarantineAt: body.QuarantineAt,
		SeverAt:      body.SeverAt,
	}
	if err := validateThresholds(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prev := g.SetThresholds(cfg)
	writeJSON(w, map[string]interface{}{
		"updated":  cfg,
		"previous": prev,
	})
}

func validateThresholds(c circuit.Config) error {
	if c.ThrottleAt <= 0 || c.TarpitAt <= 0 || c.QuarantineAt <= 0 || c.SeverAt <= 0 {
		return errors.New("all four thresholds must be > 0")
	}
	if !(c.ThrottleAt < c.TarpitAt && c.TarpitAt < c.QuarantineAt && c.QuarantineAt < c.SeverAt) {
		return errors.New("thresholds must be strictly ascending: throttle < tarpit < quarantine < sever")
	}
	return nil
}

// POST /api/choke/manual — operator-driven override.
//
// Optional body field `revert_after_seconds` schedules an auto-revert
// to the prior state after the given delay. Useful for "tarpit this for
// 5 minutes while I investigate" — frees the operator from having to
// remember to undo it.
func (s *Server) handleChokeManual(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ExecID             string `json:"exec_id"`
		PID                uint32 `json:"pid"`
		Binary             string `json:"binary"`
		Action             string `json:"action"`
		Reason             string `json:"reason"`
		RevertAfterSeconds int    `json:"revert_after_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	action, err := parseAction(body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()
	d, err := g.Manual(r.Context(), choke.ManualRequest{
		ExecID: body.ExecID,
		PID:    body.PID,
		Binary: body.Binary,
		Action: action,
		Reason: body.Reason,
		Actor:  actor,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.RevertAfterSeconds > 0 {
		g.ScheduleRevert(d.ExecID, d.From, time.Duration(body.RevertAfterSeconds)*time.Second, actor)
	}
	writeJSON(w, map[string]interface{}{
		"applied": map[string]interface{}{
			"exec_id":              d.ExecID,
			"pid":                  d.PID,
			"action":               d.Action.String(),
			"from_state":           d.From.String(),
			"to_state":             d.To.String(),
			"reason":               d.Reason,
			"revert_after_seconds": body.RevertAfterSeconds,
		},
	})
}

// POST /api/choke/bulk-manual — apply the same action to many exec_ids in
// one round-trip. Each is audited separately. Returns per-target outcomes
// so the UI can show "5/8 succeeded".
func (s *Server) handleChokeBulkManual(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Targets []struct {
			ExecID string `json:"exec_id"`
			PID    uint32 `json:"pid"`
			Binary string `json:"binary"`
		} `json:"targets"`
		Action             string `json:"action"`
		Reason             string `json:"reason"`
		RevertAfterSeconds int    `json:"revert_after_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	action, err := parseAction(body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()
	type outcome struct {
		ExecID    string `json:"exec_id"`
		OK        bool   `json:"ok"`
		Error     string `json:"error,omitempty"`
		FromState string `json:"from_state,omitempty"`
		ToState   string `json:"to_state,omitempty"`
	}
	results := make([]outcome, 0, len(body.Targets))
	for _, t := range body.Targets {
		d, err := g.Manual(r.Context(), choke.ManualRequest{
			ExecID: t.ExecID, PID: t.PID, Binary: t.Binary,
			Action: action, Reason: body.Reason, Actor: actor,
		})
		if err != nil {
			results = append(results, outcome{ExecID: t.ExecID, OK: false, Error: err.Error()})
			continue
		}
		if body.RevertAfterSeconds > 0 {
			g.ScheduleRevert(d.ExecID, d.From, time.Duration(body.RevertAfterSeconds)*time.Second, actor)
		}
		results = append(results, outcome{
			ExecID: t.ExecID, OK: true,
			FromState: d.From.String(), ToState: d.To.String(),
		})
	}
	writeJSON(w, map[string]interface{}{"results": results})
}

// POST /api/choke/forget — drop a circuit from the gateway's memory.
// Idempotent. The decision history in the audit chain is preserved;
// only the live state machine entry goes away.
func (s *Server) handleChokeForget(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ExecIDs []string `json:"exec_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, id := range body.ExecIDs {
		g.Forget(id, 0)
	}
	writeJSON(w, map[string]interface{}{"forgot": len(body.ExecIDs)})
}

// POST /api/choke/thaw — release the quarantined cgroup so any frozen
// processes resume. Audited as a single decision row.
func (s *Server) handleChokeThaw(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	actor := s.auth.Username()
	if err := g.ThawQuarantine(actor, body.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"thawed": "ok"})
}

// POST /api/choke/preset — atomically apply a named operational mode.
// Body: {name: "containment"|"forensic"|"maintenance"|"default", reason: "..."}
func (s *Server) handleChokePreset(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()
	prev, err := g.ApplyPreset(choke.Preset(body.Name), actor, body.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{
		"applied":  body.Name,
		"previous": prev,
	})
}

// GET /api/choke/cgroups — kernel-side view of which PIDs live in each
// choke tier right now. Useful for "is the system actually choking what
// we think it's choking?".
func (s *Server) handleChokeCgroups(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	inh, err := g.CgroupInhabitants()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, inh)
}

// POST /api/choke/annotate — operator note attached to a circuit.
// Empty `note` clears the annotation.
func (s *Server) handleChokeAnnotate(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ExecID string `json:"exec_id"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()
	g.Annotate(body.ExecID, body.Note, actor)
	writeJSON(w, map[string]string{"ok": "ok"})
}

// GET /api/choke/forensic-snapshot — single JSON dump of every piece of
// gateway state. Operators download this at the start of an incident
// response so the live state can't change underfoot during forensics.
func (s *Server) handleChokeForensicSnapshot(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	decisions, _ := s.store.RecentDecisions(2000)
	cgroups, _ := g.CgroupInhabitants()
	buckets, _ := g.BucketsSnapshot()
	chain, _ := s.store.VerifyDecisionChain()

	thr := g.Thresholds()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="choke-forensic-snapshot.json"`)
	writeJSON(w, map[string]interface{}{
		"taken_at":     time.Now().UTC().Format(time.RFC3339Nano),
		"mode":         string(g.Mode()),
		"dry_run":      g.DryRun(),
		"kill_switch":  g.KillSwitched(),
		"thresholds":   thr,
		"counts":       g.StateCounts(),
		"circuits":     g.Snapshot(),
		"decisions":    decisions,
		"cgroups":      cgroups,
		"bpf_buckets":  buckets,
		"audit_chain":  chain,
		"annotations":  g.AllAnnotations(),
		"pending_reverts": g.PendingReverts(),
	})
}

// GET /api/choke/processes — full host process list joined with the
// gateway's circuit state. The console's process-picker hits this every
// few seconds while the modal is open. Each entry has an optional
// (tracked, state, exec_id, score) trio when the gateway already knows
// the PID; otherwise those fields are zero/empty.
func (s *Server) handleChokeProcesses(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	out, err := g.HostProcesses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// GET /api/choke/proc/<pid> — live /proc snapshot for a single PID. Backs
// the inspect drawer in the jail picker: status, threads, RSS, fd count
// + samples, network peer count + samples, cwd / root. Returns an empty
// detail (200 OK) when no live-proc backend is wired so the client can
// render its in-memory sections regardless.
func (s *Server) handleChokeProcLive(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	pidStr := r.URL.Path[len("/api/choke/proc/"):]
	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "bad pid: "+err.Error(), http.StatusBadRequest)
		return
	}
	d, err := g.HostProcessDetail(uint32(pid64))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, d)
}

// POST /api/choke/jail — pick-a-process-and-act endpoint.
//
// Body:
//
//	{
//	  pids:        [1234, 5678],          // explicit picks (operator selected rows)
//	  binary:      "/bin/bash",           // optional — match by exact binary path
//	  descendants: true,                  // also include every descendant of each pid
//	  action:      "throttle"|"tarpit"|"quarantine"|"sever",
//	  reason:      "responding to incident #1234",
//	  revert_after_seconds: 300
//	}
//
// All match modes are unioned. The endpoint resolves the final PID set,
// runs each through gateway.Manual (which records an audit row) and
// returns a per-PID outcome list. The exec_id is taken from the gateway's
// circuit if the PID is already tracked, otherwise synthesized as
// "manual:<pid>:<starttime>" so the audit chain still has a stable key.
func (s *Server) handleChokeJail(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PIDs               []uint32 `json:"pids"`
		Binary             string   `json:"binary"`
		Descendants        bool     `json:"descendants"`
		Action             string   `json:"action"`
		Reason             string   `json:"reason"`
		RevertAfterSeconds int      `json:"revert_after_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	action, err := parseAction(body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Reason == "" {
		http.Error(w, "reason is required for the audit row", http.StatusBadRequest)
		return
	}

	// Get the host process list once so descendants + binary match resolve
	// against a consistent snapshot.
	procs, err := g.HostProcesses()
	if err != nil {
		http.Error(w, "host process list unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawForDesc := make([]sysproc.Entry, len(procs))
	byPID := make(map[uint32]choke.SysProcEntry, len(procs))
	for i, p := range procs {
		rawForDesc[i] = sysproc.Entry{PID: p.PID, PPID: p.PPID, UID: p.UID, Comm: p.Comm, Exe: p.Exe, Cmdline: p.Cmdline, StartTime: p.StartTime}
		byPID[p.PID] = p
	}

	// Build the final PID set, unioned across all match modes.
	want := make(map[uint32]bool)
	for _, pid := range body.PIDs {
		want[pid] = true
	}
	if body.Binary != "" {
		for _, p := range procs {
			if p.Exe == body.Binary || p.Comm == body.Binary {
				want[p.PID] = true
			}
		}
	}
	if body.Descendants {
		// Expand each currently-selected pid with its descendants.
		seeds := make([]uint32, 0, len(want))
		for pid := range want {
			seeds = append(seeds, pid)
		}
		for _, seed := range seeds {
			for _, d := range sysproc.Descendants(rawForDesc, seed, false) {
				want[d] = true
			}
		}
	}
	if len(want) == 0 {
		http.Error(w, "no pids matched (provide pids[], binary, or both)", http.StatusBadRequest)
		return
	}

	actor := s.auth.Username()
	type outcome struct {
		PID    uint32 `json:"pid"`
		ExecID string `json:"exec_id"`
		OK     bool   `json:"ok"`
		Error  string `json:"error,omitempty"`
		State  string `json:"state,omitempty"`
	}
	results := make([]outcome, 0, len(want))
	for pid := range want {
		entry := byPID[pid]
		execID := entry.ExecID
		if execID == "" {
			// Stable synthetic key so re-jailing the same (pid, starttime)
			// hashes to the same exec_id and the audit chain stays linked.
			execID = fmt.Sprintf("manual:%d:%d", pid, entry.StartTime)
		}
		bin := entry.Exe
		if bin == "" {
			bin = entry.Comm
		}
		d, err := g.Manual(r.Context(), choke.ManualRequest{
			ExecID: execID, PID: pid, Binary: bin,
			Action: action, Reason: body.Reason, Actor: actor,
		})
		if err != nil {
			results = append(results, outcome{PID: pid, ExecID: execID, OK: false, Error: err.Error()})
			continue
		}
		if body.RevertAfterSeconds > 0 {
			g.ScheduleRevert(d.ExecID, d.From, time.Duration(body.RevertAfterSeconds)*time.Second, actor)
		}
		results = append(results, outcome{PID: pid, ExecID: execID, OK: true, State: d.To.String()})
	}
	writeJSON(w, map[string]interface{}{
		"action":  body.Action,
		"reason":  body.Reason,
		"results": results,
	})
}

// GET /api/choke/process/<exec_id> — drill-in payload: the circuit entry
// + all decisions for this exec_id + chain ancestors + annotation.
// Used by the UI's slide-over panel.
func (s *Server) handleChokeProcess(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	execID := r.URL.Path[len("/api/choke/process/"):]
	if execID == "" {
		http.Error(w, "missing exec_id", http.StatusBadRequest)
		return
	}
	// Find the circuit entry.
	var entry *choke.Entry
	for _, e := range g.Snapshot() {
		if e.ExecID == execID {
			ec := e
			entry = &ec
			break
		}
	}
	chain := s.tree.Ancestors(execID, 10)
	events, _ := s.store.EventsByExecID(execID)
	allDecisions, _ := s.store.RecentDecisions(2000)
	mine := make([]store.Decision, 0)
	for _, d := range allDecisions {
		if d.ExecID == execID {
			mine = append(mine, d)
		}
	}
	anno, _ := g.AnnotationFor(execID)
	writeJSON(w, map[string]interface{}{
		"entry":      entry,
		"chain":      chain,
		"events":     events,
		"decisions":  mine,
		"annotation": anno,
	})
}

func parseAction(s string) (circuit.Action, error) {
	switch s {
	case "throttle":
		return circuit.ActThrottle, nil
	case "tarpit":
		return circuit.ActTarpit, nil
	case "quarantine":
		return circuit.ActQuarantine, nil
	case "sever":
		return circuit.ActSever, nil
	}
	return circuit.ActNone, fmt.Errorf("unknown action %q (want throttle|tarpit|quarantine|sever)", s)
}

// POST /api/choke/kill-switch — body: {on: bool}
func (s *Server) handleChokeKillSwitch(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	prev := g.SetKillSwitch(body.On)
	writeJSON(w, map[string]interface{}{"engaged": body.On, "previous": prev})
}

// GET /api/choke/policies — list all loaded ChokePolicies.
func (s *Server) handleChokePolicies(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if g.Policies() == nil {
		writeJSON(w, []policy.Policy{})
		return
	}
	writeJSON(w, g.Policies().All())
}

// POST /api/choke/policy/preview — body: {yaml: "..."}
// Returns {valid, errors, matches: [...]} with the live exec_ids that
// would activate under the supplied policy. The policy is NOT installed.
func (s *Server) handleChokePolicyPreview(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	var p policy.Policy
	if err := yaml.Unmarshal([]byte(body.YAML), &p); err != nil {
		writeJSON(w, map[string]interface{}{
			"valid":  false,
			"errors": []string{"yaml parse: " + err.Error()},
		})
		return
	}
	if err := p.Validate(); err != nil {
		writeJSON(w, map[string]interface{}{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}
	matches, err := g.PreviewPolicy(p)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"valid":   true,
		"policy":  p,
		"matches": matches,
	})
}
