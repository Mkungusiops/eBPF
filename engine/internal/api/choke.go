package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeffmk/ebpf-poc-engine/internal/choke"
	"github.com/jeffmk/ebpf-poc-engine/internal/choke/circuit"
	"github.com/jeffmk/ebpf-poc-engine/internal/policy"
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/sysproc"

	"gopkg.in/yaml.v3"
)

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

// maxWriteBodyBytes caps what one choke write may send. decodeWrite reads the
// body twice — once as an object, once into the handler's struct — so it has to
// buffer it, and an unbounded buffer on an authenticated write is a cost the
// operator never asked for. Orders of magnitude above the largest real body on
// this surface (a bulk jail naming thousands of targets, a policy YAML).
const maxWriteBodyBytes = 4 << 20

// decodeWrite decodes a choke write's body into dst, refusing every body that
// states no intent: absent, empty, whitespace-only, a literal `null`, or any
// JSON that is not an object.
//
// WHY the map hop rather than decoding straight into dst: encoding/json decodes
// `null` into a struct with a NIL ERROR and leaves every field at its zero
// value, and on this surface the zero value is the disarming direction —
// SetKillSwitch(false), detect-only, an empty audit reason. So POST
// /api/choke/kill-switch with the body `null` released the single
// widest-blast-radius toggle on the platform and wrote the audit row with no
// reason, indistinguishable from an operator asking for exactly that. A
// map[string]json.RawMessage separates the three cases a struct cannot: not an
// object at all, an object that OMITS a key, and an object that STATES it. The
// returned field set is what lets a handler tell "the operator said false" from
// "the body said nothing".
//
// A pointer field carries the same fact (writeChangeControl in the control
// plane uses a *bool for exactly this), but only for the fields somebody
// remembered to make a pointer. The rule here has to hold for every write in
// the file, including the next one added, so it lives at the decode point.
//
// Same rule and same refusals as the fleet fan-out's resolveTargets in
// fleet.go, which is the layer above: two implementations of one rule drift.
func decodeWrite(r *http.Request, dst any) (map[string]json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWriteBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bad json: unreadable request body: %w", err)
	}
	if len(raw) > maxWriteBodyBytes {
		return nil, fmt.Errorf("request body is larger than the %d byte limit for a choke write", maxWriteBodyBytes)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("empty request body: a choke write must be a JSON object saying what to do")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// An array, a string, a number, a bool, a truncated object. None of
		// them can carry the fields this endpoint acts on, so none of them is
		// an instruction.
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if fields == nil {
		// The literal `null`: valid JSON, unmarshals into a map with a nil
		// error, and leaves the map NIL — so every key below would read as
		// absent and every struct field as its zero value. This is the shape
		// that turned an empty request into "disengage enforcement".
		return nil, fmt.Errorf(`a choke write body must be a JSON object; a literal "null" states no intent`)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	return fields, nil
}

// stated reports whether the body actually named this field. A key whose value
// is `null` is NOT stated: `{"on":null}` carries no more intent than omitting
// the key, and decodes to the same false.
func stated(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]
	return ok && string(bytes.TrimSpace(raw)) != "null"
}

// requireStated guards a field whose ZERO VALUE IS AN ACT — `on` false releases
// the kill-switch, `enforcing` false drops this host to detect-only. For those,
// silence must never be read as a decision. Explicit false keeps working: it is
// a legitimate request, and telling it apart from silence is the whole point.
func requireStated(w http.ResponseWriter, fields map[string]json.RawMessage, key, meaning string) bool {
	if stated(fields, key) {
		return true
	}
	http.Error(w, fmt.Sprintf("%q is required: %s. State it explicitly — an absent field is not an instruction.",
		key, meaning), http.StatusBadRequest)
	return false
}

// GET /choke — the embedded console.
func (s *Server) handleChokeConsole(w http.ResponseWriter, r *http.Request) {
	if s.serveEmbeddedWebPage(w, "choke.html") {
		return
	}
	serveMissingEmbeddedWeb(w)
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
		ThrottleAt   int    `json:"throttle_at"`
		TarpitAt     int    `json:"tarpit_at"`
		QuarantineAt int    `json:"quarantine_at"`
		SeverAt      int    `json:"sever_at"`
		Reason       string `json:"reason"`
	}
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := circuit.Config{
		ThrottleAt:   body.ThrottleAt,
		TarpitAt:     body.TarpitAt,
		QuarantineAt: body.QuarantineAt,
		SeverAt:      body.SeverAt,
	}
	// circuit.Config.Validate, not a local copy: the fleet path needs the same
	// rule, and two implementations would drift.
	if err := cfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prev, err := g.SetThresholdsBy(cfg, s.auth.Username())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Moving the thresholds changes when the platform acts on every process on
	// this host. It wrote a log line and no audit row.
	g.AuditConfigChange("set-thresholds",
		fmt.Sprintf("%d/%d/%d/%d", prev.ThrottleAt, prev.TarpitAt, prev.QuarantineAt, prev.SeverAt),
		fmt.Sprintf("%d/%d/%d/%d", cfg.ThrottleAt, cfg.TarpitAt, cfg.QuarantineAt, cfg.SeverAt),
		s.auth.Username(), strings.TrimSpace(body.Reason))
	writeJSON(w, map[string]interface{}{
		"updated":  cfg,
		"previous": prev,
	})
}

// validateThresholds moved to circuit.Config.Validate, next to the type it
// guards, so the control plane and the signed-command path share one rule
// rather than the engine being the only hop that checked.

// POST /api/choke/manual — operator-driven override.
//
// Optional body field `revert_after_seconds` schedules an auto-revert
// to the prior state after the given delay. Useful for "tarpit this for
// 5 minutes while I investigate" — frees the operator from having to
// remember to undo it.
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action, err := parseAction(body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := requireReasonForDestructive(body.Action, body.Reason); err != nil {
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		ExecID string `json:"exec_id"`
		PID    uint32 `json:"pid"`
		Reason string `json:"reason"`
	}
	// The decode error used to be discarded here, so a malformed body, an
	// absent body and a real request were the same event: `null` fell
	// through to the tier-wide branch below and unfroze the whole
	// quarantine tier with an empty audit reason. No field is REQUIRED —
	// the reason-only shape is the console's "Thaw quarantine" button and
	// stays frictionless, because releasing must never be blocked — but the
	// body still has to be an object that asks for something.
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := s.auth.Username()

	// Targeted release. Without this branch the only thing thaw could do was
	// unfreeze the whole quarantine TIER without moving anyone out of it or
	// updating any circuit state — so a per-process "release" reported success
	// and left the process quarantined forever. ActNone moves the pid into the
	// limit-free pristine cgroup and drives the circuit to pristine, which is
	// what the caller is actually asking for. Matches the control plane, where
	// thaw has always been per-process.
	if body.ExecID != "" {
		d, err := g.Manual(r.Context(), choke.ManualRequest{
			ExecID: body.ExecID,
			PID:    body.PID,
			Action: circuit.ActNone,
			Reason: body.Reason,
			Actor:  actor,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]interface{}{
			"thawed": "ok",
			"scope":  "process",
			"state":  d.To.String(),
		})
		return
	}

	// No target: the legacy tier-wide unfreeze. Kept because chokectl and the
	// "Thaw quarantine" control both rely on it.
	if err := g.ThawQuarantine(actor, body.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"thawed": "ok", "scope": "tier"})
}

// POST /api/choke/mode — runtime swap between detect-only and enforcing.
// Body: {enforcing: bool, reason: string}. Returns the mode that was in
// effect before the swap so the caller can detect no-ops. The change
// applies immediately to all subsequent decisions; in-flight Apply() calls
// are unaffected (they hold their own enforcer reference).
func (s *Server) handleChokeMode(w http.ResponseWriter, r *http.Request) {
	g := s.gatewayOrErr(w)
	if g == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enforcing bool   `json:"enforcing"`
		Reason    string `json:"reason"`
	}
	fields, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !requireStated(w, fields, "enforcing", "true arms this host, false drops it to detect-only") {
		return
	}
	prev := g.SetEnforcing(body.Enforcing, s.auth.Username(), body.Reason)
	writeJSON(w, map[string]interface{}{
		"mode":     string(g.Mode()),
		"previous": string(prev),
	})
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		"taken_at":        time.Now().UTC().Format(time.RFC3339Nano),
		"mode":            string(g.Mode()),
		"dry_run":         g.DryRun(),
		"kill_switch":     g.KillSwitched(),
		"thresholds":      thr,
		"counts":          g.StateCounts(),
		"circuits":        g.Snapshot(),
		"decisions":       decisions,
		"cgroups":         cgroups,
		"bpf_buckets":     buckets,
		"audit_chain":     chain,
		"annotations":     g.AllAnnotations(),
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
		PIDs []uint32 `json:"pids"`
		// ExecID is the identifier an ALERT carries. The console's
		// alert-to-contain path sends it; without this field the engine
		// silently ignored it and answered 400 "no pids matched", because an
		// alert has no pid and no binary to fall back on.
		ExecID             string `json:"exec_id"`
		Binary             string `json:"binary"`
		Descendants        bool   `json:"descendants"`
		Action             string `json:"action"`
		Reason             string `json:"reason"`
		RevertAfterSeconds int    `json:"revert_after_seconds"`
	}
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	// exec_id resolves through the process tree, which is the only route an
	// ALERT has to a target: an alert carries exec_id and nothing else — no
	// pid, no binary. Before this, the console's alert-to-contain path could
	// not name a target at all and every attempt answered 400.
	//
	// The tree is authoritative here rather than the /proc scan: it knows the
	// pid that exec_id belonged to even for a process that has since exited,
	// and a jail on a dead pid is a harmless no-op with an honest audit row.
	if body.ExecID != "" && s.tree != nil {
		if n, ok := s.tree.Get(body.ExecID); ok && n.PID != 0 {
			want[n.PID] = true
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
		http.Error(w, "no pids matched (provide exec_id, pids[], binary, or a combination)", http.StatusBadRequest)
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
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	fields, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// `on` is required, and this is the reason the rule exists. It was
	// decoded into a bool, so a body of `null` — or `{}`, or anything else
	// that parsed — meant false, and false here BYPASSES ALL CONTAINMENT on
	// this host. An operator releasing the kill-switch says so; a body that
	// says nothing is not that operator.
	if !requireStated(w, fields, "on", "true engages the kill-switch and halts all enforcement, false releases it") {
		return
	}
	prev := g.SetKillSwitch(body.On)
	// The kill-switch bypasses ALL containment, including an action an
	// operator presses themselves. It is the single widest-blast-radius toggle
	// on the platform and it wrote no audit row.
	if prev != body.On {
		g.AuditConfigChange("kill-switch", stateWord(prev), stateWord(body.On),
			s.auth.Username(), strings.TrimSpace(body.Reason))
	}
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
	_, err := decodeWrite(r, &body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		// scanned is the size of the live tracked snapshot the policy was
		// evaluated against, so the UI can show "N matched of M scanned"
		// and explain an empty match set instead of looking broken.
		"scanned": len(g.Snapshot()),
	})
}

// stateWord renders the kill-switch as the word the audit row carries.
func stateWord(on bool) string {
	if on {
		return "engaged"
	}
	return "released"
}
